from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_cors import CORS
from werkzeug.utils import secure_filename
import sqlite3, os, smtplib, json, urllib.request, urllib.error, base64, struct
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
CORS(app)
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

# ══════════════════════════════════════════
#  EMAIL CONFIG
# ══════════════════════════════════════════
EMAIL_SENDER   = os.environ.get("EMAIL_SENDER")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD")
EMAIL_NAME     = "EasyEstate Team"
# ══════════════════════════════════════════
#  ANTHROPIC API KEY
# ══════════════════════════════════════════
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")

UPLOAD_FOLDER = os.path.join("static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def get_db():
    conn = sqlite3.connect("easyestate.db")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur  = conn.cursor()

    # ── USERS TABLE ──
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT,
            email      TEXT UNIQUE,
            phone      TEXT,
            password   TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
    try:
        cur.execute("ALTER TABLE users ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
        conn.commit()
    except Exception:
        pass

    # ── PROPERTIES TABLE ──
    cur.execute("""
        CREATE TABLE IF NOT EXISTS properties (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            seller_name  TEXT,
            seller_phone TEXT,
            seller_email TEXT,
            title        TEXT,
            location     TEXT,
            type         TEXT,
            status       TEXT DEFAULT 'Sale',
            price        REAL,
            bedrooms     INTEGER,
            bathrooms    INTEGER,
            description  TEXT,
            images       TEXT DEFAULT '',
            created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")

    # ── SAFE MIGRATIONS for existing DBs ──
    migrations = [
        "ALTER TABLE properties ADD COLUMN status TEXT DEFAULT 'Sale'",
        "ALTER TABLE properties ADD COLUMN description TEXT",
    ]
    for sql in migrations:
        try:
            cur.execute(sql)
            conn.commit()
        except Exception:
            pass  # Column already exists — safe to ignore

    # ── CONTACTS TABLE ──
    cur.execute("""
        CREATE TABLE IF NOT EXISTS contacts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT,
            email      TEXT,
            message    TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
    conn.commit()
    conn.close()


def send_email(to_email, subject, html_body):
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = f"{EMAIL_NAME} <{EMAIL_SENDER}>"
        msg["To"]      = to_email
        msg.attach(MIMEText(html_body, "html"))
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
            s.login(EMAIL_SENDER, EMAIL_PASSWORD)
            s.sendmail(EMAIL_SENDER, to_email, msg.as_string())
        print(f"[EMAIL] Sent to {to_email}")
        return True
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")
        return False


def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin_login_page"))
        return f(*args, **kwargs)
    return decorated


# ══════════════════════════════════════════════════════════════
#  IMAGE DIMENSION READER (no Pillow needed)
# ══════════════════════════════════════════════════════════════
def get_image_dimensions(img_bytes):
    try:
        if img_bytes[:4] == b'\x89PNG':
            w = struct.unpack('>I', img_bytes[16:20])[0]
            h = struct.unpack('>I', img_bytes[20:24])[0]
            return w, h
        if img_bytes[:2] == b'\xff\xd8':
            i = 2
            while i < len(img_bytes) - 8:
                if img_bytes[i] != 0xff:
                    break
                marker = img_bytes[i + 1]
                if marker in (0xC0, 0xC1, 0xC2, 0xC3,
                               0xC5, 0xC6, 0xC7,
                               0xC9, 0xCA, 0xCB,
                               0xCD, 0xCE, 0xCF):
                    h = struct.unpack('>H', img_bytes[i + 5:i + 7])[0]
                    w = struct.unpack('>H', img_bytes[i + 7:i + 9])[0]
                    return w, h
                seg_len = struct.unpack('>H', img_bytes[i + 2:i + 4])[0]
                i += 2 + seg_len
    except Exception as e:
        print(f"[DIMENSIONS ERROR] {e}")
    return None, None


def local_validate(b64_data, filename):
    try:
        img_bytes = base64.b64decode(b64_data)
        width, height = get_image_dimensions(img_bytes)
        print(f"[LOCAL FALLBACK] file={filename!r}  w={width}  h={height}")
        suspicious_name = any(w in filename for w in [
            "whatsapp", "img-", "img_", "received", "photo_",
            "pxl_", "snap", "selfie", "portrait", "face", "person",
            "profile", "avatar", "fb_img"
        ])
        if width and height and width > 0:
            ratio = height / width
            if ratio >= 1.35:
                return {"approved": False, "reason": "Not a property photo"}
            if ratio >= 1.05 and suspicious_name:
                return {"approved": False, "reason": "Not a property photo"}
            if suspicious_name:
                return {"approved": False, "reason": "Not a property photo"}
        else:
            if suspicious_name:
                return {"approved": False, "reason": "Not a property photo"}
        return {"approved": True, "reason": ""}
    except Exception as e:
        print(f"[LOCAL FALLBACK ERROR] {e}")
        return {"approved": True, "reason": ""}


# ══════════════════════════════════════════════════════════════
#  API — IMAGE VALIDATOR
# ══════════════════════════════════════════════════════════════
@app.route("/api/validate_image", methods=["POST"])
def validate_image():
    try:
        data       = request.json or {}
        b64_data   = data.get("base64", "")
        media_type = data.get("mediaType", "image/jpeg")
        filename   = data.get("filename", "").lower().strip()

        if not b64_data:
            return jsonify({"approved": False, "reason": "No image received"})

        allowed_types = ["image/jpeg", "image/jpg", "image/png", "image/webp", "image/gif"]
        if media_type not in allowed_types:
            return jsonify({"approved": False, "reason": "Invalid file type"})

        bad_words = [
            "selfie", "selfi", "food", "dog", "cat", "pet", "bird",
            "animal", "screenshot", "screen_shot", "screencap", "meme",
            "snap", "whatsapp", "fb_img", "received", "profile", "avatar",
            "face", "people", "person", "dinner", "lunch", "breakfast",
            "burger", "pizza", "restaurant", "menu", "portrait",
            "img-", "img_", "photo_", "pxl_"
        ]
        for word in bad_words:
            if word in filename:
                return jsonify({"approved": False, "reason": "Not a property photo"})

        if ANTHROPIC_API_KEY and ANTHROPIC_API_KEY not in ("", "YOUR_ANTHROPIC_API_KEY_HERE"):
            try:
                prompt = """You are a strict property photo validator for EasyEstate, an Indian real estate platform.

LOOK at the image carefully. Ask yourself: "Is a building, room, or property structure the MAIN subject?"

APPROVE — return {"approved": true, "reason": ""}:
- Building exterior, facade, or front view of a house or apartment
- Indoor rooms: bedroom, living room, kitchen, bathroom, hall, staircase, dining room
- Garden, lawn, balcony, terrace, rooftop, parking area, garage
- Swimming pool, gym, clubhouse, or common areas of an apartment complex
- Aerial or drone view of a property or plot of land
- Street or locality showing the area around the property
- Floor plan or architectural drawing
- A property photo that ALSO has a person visible far in the background is still APPROVED

REJECT — return {"approved": false, "reason": "Not a property photo"}:
- A HUMAN FACE or PERSON'S BODY is the dominant, central, most prominent element
- Selfie, portrait, food, drink, animal, pet, screenshot, document
- Any photo where NO house, room, building, or property structure is the main subject

Respond ONLY with valid JSON, no markdown:
{"approved": true, "reason": ""} or {"approved": false, "reason": "Not a property photo"}"""

                payload = json.dumps({
                    "model": "claude-sonnet-4-20250514",
                    "max_tokens": 80,
                    "messages": [{
                        "role": "user",
                        "content": [
                            {"type": "image", "source": {"type": "base64", "media_type": media_type, "data": b64_data}},
                            {"type": "text", "text": prompt}
                        ]
                    }]
                }).encode("utf-8")

                req = urllib.request.Request(
                    "https://api.anthropic.com/v1/messages",
                    data=payload,
                    headers={
                        "Content-Type": "application/json",
                        "x-api-key": ANTHROPIC_API_KEY,
                        "anthropic-version": "2023-06-01"
                    },
                    method="POST"
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    resp_data = json.loads(resp.read().decode("utf-8"))
                raw = resp_data["content"][0]["text"].strip()
                raw = raw.replace("```json", "").replace("```", "").strip()
                result = json.loads(raw)
                reason_lower = (result.get("reason") or "").lower()
                person_kw = ["person","people","selfie","portrait","face","human","woman","man","girl","boy","child"]
                if result.get("approved") and any(k in reason_lower for k in person_kw):
                    result = {"approved": False, "reason": "Not a property photo"}
                return jsonify(result)

            except Exception as e:
                print(f"[IMAGE VALIDATOR] API error: {e} — using local fallback")

        return jsonify(local_validate(b64_data, filename))

    except Exception as e:
        print(f"[IMAGE VALIDATOR ERROR] {e}")
        return jsonify({"approved": True, "reason": ""})


# ══════════════════════════════════════════
#  PAGE ROUTES
# ══════════════════════════════════════════
@app.route("/")
def home():
    return render_template("logoo.html")

@app.route("/index")
def index():
    return render_template("index.html")

@app.route("/about")
def about():
    return render_template("ABOUTUS.HTML")

@app.route("/leadership")
def leadership():
    return render_template("LEADERSHIP.HTML")

@app.route("/service")
def service():
    return render_template("service.html")

@app.route("/profile")
def profile():
    return render_template("profile.html")

@app.route("/shop")
def shop():
    return render_template("shop.html")

@app.route("/seller")
def seller():
    return render_template("seller.html")

@app.route("/bargraph")
def bargraph():
    return render_template("bargraph.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/create")
def create():
    return render_template("create.html")

@app.route("/success")
def success():
    return render_template("success.html")

@app.route("/loginpage")
def loginpage():
    return render_template("login.html")

@app.route("/registerpage")
def registerpage():
    return render_template("register.html")


# ══════════════════════════════════════════
#  API — GET ALL PROPERTIES
# ══════════════════════════════════════════
@app.route("/api/properties")
def api_properties():
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM properties ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        raw_images = d.get("images") or ""
        d["images"] = [i.strip() for i in raw_images.split(",") if i.strip()]
        d["price"]  = float(d.get("price") or 0)
        # Ensure status has a default value for old rows
        if not d.get("status"):
            d["status"] = "Sale"
        result.append(d)
    return jsonify(result)


# ══════════════════════════════════════════
#  API — ADD PROPERTY (from seller page)
# ══════════════════════════════════════════
@app.route("/add_property", methods=["POST"])
def add_property():
    seller_name  = request.form.get("sellerName",  "")
    seller_phone = request.form.get("sellerPhone", "")
    seller_email = request.form.get("sellerEmail", session.get("user", ""))
    title        = request.form.get("title",       "")
    location     = request.form.get("location",    "")
    prop_type    = request.form.get("type",        "")
    status       = request.form.get("status",      "Sale")   # ✅ Sale or Rent
    price        = request.form.get("price",       0)
    bedrooms     = request.form.get("bedrooms",    0)
    bathrooms    = request.form.get("bathrooms",   0)
    description  = request.form.get("description", "")

    if not title or not location or not price:
        return jsonify({"error": "Title, location and price are required"}), 400

    image_paths = []
    for file in request.files.getlist("images"):
        if file and file.filename and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            image_paths.append("/static/uploads/" + filename)

    conn = get_db()
    conn.execute("""
        INSERT INTO properties
            (seller_name, seller_phone, seller_email,
             title, location, type, status,
             price, bedrooms, bathrooms,
             description, images)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (seller_name, seller_phone, seller_email,
         title, location, prop_type, status,
         float(price or 0), int(bedrooms or 0), int(bathrooms or 0),
         description, ",".join(image_paths))
    )
    conn.commit()
    conn.close()

    # Send confirmation email to seller
    if seller_email and "@" in seller_email:
        status_label = "For Rent" if status == "Rent" else "For Sale"
        html = f"""
        <div style="font-family:Arial;max-width:600px;margin:auto;background:#fff;
             border-radius:16px;overflow:hidden;box-shadow:0 8px 30px rgba(0,0,0,0.1)">
          <div style="background:linear-gradient(135deg,#0a0a0a,#1c1c1c);
               padding:40px;text-align:center">
            <h1 style="color:#ffd700;margin:0 0 6px">EasyEstate</h1>
            <p style="color:rgba(255,255,255,0.45);font-size:13px;margin:0">
              Property Listing Confirmed</p>
          </div>
          <div style="padding:36px 40px">
            <h2 style="color:#111;margin-bottom:10px">Hi {seller_name}! &#x1F389;</h2>
            <p style="color:#666;line-height:1.7;margin-bottom:24px">
              Your property has been <strong>successfully listed</strong> on EasyEstate.
              Verified buyers can now see your listing!</p>
            <div style="background:#f9f9f9;border-radius:12px;padding:24px;margin-bottom:24px">
              <h3 style="color:#d4af37;margin-bottom:16px;border-bottom:1px solid #eee;
                  padding-bottom:10px">&#x1F3E0; Property Details</h3>
              <table style="width:100%;font-size:14px">
                <tr><td style="color:#999;padding:6px 0">Title</td>
                    <td style="font-weight:600;color:#111">{title}</td></tr>
                <tr><td style="color:#999;padding:6px 0">Location</td>
                    <td style="font-weight:600;color:#111">{location}</td></tr>
                <tr><td style="color:#999;padding:6px 0">Type</td>
                    <td style="font-weight:600;color:#111">{prop_type or "—"}</td></tr>
                <tr><td style="color:#999;padding:6px 0">Status</td>
                    <td style="font-weight:600;color:#111">{status_label}</td></tr>
                <tr><td style="color:#999;padding:6px 0">Bedrooms</td>
                    <td style="font-weight:600;color:#111">{bedrooms}</td></tr>
                <tr><td style="color:#999;padding:6px 0">Bathrooms</td>
                    <td style="font-weight:600;color:#111">{bathrooms}</td></tr>
              </table>
              <div style="font-size:26px;color:#d4af37;font-weight:700;text-align:center;
                   padding:16px;background:linear-gradient(135deg,#fffbea,#fff8d6);
                   border-radius:10px;margin-top:14px">
                Rs.{float(price or 0):,.0f}
              </div>
            </div>
            <div style="text-align:center">
              <a href="http://127.0.0.1:5000/shop"
                 style="background:linear-gradient(135deg,#b8860b,#ffd700);color:#000;
                 text-decoration:none;padding:14px 36px;border-radius:30px;
                 font-weight:700;font-size:15px;display:inline-block">
                View on EasyEstate &#x2192;</a>
            </div>
          </div>
          <div style="background:#0a0a0a;padding:20px 40px;text-align:center">
            <p style="color:#444;font-size:12px;margin:4px 0">
              &#xa9; 2026 <span style="color:#d4af37">EasyEstate</span> | Mangalore, Karnataka</p>
            <p style="color:#444;font-size:12px;margin:4px 0">
              easyestate2026@gmail.com | +91 98765 43210</p>
          </div>
        </div>"""
        send_email(seller_email, "Your Property is Listed on EasyEstate!", html)

    return jsonify({"status": "success", "message": "Property listed! Confirmation email sent."})


# ══════════════════════════════════════════
#  API — BARGRAPH DATA
# ══════════════════════════════════════════
@app.route("/api/bargraph_data")
def bargraph_data():
    conn = get_db()
    loc  = conn.execute(
        "SELECT location, AVG(price) as avg_price, COUNT(*) as count "
        "FROM properties GROUP BY location ORDER BY avg_price DESC"
    ).fetchall()
    typ  = conn.execute(
        "SELECT type, AVG(price) as avg_price, COUNT(*) as count "
        "FROM properties WHERE type != '' GROUP BY type ORDER BY avg_price DESC"
    ).fetchall()
    all_ = conn.execute(
        "SELECT title, location, type, status, price, bedrooms, bathrooms, "
        "seller_name, created_at FROM properties ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return jsonify({
        "by_location"   : [{"location": r["location"], "avg_price": round(r["avg_price"], 2), "count": r["count"]} for r in loc],
        "by_type"       : [{"type": r["type"], "avg_price": round(r["avg_price"], 2), "count": r["count"]} for r in typ],
        "all_properties": [dict(p) for p in all_]
    })


# ══════════════════════════════════════════
#  CONTACT FORM
# ══════════════════════════════════════════
@app.route("/contact", methods=["POST"])
def contact_submit():
    data    = request.json or request.form
    name    = data.get("name")
    email   = data.get("email")
    message = data.get("message")
    if not name or not email or not message:
        return jsonify({"error": "All fields required"}), 400
    conn = get_db()
    conn.execute("INSERT INTO contacts (name, email, message) VALUES (?, ?, ?)", (name, email, message))
    conn.commit()
    conn.close()
    return jsonify({"message": "Message sent successfully"})


# ══════════════════════════════════════════
#  REGISTER INTEREST
# ══════════════════════════════════════════
@app.route("/register_interest", methods=["POST"])
def register_interest():
    data        = request.json or {}
    buyer_name  = data.get("buyer_name",  "")
    buyer_email = data.get("buyer_email", "")
    interest    = data.get("interest",    "Buy")
    reg_no      = data.get("reg_no",      "")
    prop        = data.get("property",    {})

    if not buyer_email or "@" not in buyer_email:
        return jsonify({"error": "Valid email required"}), 400

    price = float(prop.get("price", 0) or 0)
    if   price >= 10000000: price_str = f"Rs.{price/10000000:.2f} Cr"
    elif price >= 100000:   price_str = f"Rs.{price/100000:.1f} L"
    else:                   price_str = f"Rs.{price:,.0f}"

    image_url = prop.get("image", "")
    img_html  = ""
    if image_url:
        if image_url.startswith("/"):
            image_url = f"http://127.0.0.1:5000{image_url}"
        img_html = (f'<img src="{image_url}" style="width:100%;max-height:260px;'
                    f'object-fit:cover;border-radius:12px;margin:16px 0" alt="Property">')

    seller_name      = prop.get("seller_name",  "Not provided")
    seller_phone     = prop.get("seller_phone", "Not provided")
    seller_email_val = prop.get("seller_email", "")

    step_buy = [
        "Contact the owner using the details above and mention your registration number.",
        "Schedule a property visit and verify all documents (title deed, encumbrance certificate).",
        "Negotiate the final sale price and agree on payment terms.",
        "Engage a lawyer to draft the sale agreement and verify legal clearances.",
        "Complete payment and register the property at the sub-registrar office."
    ]
    step_rent = [
        "Contact the owner using the details above and mention your registration number.",
        "Schedule a property visit at a mutually convenient time.",
        "Negotiate the rental amount and terms directly with the owner.",
        "Sign the rental agreement and pay the security deposit (usually 2–3 months rent).",
        "Complete the registration at the local sub-registrar office if required."
    ]
    steps = step_rent if interest == "Rent" else step_buy
    steps_html = "".join([
        f'<div style="display:flex;align-items:flex-start;gap:10px;margin-bottom:12px;font-size:13px;color:#444;line-height:1.6">'
        f'<div style="min-width:24px;height:24px;background:#22c55e;color:#fff;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;flex-shrink:0">{i+1}</div>'
        f'<div style="padding-top:3px">{s}</div></div>'
        for i, s in enumerate(steps)
    ])

    seller_email_row = ""
    if seller_email_val:
        seller_email_row = (
            f'<tr><td style="padding:8px 0;border-bottom:1px solid rgba(255,255,255,0.06);font-size:14px;color:#777">Email</td>'
            f'<td style="padding:8px 0;border-bottom:1px solid rgba(255,255,255,0.06);font-size:14px;color:#ffd700;font-weight:600;text-align:right">{seller_email_val}</td></tr>'
        )

    interest_color = "#3b82f6" if interest == "Buy" else "#a855f7"
    process_label  = "Purchase" if interest == "Buy" else "Rental"
    action_word    = "purchasing" if interest == "Buy" else "renting"
    interest_icon  = "&#x1F3E0; Buying" if interest == "Buy" else "&#x1F511; Renting"

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<style>
  body{{font-family:Arial,sans-serif;background:#f0f0f0;margin:0;padding:20px 0;}}
  .wrap{{max-width:620px;margin:0 auto;background:#fff;border-radius:20px;overflow:hidden;box-shadow:0 12px 40px rgba(0,0,0,0.15);}}
  .header{{background:linear-gradient(135deg,#0a0a0a 0%,#1a1a1a 100%);padding:44px 40px;text-align:center;}}
  .body{{padding:40px;}}
  .section{{border-radius:14px;padding:24px;margin-bottom:22px;}}
  .section-title{{font-size:16px;font-weight:700;margin-bottom:16px;border-bottom:1px solid rgba(0,0,0,0.08);padding-bottom:10px;}}
  .prop-section{{background:#f8f8f8;border:1px solid #ebebeb;}}
  .prop-section .section-title{{color:#d4af37;border-bottom-color:#e8e8e8;}}
  .owner-section{{background:linear-gradient(135deg,#0c0c0c,#161616);}}
  .owner-section .section-title{{color:#ffd700;border-bottom-color:rgba(255,255,255,0.08);}}
  .steps-section{{background:#f0fff6;border:1px solid rgba(34,197,94,0.2);}}
  .steps-section .section-title{{color:#166534;border-bottom-color:rgba(34,197,94,0.15);}}
  .footer{{background:#0a0a0a;padding:24px 40px;text-align:center;}}
  .footer p{{color:#444;font-size:12px;margin:4px 0;}}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <div style="width:70px;height:70px;background:rgba(34,197,94,0.15);border:2px solid rgba(34,197,94,0.5);border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-size:30px;margin-bottom:18px;">&#x2705;</div>
    <h1 style="color:#ffd700;font-size:28px;margin:0 0 6px;letter-spacing:1px">EasyEstate</h1>
    <p style="color:rgba(255,255,255,0.4);font-size:13px;margin:0;">Property Interest Confirmation</p>
  </div>
  <div class="body">
    <h2 style="font-size:24px;font-weight:700;color:#111;margin-bottom:8px;">Congratulations, {buyer_name}! &#x1F389;</h2>
    <p style="font-size:15px;color:#555;line-height:1.8;margin-bottom:24px;">Your interest has been <strong>successfully registered</strong> on EasyEstate.</p>
    <div style="margin-bottom:24px;">
      <span style="display:inline-block;background:linear-gradient(135deg,#b8860b,#ffd700);color:#000;padding:7px 20px;border-radius:30px;font-weight:700;font-size:14px;margin-right:8px;">Reg No: {reg_no}</span>
      <span style="display:inline-block;padding:5px 16px;border-radius:20px;font-size:12px;font-weight:600;color:{interest_color};background:rgba(59,130,246,0.08);border:1px solid rgba(59,130,246,0.25);">{interest_icon}</span>
    </div>
    {img_html}
    <div class="section prop-section">
      <div class="section-title">&#x1F3E0; Property Details</div>
      <table style="width:100%;border-collapse:collapse;">
        <tr><td style="color:#999;width:40%;padding:9px 0;border-bottom:1px solid #f0f0f0;font-size:14px">Title</td><td style="font-weight:600;color:#111;text-align:right;padding:9px 0;border-bottom:1px solid #f0f0f0;font-size:14px">{prop.get("title","—")}</td></tr>
        <tr><td style="color:#999;padding:9px 0;border-bottom:1px solid #f0f0f0;font-size:14px">Location</td><td style="font-weight:600;color:#111;text-align:right;padding:9px 0;border-bottom:1px solid #f0f0f0;font-size:14px">&#x1F4CD; {prop.get("location","—")}</td></tr>
        <tr><td style="color:#999;padding:9px 0;border-bottom:1px solid #f0f0f0;font-size:14px">Type</td><td style="font-weight:600;color:#111;text-align:right;padding:9px 0;border-bottom:1px solid #f0f0f0;font-size:14px">{prop.get("type","—")}</td></tr>
        <tr><td style="color:#999;padding:9px 0;font-size:14px">Bedrooms</td><td style="font-weight:600;color:#111;text-align:right;padding:9px 0;font-size:14px">&#x1F6CF; {prop.get("bedrooms","—")}</td></tr>
      </table>
      <div style="font-size:26px;color:#d4af37;font-weight:700;text-align:center;padding:16px;background:linear-gradient(135deg,#fffbea,#fff5c0);border-radius:12px;margin-top:16px;">{price_str}</div>
    </div>
    <div class="section owner-section">
      <div class="section-title">&#x1F4DE; Owner / Seller Contact Details</div>
      <table style="width:100%;border-collapse:collapse;">
        <tr><td style="color:#666;width:40%;padding:9px 0;border-bottom:1px solid rgba(255,255,255,0.06);font-size:14px">Owner Name</td><td style="color:#f0f0f0;font-weight:600;text-align:right;padding:9px 0;border-bottom:1px solid rgba(255,255,255,0.06);font-size:14px">&#x1F464; {seller_name}</td></tr>
        <tr><td style="color:#666;padding:9px 0;font-size:14px">Phone</td><td style="color:#ffd700;font-weight:700;text-align:right;padding:9px 0;font-size:14px">&#x1F4F1; {seller_phone}</td></tr>
        {seller_email_row}
      </table>
      <div style="background:rgba(255,215,0,0.05);border:1px solid rgba(255,215,0,0.2);border-radius:10px;padding:14px 18px;margin-top:14px;font-size:13px;color:#aaa;line-height:1.6;">
        &#x1F4CC; Mention Reg No <strong style="color:#ffd700">{reg_no}</strong> when contacting the owner.
      </div>
    </div>
    <div class="section steps-section">
      <div class="section-title">&#x1F4CB; Next Steps — {process_label} Process</div>
      {steps_html}
    </div>
    <div style="text-align:center;margin:28px 0;">
      <a href="http://127.0.0.1:5000/shop" style="background:linear-gradient(135deg,#b8860b,#ffd700);color:#000;text-decoration:none;padding:15px 40px;border-radius:30px;font-weight:700;font-size:15px;display:inline-block;">Browse More Properties &#x2192;</a>
    </div>
  </div>
  <div class="footer">
    <p>&#xa9; 2026 <span style="color:#d4af37">EasyEstate</span> | Mangalore, Karnataka, India</p>
    <p>easyestate2026@gmail.com | +91 98765 43210</p>
  </div>
</div>
</body></html>"""

    email_sent = send_email(buyer_email, f"Congratulations {buyer_name}! Your Interest is Registered — EasyEstate", html)
    return jsonify({"status": "success", "email_sent": email_sent})


# ══════════════════════════════════════════
#  AUTH — LOGIN / LOGOUT / REGISTER
# ══════════════════════════════════════════
@app.route("/login", methods=["POST"])
def login():
    data     = request.json or {}
    email    = data.get("email",    "")
    password = data.get("password", "")
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email=? AND password=?", (email, password)).fetchone()
    conn.close()
    if user:
        session["user"] = email
        return jsonify({"message": "Login successful", "name": user["name"]})
    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("home"))


@app.route("/register", methods=["POST"])
def register():
    data     = request.json or {}
    name     = data.get("name",     "")
    email    = data.get("email",    "")
    phone    = data.get("phone",    "")
    password = data.get("password", "")
    if not name or not email or not password:
        return jsonify({"error": "All fields required"}), 400
    conn = get_db()
    try:
        conn.execute("INSERT INTO users (name, email, phone, password) VALUES (?,?,?,?)", (name, email, phone, password))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Email already registered"}), 409
    conn.close()
    html = f"""
    <div style="font-family:Arial;max-width:600px;margin:auto;background:#fff;border-radius:16px;overflow:hidden">
      <div style="background:linear-gradient(135deg,#0a0a0a,#1c1c1c);padding:40px;text-align:center">
        <h1 style="color:#ffd700;margin:0">&#x1F3E0; Welcome to EasyEstate</h1>
        <p style="color:rgba(255,255,255,0.45);margin:6px 0 0;font-size:13px">Luxury Living Starts Here</p>
      </div>
      <div style="padding:40px">
        <h2 style="color:#111">Hello, {name}! &#x1F44B;</h2>
        <p style="color:#666;line-height:1.75;margin:12px 0 24px">Your account has been created. You now have access to premium verified property listings across India.</p>
        <div style="text-align:center">
          <a href="http://127.0.0.1:5000/index" style="background:linear-gradient(135deg,#b8860b,#ffd700);color:#000;text-decoration:none;padding:14px 40px;border-radius:30px;font-weight:700;font-size:15px;display:inline-block">Explore Properties &#x2192;</a>
        </div>
      </div>
      <div style="background:#0a0a0a;padding:20px 40px;text-align:center">
        <p style="color:#444;font-size:12px">&#xa9; 2026 <span style="color:#d4af37">EasyEstate</span> | Mangalore, Karnataka</p>
        <p style="color:#444;font-size:12px">easyestate2026@gmail.com</p>
      </div>
    </div>"""
    send_email(email, "Welcome to EasyEstate!", html)
    return jsonify({"message": "User registered successfully"})


# ══════════════════════════════════════════
#  ADMIN ROUTES
# ══════════════════════════════════════════
@app.route("/admin")
@app.route("/admin/login")
def admin_login_page():
    if session.get("admin_logged_in"):
        return redirect(url_for("admin_messages"))
    return render_template("admin_login.html")


@app.route("/admin/login", methods=["POST"])
def admin_login():
    data     = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        session["admin_logged_in"] = True
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Invalid admin credentials"}), 401


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_logged_in", None)
    return redirect(url_for("admin_login_page"))


@app.route("/admin/messages")
@admin_required
def admin_messages():
    conn     = get_db()
    messages = conn.execute("SELECT * FROM contacts ORDER BY created_at DESC").fetchall()
    conn.close()
    return render_template("admin_messages.html", messages=messages)


@app.route("/admin/properties")
@admin_required
def admin_properties():
    conn       = get_db()
    properties = conn.execute("SELECT * FROM properties ORDER BY created_at DESC").fetchall()
    conn.close()
    return render_template("admin_properties.html", properties=properties)


@app.route("/admin/users")
@admin_required
def admin_users():
    conn  = get_db()
    users = conn.execute("SELECT id, name, email, phone FROM users ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("admin_users.html", users=users)


@app.route("/admin/delete_message/<int:msg_id>", methods=["POST"])
@admin_required
def delete_message(msg_id):
    conn = get_db()
    conn.execute("DELETE FROM contacts WHERE id=?", (msg_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_messages"))


@app.route("/admin/delete_properties/<int:property_id>", methods=["POST"])
@admin_required
def delete_property(property_id):
    conn = get_db()
    conn.execute("DELETE FROM properties WHERE id=?", (property_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_properties"))


@app.route("/admin/toggle_property/<int:property_id>", methods=["POST"])
@admin_required
def toggle_property(property_id):
    conn = get_db()
    conn.execute("UPDATE properties SET is_active = NOT is_active WHERE id=?", (property_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_properties"))


# ══════════════════════════════════════════
#  API — USER PROFILE
# ══════════════════════════════════════════
@app.route("/api/me")
def api_me():
    email = session.get("user")
    if not email:
        return jsonify({"error": "Not logged in"}), 401
    conn = get_db()
    user = conn.execute(
        "SELECT id, name, email, phone, created_at FROM users WHERE email=?", (email,)
    ).fetchone()
    conn.close()
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(dict(user))


@app.route("/api/update_profile", methods=["POST"])
def update_profile():
    email = session.get("user")
    if not email:
        return jsonify({"error": "Not logged in"}), 401
    data     = request.json or {}
    name     = data.get("name", "").strip()
    phone    = data.get("phone", "").strip()
    password = data.get("password", "").strip()
    if not name:
        return jsonify({"error": "Name is required"}), 400
    conn = get_db()
    if password:
        conn.execute("UPDATE users SET name=?, phone=?, password=? WHERE email=?", (name, phone, password, email))
    else:
        conn.execute("UPDATE users SET name=?, phone=? WHERE email=?", (name, phone, email))
    conn.commit()
    conn.close()
    return jsonify({"message": "Profile updated"})


@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data  = request.get_json()
    email = data.get('email')
    if not email:
        return jsonify({'error': 'Email is required'}), 400
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()
    if not user:
        return jsonify({'error': 'No account found with this email'}), 404
    return jsonify({'message': 'Reset link sent'}), 200


# ══════════════════════════════════════════
#  API — AI CHAT
# ══════════════════════════════════════════
@app.route("/api/chat", methods=["POST"])
def chat():
    data     = request.json or {}
    user_msg = data.get("message", "").strip()
    history  = data.get("history", [])
    if not user_msg:
        return jsonify({"error": "Empty message"}), 400

    messages = history + [{"role": "user", "content": user_msg}]
    payload  = json.dumps({
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 500,
        "system": """You are EasyEstate Assistant, a helpful real estate advisor
        for an Indian property platform. Help users with questions about buying,
        renting, property prices, locations, legal process, and home loans.
        Keep answers concise and practical. Always respond in a friendly,
        professional tone. If asked something unrelated to real estate,
        politely redirect to property topics.""",
        "messages": messages
    }).encode("utf-8")

    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "x-api-key": ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01"
        },
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode("utf-8"))
        reply = result["content"][0]["text"]
        return jsonify({"reply": reply})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ══════════════════════════════════════════
#  RUN
# ══════════════════════════════════════════
if __name__ == "__main__":
    init_db()
    app.run(debug=True)
