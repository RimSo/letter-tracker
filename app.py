import os
import io
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, send_from_directory, abort
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event, text, case
from werkzeug.utils import secure_filename
from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from PIL import Image, ImageOps, ImageDraw
import sqlite3

# ---------------------------------------------------------------------
# Paths / basic config
# ---------------------------------------------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
UPLOAD_DIR = os.path.join(DATA_DIR, 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, 'letters.db')

# Avatar upload folder
AVATAR_DIR = os.path.join(BASE_DIR, "static", "avatars")
os.makedirs(AVATAR_DIR, exist_ok=True)
# Avatar settings
AVATAR_SIZE = 256
AVATAR_MAX_BYTES = 1 * 1024 * 1024  # 1 MB
AVATAR_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "webp", "svg"}

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "change-me-please")

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + DB_PATH
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

USERS_DB = os.path.join(BASE_DIR, "users.sqlite")

# ---------------------------------------------------------------------
# Users (SQLite)
# ---------------------------------------------------------------------
class User(UserMixin):
    def __init__(self, id_, email, name, avatar_path=None):
        self.id = str(id_)
        self.email = email
        self.name = name
        self.avatar_path = avatar_path


def _users_conn():
    conn = sqlite3.connect(USERS_DB)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_users_table():
    """Create / migrate users table (adds verified column if missing)."""
    with _users_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              email TEXT UNIQUE NOT NULL,
              name TEXT NOT NULL,
              password_hash TEXT NOT NULL,
              verified INTEGER DEFAULT 0,
              created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        cols = [row["name"] for row in conn.execute("PRAGMA table_info(users)")]
        if "verified" not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN verified INTEGER DEFAULT 0")
        conn.commit()

# Add avatar_path column if missing
with _users_conn() as conn:
    cols = [r[1] for r in conn.execute("PRAGMA table_info(users)")]
    if "avatar_path" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN avatar_path TEXT")
    conn.commit()

@app.before_request
def _bootstrap_auth_once():
    if not getattr(app, "_auth_initialized", False):
        ensure_users_table()
        app._auth_initialized = True


@login_manager.user_loader
def load_user(user_id):
    with _users_conn() as conn:
        row = conn.execute(
            "SELECT id, email, name, avatar_path FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()
    if row:
        return User(
            id_=row["id"],
            email=row["email"],
            name=row["name"],
            avatar_path=row["avatar_path"]
        )
    return None


# ---------------------------------------------------------------------
# Token helpers for email verification & password reset
# ---------------------------------------------------------------------
def _get_serializer(purpose: str) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(app.secret_key, salt=f"letter-tracker-{purpose}")


def generate_token(user_id: int, purpose: str) -> str:
    s = _get_serializer(purpose)
    return s.dumps({"user_id": user_id})


def load_token(token: str, purpose: str, max_age: int):
    s = _get_serializer(purpose)
    return s.loads(token, max_age=max_age)


def send_link_via_flash(label: str, url: str):
    """
    For now we 'send' emails by flashing the link.
    (You can later replace this with real SMTP sending.)
    """
    flash(f"{label}: {url}", "info")


# ---------------------------------------------------------------------
# Upload rules / DB
# ---------------------------------------------------------------------
ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png', 'doc', 'docx'}
MAX_FILE_MB = 10
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_MB * 1024 * 1024

db = SQLAlchemy(app)

# --- Country list ---
COUNTRIES = [
    "Afghanistan","Albania","Algeria","Andorra","Angola","Antigua and Barbuda","Argentina","Armenia","Australia","Austria",
    "Azerbaijan","Bahamas","Bahrain","Bangladesh","Barbados","Belarus","Belgium","Belize","Benin","Bhutan",
    "Bolivia","Bosnia and Herzegovina","Botswana","Brazil","Brunei","Bulgaria","Burkina Faso","Burundi","Cabo Verde","Cambodia",
    "Cameroon","Canada","Central African Republic","Chad","Chile","China","Colombia","Comoros","Congo (Congo-Brazzaville)","Costa Rica",
    "Côte d’Ivoire","Croatia","Cuba","Cyprus","Czechia","Democratic Republic of the Congo","Denmark","Djibouti","Dominica","Dominican Republic",
    "Ecuador","Egypt","El Salvador","Equatorial Guinea","Eritrea","Estonia","Eswatini","Ethiopia","Fiji","Finland",
    "France","Gabon","Gambia","Georgia","Germany","Ghana","Greece","Grenada","Guatemala","Guinea",
    "Guinea-Bissau","Guyana","Haiti","Honduras","Hungary","Iceland","India","Indonesia","Iran","Iraq",
    "Ireland","Israel","Italy","Jamaica","Japan","Jordan","Kazakhstan","Kenya","Kiribati","Kuwait",
    "Kyrgyzstan","Laos","Latvia","Lebanon","Lesotho","Liberia","Libya","Liechtenstein","Lithuania","Luxembourg",
    "Madagascar","Malawi","Malaysia","Maldives","Mali","Malta","Marshall Islands","Mauritania","Mauritius","Mexico",
    "Micronesia","Moldova","Monaco","Mongolia","Montenegro","Morocco","Mozambique","Myanmar","Namibia","Nauru",
    "Nepal","Netherlands","New Zealand","Nicaragua","Niger","Nigeria","North Korea","North Macedonia","Norway","Oman",
    "Pakistan","Palau","Panama","Papua New Guinea","Paraguay","Peru","Philippines","Poland","Portugal","Qatar",
    "Romania","Russia","Rwanda","Saint Kitts and Nevis","Saint Lucia","Saint Vincent and the Grenadines","Samoa","San Marino","Sao Tome and Principe","Saudi Arabia",
    "Senegal","Serbia","Seychelles","Sierra Leone","Singapore","Slovakia","Slovenia","Solomon Islands","Somalia","South Africa",
    "South Korea","South Sudan","Spain","Sri Lanka","Sudan","Suriname","Sweden","Switzerland","Syria","Taiwan",
    "Tajikistan","Tanzania","Thailand","Timor-Leste","Togo","Tonga","Trinidad and Tobago","Tunisia","Turkey","Turkmenistan",
    "Tuvalu","Uganda","Ukraine","United Arab Emirates","United Kingdom","United States","Uruguay","Uzbekistan","Vanuatu","Vatican City",
    "Venezuela","Vietnam","Yemen","Zambia","Zimbabwe"
]


class Letter(db.Model):
    __tablename__ = 'letters'
    id = db.Column(db.Integer, primary_key=True)
    nickname = db.Column(db.String(120), nullable=True)
    name = db.Column(db.String(200), nullable=False)
    to_country = db.Column(db.String(120), nullable=False)
    from_country = db.Column(db.String(120), nullable=False, default='Qatar')
    sent_date = db.Column(db.Date, nullable=True)
    received_date = db.Column(db.Date, nullable=True)
    days = db.Column(db.Integer, nullable=True)
    tracking = db.Column(db.String(200), nullable=True)

    letter_type = db.Column(db.String(20), default='Sending')  # 'Sending' or 'Receiving'
    is_completed = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(20), default='Active')  # 'Active' or 'Draft'
    attachment_path = db.Column(db.String(255), nullable=True)  # stored filename only

    def recompute_days_and_completion(self):
        if self.sent_date and self.received_date:
            self.days = (self.received_date - self.sent_date).days
            self.is_completed = True
        else:
            self.days = None


@event.listens_for(Letter, 'before_insert')
def before_insert(mapper, connection, target):
    target.recompute_days_and_completion()


@event.listens_for(Letter, 'before_update')
def before_update(mapper, connection, target):
    target.recompute_days_and_completion()


def parse_date(val: str):
    if not val:
        return None
    for fmt in ('%Y-%m-%d', '%d/%m/%Y'):
        try:
            return datetime.strptime(val, fmt).date()
        except ValueError:
            continue
    return None


def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.context_processor
def inject_globals():
    return {
        'COUNTRIES': COUNTRIES,
        'now': datetime.utcnow
    }


def sent_date_desc(q):
    # SQLite lacks NULLS LAST; emulate: first rows where sent_date IS NOT NULL, then date desc, then id desc
    return q.order_by(
        case((Letter.sent_date.is_(None), 1), else_=0),
        Letter.sent_date.desc(),
        Letter.id.desc()
    )

# ---------------------------------------------------------------------
# Letter views (all protected)
# ---------------------------------------------------------------------
@app.route('/')
@login_required
def index():
    q = request.args.get('q', '').strip()
    query = Letter.query
    if q:
        like = f"%{q}%"
        query = query.filter(
            (Letter.nickname.ilike(like)) |
            (Letter.name.ilike(like)) |
            (Letter.to_country.ilike(like)) |
            (Letter.from_country.ilike(like)) |
            (Letter.tracking.ilike(like))
        )
    letters = sent_date_desc(query).all()

    sending_letters = sent_date_desc(
        Letter.query.filter_by(letter_type='Sending', is_completed=False)
    ).all()
    receiving_letters = sent_date_desc(
        Letter.query.filter_by(letter_type='Receiving', is_completed=False)
    ).all()
    completed_letters = sent_date_desc(
        Letter.query.filter_by(is_completed=True)
    ).all()
    draft_letters = sent_date_desc(
        Letter.query.filter_by(status='Draft')
    ).all()

    counts = {
        "all": len(letters),
        "sending": len(sending_letters),
        "receiving": len(receiving_letters),
        "completed": len(completed_letters),
        "draft": len(draft_letters),
    }

    return render_template(
        'index.html',
        letters=letters,
        sending_letters=sending_letters,
        receiving_letters=receiving_letters,
        completed_letters=completed_letters,
        draft_letters=draft_letters,
        counts=counts,
        q=q
    )


@app.route('/uploads/<path:filename>')
@login_required
def uploaded_file(filename):
    # Security: serve only from UPLOAD_DIR
    safe_name = os.path.basename(filename)
    full_path = os.path.join(UPLOAD_DIR, safe_name)
    if not os.path.isfile(full_path):
        abort(404)
    return send_from_directory(UPLOAD_DIR, safe_name, as_attachment=False)


@app.route('/add', methods=['POST'])
@login_required
def add():
    nickname = request.form.get('nickname') or None
    name = request.form.get('name')
    letter_type = request.form.get('letter_type') or 'Sending'
    to_country = request.form.get('to_country')
    from_country = request.form.get('from_country') or 'Qatar'
    sent_date = parse_date(request.form.get('sent_date'))
    received_date = parse_date(request.form.get('received_date'))
    tracking = request.form.get('tracking') or None

    # Attachment (mandatory)
    file = request.files.get('attachment')
    if not file or file.filename == '':
        flash('Attachment is required.', 'danger')
        return redirect(url_for('index'))
    if not allowed_file(file.filename):
        flash('Invalid file type. Allowed: pdf, jpg, jpeg, png, doc, docx.', 'danger')
        return redirect(url_for('index'))
    orig = secure_filename(file.filename)
    ext = orig.rsplit('.', 1)[1].lower()

    if not name or not to_country:
        flash('Name and To Country are required.', 'danger')
        return redirect(url_for('index'))

    # Create letter first to get ID for filename when nickname is missing
    letter = Letter(
        nickname=nickname,
        name=name,
        letter_type=letter_type,
        to_country=to_country,
        from_country=from_country,
        sent_date=sent_date,
        received_date=received_date,
        tracking=tracking,
    )
    db.session.add(letter)
    db.session.flush()  # get letter.id without full commit

    # Build filename
    if nickname:
        base = f"{secure_filename(nickname)}_attachment"
    else:
        base = f"letter_{letter.id}_attachment"
    final_filename = f"{base}.{ext}"
    save_path = os.path.join(UPLOAD_DIR, final_filename)

    # If file exists, append timestamp for uniqueness
    if os.path.exists(save_path):
        ts = datetime.now().strftime('%Y%m%d%H%M%S')
        final_filename = f"{base}_{ts}.{ext}"
        save_path = os.path.join(UPLOAD_DIR, final_filename)

    file.save(save_path)
    letter.attachment_path = final_filename

    # If it's a Sending record, auto-create a Receiving draft (reverse To/From)
    if letter_type == 'Sending':
        receiving_copy = Letter(
            nickname=nickname,
            name=name,
            letter_type='Receiving',
            to_country=from_country,   # reversed
            from_country=to_country,   # reversed
            sent_date=sent_date,
            tracking=tracking,
            status='Draft',
        )
        db.session.add(receiving_copy)

    db.session.commit()
    flash('Letter added.', 'success')
    return redirect(url_for('index'))


@app.route('/edit/<int:letter_id>')
@login_required
def edit(letter_id):
    letter = Letter.query.get_or_404(letter_id)
    return render_template('edit.html', letter=letter)


@app.route('/update/<int:letter_id>', methods=['POST'])
@login_required
def update(letter_id):
    letter = Letter.query.get_or_404(letter_id)
    letter.nickname = request.form.get('nickname') or None
    letter.name = request.form.get('name')
    letter.letter_type = request.form.get('letter_type') or 'Sending'
    letter.to_country = request.form.get('to_country')
    letter.from_country = request.form.get('from_country') or 'Qatar'
    letter.sent_date = parse_date(request.form.get('sent_date'))
    letter.received_date = parse_date(request.form.get('received_date'))
    letter.tracking = request.form.get('tracking') or None

    # Draft -> Active when any date is set
    if letter.status == 'Draft' and (letter.sent_date or letter.received_date):
        letter.status = 'Active'

    db.session.commit()
    flash('Letter updated.', 'success')
    return redirect(url_for('index'))


@app.route('/delete/<int:letter_id>', methods=['POST'])
@login_required
def delete(letter_id):
    letter = Letter.query.get_or_404(letter_id)
    # Also try to remove attachment from disk (optional)
    if letter.attachment_path:
        try:
            os.remove(os.path.join(UPLOAD_DIR, letter.attachment_path))
        except Exception:
            pass
    db.session.delete(letter)
    db.session.commit()
    flash('Letter deleted.', 'warning')
    return redirect(url_for('index'))


@app.route('/complete/<int:letter_id>', methods=['POST'])
@login_required
def complete(letter_id):
    letter = Letter.query.get_or_404(letter_id)
    if letter.sent_date and letter.received_date:
        letter.is_completed = True
        db.session.commit()
        flash('Marked as completed.', 'success')
    else:
        flash('Cannot complete: set both Sent and Received dates first.', 'warning')
    return redirect(url_for('index'))

# ---------------------------------------------------------------------
# Auth: register / login / logout / verify / forgot / reset / profile
# ---------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    errors = {}
    name = ""
    email = ""

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm") or ""

        if not name:
            errors["name"] = "Full name is required."
        if not email:
            errors["email"] = "Email is required."
        if not password:
            errors["password"] = "Password is required."
        elif len(password) < 6:
            errors["password"] = "Password must be at least 6 characters."
        if password != confirm:
            errors["confirm"] = "Passwords do not match."

        if not errors:
            try:
                with _users_conn() as conn:
                    cur = conn.execute(
                        "INSERT INTO users (email, name, password_hash) VALUES (?, ?, ?)",
                        (email, name, generate_password_hash(password))
                    )
                    user_id = cur.lastrowid
                    conn.commit()

                # Email verification link (for now via flash)
                token = generate_token(user_id, "email-verify")
                verify_url = url_for("verify_email", token=token, _external=True)
                send_link_via_flash("Verification link", verify_url)

                flash("Account created. Please verify your email.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                errors["email"] = "This email is already registered."

    return render_template(
        "register.html",
        errors=errors,
        name=name,
        email=email,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    errors = {}
    email = ""

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        remember = bool(request.form.get("remember"))

        if not email:
            errors["email"] = "Email is required."
        if not password:
            errors["password"] = "Password is required."

        if not errors:
            with _users_conn() as conn:
                row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            if not row or not check_password_hash(row["password_hash"], password):
                errors["__all__"] = "Invalid email or password."
            elif not row["verified"]:
                errors["__all__"] = "Please verify your email first."

                # Optionally re-send verification link
                token = generate_token(row["id"], "email-verify")
                verify_url = url_for("verify_email", token=token, _external=True)
                send_link_via_flash("New verification link", verify_url)
            else:
                user = User(row["id"], row["email"], row["name"])
                login_user(user, remember=remember)
                flash("Welcome back!", "success")
                next_url = request.args.get("next") or url_for("index")
                return redirect(next_url)

    return render_template("login.html", errors=errors, email=email)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/verify/<token>")
def verify_email(token):
    try:
        data = load_token(token, "email-verify", max_age=60 * 60 * 24 * 3)  # 3 days
    except SignatureExpired:
        flash("Verification link has expired. Please log in and request a new one.", "warning")
        return redirect(url_for("login"))
    except BadSignature:
        flash("Invalid verification link.", "danger")
        return redirect(url_for("login"))

    user_id = data.get("user_id")
    if not user_id:
        flash("Invalid verification link.", "danger")
        return redirect(url_for("login"))

    with _users_conn() as conn:
        conn.execute("UPDATE users SET verified = 1 WHERE id = ?", (user_id,))
        conn.commit()

    flash("Email verified. You can now log in.", "success")
    return redirect(url_for("login"))


@app.route("/forgot", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        if email:
            with _users_conn() as conn:
                row = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
            if row:
                token = generate_token(row["id"], "password-reset")
                reset_url = url_for("reset_password", token=token, _external=True)
                send_link_via_flash("Password reset link", reset_url)
        # Always show generic message
        flash("If that email exists, a reset link has been generated.", "info")
        return redirect(url_for("login"))

    return render_template("forgot.html")


@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        data = load_token(token, "password-reset", max_age=60 * 60 * 24)  # 1 day
    except SignatureExpired:
        flash("Reset link has expired. Please request a new one.", "warning")
        return redirect(url_for("forgot_password"))
    except BadSignature:
        flash("Invalid reset link.", "danger")
        return redirect(url_for("forgot_password"))

    user_id = data.get("user_id")
    if not user_id:
        flash("Invalid reset link.", "danger")
        return redirect(url_for("forgot_password"))

    errors = {}
    if request.method == "POST":
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm") or ""
        if not password:
            errors["password"] = "Password is required."
        elif len(password) < 6:
            errors["password"] = "Password must be at least 6 characters."
        if password != confirm:
            errors["confirm"] = "Passwords do not match."

        if not errors:
            with _users_conn() as conn:
                conn.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    (generate_password_hash(password), user_id)
                )
                conn.commit()
            flash("Password updated. You can now log in.", "success")
            return redirect(url_for("login"))

    return render_template("reset_password.html", errors=errors)

@app.route("/delete_avatar")
@login_required
def delete_avatar():
    # Delete file on disk
    if current_user.avatar_path:
        path = os.path.join(AVATAR_DIR, current_user.avatar_path)
        if os.path.exists(path):
            os.remove(path)

    # Remove from database
    with _users_conn() as conn:
        conn.execute("UPDATE users SET avatar_path = NULL WHERE id = ?", (current_user.id,))
        conn.commit()

    current_user.avatar_path = None
    flash("Profile photo removed.", "success")
    return redirect(url_for("profile"))
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        name = request.form.get("name").strip()
        new_pass = request.form.get("new_password") or ""
        confirm = request.form.get("confirm_password") or ""

        # --- Update name ---
        with _users_conn() as conn:
            conn.execute("UPDATE users SET name = ? WHERE id = ?", (name, current_user.id))
            conn.commit()
        current_user.name = name

        # --- Update password ---
        if new_pass:
            if new_pass != confirm:
                flash("Passwords do not match.", "danger")
                return redirect(url_for("profile"))
            if len(new_pass) < 6:
                flash("Password must be at least 6 characters.", "danger")
                return redirect(url_for("profile"))

            with _users_conn() as conn:
                conn.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    (generate_password_hash(new_pass), current_user.id)
                )
                conn.commit()
            flash("Password updated.", "success")

        # --- Update avatar (resize 256px, circle crop, SVG/WebP support, delete old, 1MB limit) ---
        file = request.files.get("avatar")
        if file and file.filename:
            # Read file into memory
            data = file.read()

            # 1 MB size check
            if len(data) > (1 * 1024 * 1024):  # 1 MB
                flash("Avatar must be at most 1 MB.", "danger")
                return redirect(url_for("profile"))

            # Allowed extensions
            ext = file.filename.rsplit(".", 1)[1].lower()
            allowed = {"jpg", "jpeg", "png", "gif", "webp", "svg"}
            if ext not in allowed:
                flash("Invalid avatar type. Allowed: JPG, PNG, GIF, WEBP, SVG.", "danger")
                return redirect(url_for("profile"))

            # Remove previous avatar file if exists
            if getattr(current_user, "avatar_path", None):
                old_path = os.path.join(AVATAR_DIR, current_user.avatar_path)
                try:
                    if os.path.exists(old_path):
                        os.remove(old_path)
                except OSError:
                    pass

            # --- If SVG, save directly without processing ---
            if ext == "svg":
                filename = f"user_{current_user.id}.svg"
                save_path = os.path.join(AVATAR_DIR, filename)
                with open(save_path, "wb") as f:
                    f.write(data)

            else:
                # --- Raster image: resize + circle crop ---
                try:
                    img = Image.open(io.BytesIO(data))
                except Exception:
                    flash("Could not process image file.", "danger")
                    return redirect(url_for("profile"))

                img = img.convert("RGBA")
                img = ImageOps.fit(img, (256, 256), Image.LANCZOS)

                # Create circle mask
                mask = Image.new("L", (256, 256), 0)
                draw = ImageDraw.Draw(mask)
                draw.ellipse((0, 0, 256, 256), fill=255)
                img.putalpha(mask)

                # Save final PNG regardless of original format
                filename = f"user_{current_user.id}.png"
                save_path = os.path.join(AVATAR_DIR, filename)
                img.save(save_path, format="PNG")


            # Save to DB
            with _users_conn() as conn:
                conn.execute(
                    "UPDATE users SET avatar_path = ? WHERE id = ?",
                    (filename, current_user.id)
                )
                conn.commit()

            current_user.avatar_path = filename
            flash("Profile picture updated.", "success")

        flash("Profile saved.", "success")
        return redirect(url_for("profile"))

    return render_template("profile.html")


# ---------------------------------------------------------------------
# Safe startup
# ---------------------------------------------------------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        with db.engine.connect() as conn:
            cols = [r[1] for r in conn.execute(text("PRAGMA table_info(letters)"))]
            if 'letter_type' not in cols:
                conn.execute(text("ALTER TABLE letters ADD COLUMN letter_type VARCHAR(20) DEFAULT 'Sending'"))
            if 'is_completed' not in cols:
                conn.execute(text("ALTER TABLE letters ADD COLUMN is_completed BOOLEAN DEFAULT 0"))
            if 'status' not in cols:
                conn.execute(text("ALTER TABLE letters ADD COLUMN status VARCHAR(20) DEFAULT 'Active'"))
            if 'attachment_path' not in cols:
                conn.execute(text("ALTER TABLE letters ADD COLUMN attachment_path VARCHAR(255)"))
            conn.commit()
    app.run(host='0.0.0.0', port=5000)