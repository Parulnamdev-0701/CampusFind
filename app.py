
import os
import re
import sqlite3
import uuid
from difflib import SequenceMatcher

from flask import Flask, request, jsonify, session, send_from_directory
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app, supports_credentials=True)

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "local-development-key-change-before-deployment"
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "campusfind.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")

ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}
MAX_IMAGE_SIZE = 5 * 1024 * 1024

app.config["MAX_CONTENT_LENGTH"] = MAX_IMAGE_SIZE
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("COOKIE_SECURE", "false").lower() == "true"
)

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ---------------- FILE UPLOAD ----------------

def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)


# ---------------- DATABASE ----------------

def get_db_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def create_table():
    connection = get_db_connection()

    try:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_type TEXT NOT NULL,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                description TEXT NOT NULL,
                location TEXT NOT NULL,
                incident_date TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        columns = connection.execute(
            "PRAGMA table_info(reports)"
        ).fetchall()

        column_names = [column["name"] for column in columns]

        if "image_filename" not in column_names:
            connection.execute(
                "ALTER TABLE reports ADD COLUMN image_filename TEXT"
            )

        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'student',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS claims (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id INTEGER NOT NULL,
                claimant_id INTEGER NOT NULL,
                claim_message TEXT NOT NULL,
                verification_status TEXT NOT NULL DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY (report_id)
                    REFERENCES reports(id)
                    ON DELETE CASCADE,

                FOREIGN KEY (claimant_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            )
        """)

        connection.commit()

    finally:
        connection.close()


# ---------------- CREATE / UPDATE ADMIN ACCOUNT ----------------

def ensure_admin_account():
    admin_email = os.environ.get("ADMIN_EMAIL", "").strip().lower()
    admin_password = os.environ.get("ADMIN_PASSWORD", "")
    admin_name = os.environ.get("ADMIN_NAME", "CampusFind Admin").strip()

    if not admin_email or not admin_password:
        app.logger.warning(
            "ADMIN_EMAIL or ADMIN_PASSWORD is not configured."
        )
        return

    if len(admin_password) < 8:
        raise ValueError("ADMIN_PASSWORD must be at least 8 characters.")

    connection = get_db_connection()

    try:
        existing = connection.execute("""
            SELECT id
            FROM users
            WHERE email = ?
        """, (admin_email,)).fetchone()

        password_hash = generate_password_hash(admin_password)

        if existing:
            connection.execute("""
                UPDATE users
                SET role = 'admin',
                    password_hash = ?
                WHERE email = ?
            """, (password_hash, admin_email))

        else:
            connection.execute("""
                INSERT INTO users (name, email, password_hash, role)
                VALUES (?, ?, ?, 'admin')
            """, (
                admin_name or "CampusFind Admin",
                admin_email,
                password_hash
            ))

        connection.commit()
        app.logger.info("CampusFind admin account is ready.")

    finally:
        connection.close()


# ---------------- HOME AND TEST ----------------

@app.route("/")
def home():
    return send_from_directory(app.root_path, "index.html")

@app.route("/login.html")
def login_page():
    return send_from_directory(app.root_path, "login.html")


@app.route("/signup.html")
def signup_page():
    return send_from_directory(app.root_path, "signup.html")


@app.route("/report.html")
def report_page():
    return send_from_directory(app.root_path, "report.html")


@app.route("/admin.html")
def admin_page():
    return send_from_directory(app.root_path, "admin.html")


@app.route("/my-claims.html")
def my_claims_page():
    return send_from_directory(app.root_path, "my-claims.html")


@app.route("/style.css")
def stylesheet():
    return send_from_directory(app.root_path, "style.css")


@app.route("/api/test")
def test():
    return jsonify({
        "message": "CampusFind API is working successfully!"
    })


# ---------------- SIGNUP ----------------

@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Please provide signup details"}), 400

    name = data.get("name")
    email = data.get("email")
    password = data.get("password")

    if not all(isinstance(v, str) for v in (name, email, password)):
        return jsonify({
            "error": "Name, email and password are required"
        }), 400

    name = name.strip()
    email = email.strip().lower()

    if not name or not email or not password:
        return jsonify({
            "error": "Name, email and password are required"
        }), 400

    if "@" not in email or "." not in email.split("@")[-1]:
        return jsonify({"error": "Please enter a valid email"}), 400

    if len(password) < 8:
        return jsonify({
            "error": "Password must be at least 8 characters"
        }), 400

    connection = get_db_connection()

    try:
        connection.execute("""
            INSERT INTO users (name, email, password_hash, role)
            VALUES (?, ?, ?, 'student')
        """, (name, email, generate_password_hash(password)))

        connection.commit()

        return jsonify({
            "message": "Account created successfully!",
            "role": "student"
        }), 201

    except sqlite3.IntegrityError:
        return jsonify({
            "error": "This email is already registered"
        }), 409

    finally:
        connection.close()


# ---------------- LOGIN ----------------

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Please provide login details"}), 400

    email = data.get("email")
    password = data.get("password")

    if not isinstance(email, str) or not isinstance(password, str):
        return jsonify({
            "error": "Email and password are required"
        }), 400

    email = email.strip().lower()

    if not email or not password:
        return jsonify({
            "error": "Email and password are required"
        }), 400

    connection = get_db_connection()

    try:
        user = connection.execute("""
            SELECT id, name, email, password_hash, role
            FROM users
            WHERE email = ?
        """, (email,)).fetchone()

    finally:
        connection.close()

    if user is None or not check_password_hash(
        user["password_hash"], password
    ):
        return jsonify({
            "error": "Invalid email or password"
        }), 401

    session.clear()
    session["user_id"] = user["id"]
    session["name"] = user["name"]
    session["role"] = user["role"]

    return jsonify({
        "message": "Login successful!",
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"]
        }
    }), 200


# ---------------- CURRENT USER ----------------

@app.route("/api/me", methods=["GET"])
def current_user():
    if "user_id" not in session:
        return jsonify({"error": "Please log in first"}), 401

    return jsonify({
        "id": session["user_id"],
        "name": session["name"],
        "role": session["role"]
    }), 200


# ---------------- LOGOUT ----------------

@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()

    return jsonify({
        "message": "Logged out successfully!"
    }), 200


# ---------------- CREATE REPORT ----------------

@app.route("/api/reports", methods=["POST"])
def create_report():
    if "user_id" not in session:
        return jsonify({"error": "Please log in first"}), 401

    if request.is_json:
        data = request.get_json(silent=True)
    else:
        data = request.form.to_dict()

    if not isinstance(data, dict):
        return jsonify({"error": "Valid report data is required"}), 400

    required_fields = [
        "report_type", "title", "category",
        "description", "location", "incident_date"
    ]

    for field in required_fields:
        value = data.get(field)

        if not isinstance(value, str) or not value.strip():
            return jsonify({"error": f"{field} is required"}), 400

    report_type = data["report_type"].strip().upper()

    if report_type not in ("LOST", "FOUND"):
        return jsonify({"error": "Type must be LOST or FOUND"}), 400

    image_filename = None
    photo = request.files.get("photo")

    if photo and photo.filename:
        if not allowed_file(photo.filename):
            return jsonify({
                "error": "Only JPG, JPEG, PNG and WebP images are allowed"
            }), 400

        photo.seek(0, os.SEEK_END)
        photo_size = photo.tell()
        photo.seek(0)

        if photo_size > MAX_IMAGE_SIZE:
            return jsonify({
                "error": "Photo must be no larger than 5 MB"
            }), 400

        extension = photo.filename.rsplit(".", 1)[1].lower()
        image_filename = f"{uuid.uuid4().hex}.{extension}"

    connection = None
    saved_path = None

    try:
        if photo and photo.filename and image_filename:
            saved_path = os.path.join(UPLOAD_FOLDER, image_filename)
            photo.save(saved_path)

        connection = get_db_connection()

        cursor = connection.execute("""
            INSERT INTO reports (
                report_type, title, category, description,
                location, incident_date, image_filename
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            report_type,
            data["title"].strip(),
            data["category"].strip(),
            data["description"].strip(),
            data["location"].strip(),
            data["incident_date"].strip(),
            image_filename
        ))

        connection.commit()

        return jsonify({
            "message": "Report saved successfully!",
            "report_id": cursor.lastrowid,
            "image_url": (
                f"/uploads/{image_filename}" if image_filename else None
            )
        }), 201

    except Exception:
        if connection is not None:
            connection.rollback()

        if saved_path and os.path.exists(saved_path):
            os.remove(saved_path)

        app.logger.exception("Failed to save report")

        return jsonify({
            "error": "Unable to save the report. Please try again."
        }), 500

    finally:
        if connection is not None:
            connection.close()


# ---------------- DASHBOARD STATISTICS ----------------

@app.route("/api/stats", methods=["GET"])
def dashboard_stats():
    connection = get_db_connection()

    try:
        report_stats = connection.execute("""
            SELECT
                COUNT(*) AS total_reports,
                SUM(CASE WHEN UPPER(report_type) = 'LOST'
                    THEN 1 ELSE 0 END) AS lost_items,
                SUM(CASE WHEN UPPER(report_type) = 'FOUND'
                    THEN 1 ELSE 0 END) AS found_items
            FROM reports
        """).fetchone()

        claim_stats = connection.execute("""
            SELECT
                COUNT(*) AS total_claims,
                SUM(CASE WHEN verification_status = 'pending'
                    THEN 1 ELSE 0 END) AS pending_claims,
                SUM(CASE WHEN verification_status = 'approved'
                    THEN 1 ELSE 0 END) AS approved_claims
            FROM claims
        """).fetchone()

        return jsonify({
            "total_reports": report_stats["total_reports"] or 0,
            "lost_items": report_stats["lost_items"] or 0,
            "found_items": report_stats["found_items"] or 0,
            "total_claims": claim_stats["total_claims"] or 0,
            "pending_claims": claim_stats["pending_claims"] or 0,
            "approved_claims": claim_stats["approved_claims"] or 0
        }), 200

    finally:
        connection.close()


# ---------------- GET ALL REPORTS ----------------

@app.route("/api/reports", methods=["GET"])
def get_reports():
    connection = get_db_connection()

    try:
        rows = connection.execute("""
            SELECT id, report_type, title, category,
                   description, location, incident_date,
                   created_at, image_filename
            FROM reports
            ORDER BY id DESC
        """).fetchall()

        reports = []

        for row in rows:
            report = dict(row)
            filename = report.pop("image_filename", None)

            report["image_url"] = (
                f"/uploads/{filename}" if filename else None
            )

            reports.append(report)

        return jsonify(reports), 200

    finally:
        connection.close()


# ---------------- SMART MATCHING ----------------

SYNONYM_GROUPS = [
    {
        "headphone", "headphones", "earbud",
        "earbuds", "earphone", "earphones"
    },
    {
        "book", "books", "notebook",
        "notebooks", "textbook", "textbooks"
    },
    {
        "bottle", "bottles", "water bottle", "water bottles"
    }
]


def normalize_text(text):
    text = str(text or "").lower().strip()
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    return re.sub(r"\s+", " ", text)


def expand_synonyms(text):
    text = normalize_text(text)

    for group in SYNONYM_GROUPS:
        for phrase in sorted(group, key=len, reverse=True):
            text = re.sub(
                r"\b" + re.escape(phrase) + r"\b",
                " relateditem ",
                text
            )

    return re.sub(r"\s+", " ", text).strip()


def text_similarity(text1, text2):
    text1 = normalize_text(text1)
    text2 = normalize_text(text2)

    if not text1 or not text2:
        return 0.0

    if text1 == text2:
        return 1.0

    original_score = SequenceMatcher(None, text1, text2).ratio()

    expanded1 = expand_synonyms(text1)
    expanded2 = expand_synonyms(text2)

    synonym_score = SequenceMatcher(
        None, expanded1, expanded2
    ).ratio()

    words1 = set(expanded1.split())
    words2 = set(expanded2.split())

    union = words1 | words2

    word_score = (
        len(words1 & words2) / len(union) if union else 0.0
    )

    return max(original_score, synonym_score, word_score)


@app.route("/api/matches/<int:report_id>", methods=["GET"])
def find_matches(report_id):
    connection = get_db_connection()

    try:
        reports = connection.execute("""
            SELECT id, report_type, title, category,
                   description, location, incident_date
            FROM reports
        """).fetchall()

        current = next(
            (row for row in reports if row["id"] == report_id),
            None
        )

        if current is None:
            return jsonify({"error": "Report not found"}), 404

        current_type = current["report_type"].upper()

        if current_type not in ("LOST", "FOUND"):
            return jsonify({"error": "Invalid report type"}), 400

        opposite_type = "FOUND" if current_type == "LOST" else "LOST"

        ignored_words = {
            "is", "are", "was", "were", "the", "a", "an",
            "my", "found", "lost", "missing", "near",
            "in", "at", "on", "of", "and", "black", "blue"
        }

        def item_words(title):
            return set(normalize_text(title).split()) - ignored_words

        current_words = item_words(current["title"])
        matches = []

        for candidate in reports:
            if candidate["report_type"].upper() != opposite_type:
                continue

            if normalize_text(current["category"]) != normalize_text(
                candidate["category"]
            ):
                continue

            candidate_words = item_words(candidate["title"])

            if not current_words.intersection(candidate_words):
                continue

            title_score = text_similarity(
                current["title"], candidate["title"]
            )

            description_score = text_similarity(
                current["description"], candidate["description"]
            )

            location_score = text_similarity(
                current["location"], candidate["location"]
            )

            score = (
                title_score * 0.65
                + description_score * 0.20
                + location_score * 0.15
            )

            if score >= 0.50:
                matches.append({
                    "id": candidate["id"],
                    "report_type": candidate["report_type"],
                    "title": candidate["title"],
                    "category": candidate["category"],
                    "description": candidate["description"],
                    "location": candidate["location"],
                    "incident_date": candidate["incident_date"],
                    "match_percentage": round(score * 100, 1)
                })

        matches.sort(
            key=lambda item: item["match_percentage"],
            reverse=True
        )

        return jsonify({
            "report_id": report_id,
            "matches": matches
        }), 200

    finally:
        connection.close()


# ---------------- CLAIM ITEM ----------------

@app.route("/api/claims", methods=["POST"])
def create_claim():
    if "user_id" not in session:
        return jsonify({"error": "Please log in first"}), 401

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Please provide claim details"}), 400

    report_id = data.get("report_id")
    claim_message = data.get("claim_message")

    if (
        isinstance(report_id, bool)
        or not isinstance(report_id, int)
        or report_id <= 0
    ):
        return jsonify({"error": "A valid report_id is required"}), 400

    if not isinstance(claim_message, str) or not claim_message.strip():
        return jsonify({
            "error": "Please explain how you can verify ownership"
        }), 400

    if len(claim_message.strip()) > 1000:
        return jsonify({
            "error": "Claim message must be under 1000 characters"
        }), 400

    connection = get_db_connection()

    try:
        report = connection.execute("""
            SELECT id, title
            FROM reports
            WHERE id = ?
        """, (report_id,)).fetchone()

        if report is None:
            return jsonify({"error": "Item report not found"}), 404

        existing_claim = connection.execute("""
            SELECT id
            FROM claims
            WHERE report_id = ?
              AND claimant_id = ?
              AND verification_status = 'pending'
        """, (report_id, session["user_id"])).fetchone()

        if existing_claim:
            return jsonify({
                "error": "You already have a pending claim for this item"
            }), 409

        cursor = connection.execute("""
            INSERT INTO claims (
                report_id,
                claimant_id,
                claim_message,
                verification_status
            )
            VALUES (?, ?, ?, 'pending')
        """, (
            report_id,
            session["user_id"],
            claim_message.strip()
        ))

        connection.commit()

        return jsonify({
            "message": "Claim submitted successfully!",
            "claim_id": cursor.lastrowid,
            "report_id": report_id,
            "status": "pending"
        }), 201

    except sqlite3.Error:
        connection.rollback()
        app.logger.exception("Could not submit claim")

        return jsonify({
            "error": "Unable to submit claim"
        }), 500

    finally:
        connection.close()


# ---------------- VIEW MY CLAIMS ----------------

@app.route("/api/claims/my", methods=["GET"])
def get_my_claims():
    if "user_id" not in session:
        return jsonify({"error": "Please log in first"}), 401

    connection = get_db_connection()

    try:
        rows = connection.execute("""
            SELECT
                claims.id AS claim_id,
                claims.report_id,
                reports.title AS item_title,
                claims.claim_message,
                claims.verification_status,
                claims.created_at
            FROM claims
            JOIN reports ON reports.id = claims.report_id
            WHERE claims.claimant_id = ?
            ORDER BY claims.id DESC
        """, (session["user_id"],)).fetchall()

        return jsonify([dict(row) for row in rows]), 200

    finally:
        connection.close()


# ---------------- ADMIN VIEW ALL CLAIMS ----------------

@app.route("/api/admin/claims", methods=["GET"])
def get_all_claims():
    if "user_id" not in session:
        return jsonify({"error": "Please log in first"}), 401

    if session.get("role") != "admin":
        return jsonify({
            "error": "Admin access required"
        }), 403

    connection = get_db_connection()

    try:
        rows = connection.execute("""
            SELECT
                claims.id AS claim_id,
                claims.report_id,
                reports.title AS item_title,
                reports.category,
                reports.location,
                users.name AS claimant_name,
                users.email AS claimant_email,
                claims.claim_message,
                claims.verification_status,
                claims.created_at
            FROM claims
            JOIN reports ON reports.id = claims.report_id
            JOIN users ON users.id = claims.claimant_id
            ORDER BY
                CASE
                    WHEN claims.verification_status = 'pending'
                    THEN 0
                    ELSE 1
                END,
                claims.id DESC
        """).fetchall()

        return jsonify([dict(row) for row in rows]), 200

    finally:
        connection.close()


# ---------------- ADMIN REVIEW CLAIM ----------------

@app.route("/api/claims/<int:claim_id>/status", methods=["PATCH"])
def update_claim_status(claim_id):
    if "user_id" not in session:
        return jsonify({"error": "Please log in first"}), 401

    if session.get("role") != "admin":
        return jsonify({
            "error": "Only an admin can review claims"
        }), 403

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Please provide a status"}), 400

    status = data.get("status")

    if status not in ("approved", "rejected"):
        return jsonify({
            "error": "Status must be approved or rejected"
        }), 400

    connection = get_db_connection()

    try:
        cursor = connection.execute("""
            UPDATE claims
            SET verification_status = ?
            WHERE id = ?
              AND verification_status = 'pending'
        """, (status, claim_id))

        if cursor.rowcount == 0:
            connection.rollback()

            existing = connection.execute("""
                SELECT id, verification_status
                FROM claims
                WHERE id = ?
            """, (claim_id,)).fetchone()

            if existing is None:
                return jsonify({"error": "Claim not found"}), 404

            return jsonify({
                "error": "This claim has already been reviewed",
                "status": existing["verification_status"]
            }), 409

        connection.commit()

        return jsonify({
            "message": "Claim reviewed successfully",
            "claim_id": claim_id,
            "status": status
        }), 200

    except sqlite3.Error:
        connection.rollback()
        app.logger.exception("Could not update claim status")

        return jsonify({
            "error": "Unable to update claim status"
        }), 500

    finally:
        connection.close()


# ---------------- DATABASE INITIALIZATION ----------------

create_table()
ensure_admin_account()


# ---------------- RUN APPLICATION ----------------

if __name__ == "__main__":
    app.run(debug=True)
