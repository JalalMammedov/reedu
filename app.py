import os
from datetime import datetime

from flask import Flask, abort, flash, redirect, render_template, request, send_from_directory, url_for
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "reedu-dev-secret")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(BASE_DIR, 'app.db')}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = os.path.join(BASE_DIR, "uploads")
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "mp4"}


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    birth_date = db.Column(db.Date, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    teacher_profile = db.relationship("TeacherProfile", backref="user", uselist=False)
    student_profile = db.relationship("StudentProfile", backref="user", uselist=False)


class TeacherProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    subject = db.Column(db.String(120), nullable=False)
    bio = db.Column(db.Text, nullable=False)
    rate = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default="pending")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class StudentProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    grade = db.Column(db.String(40), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Subscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    status = db.Column(db.String(20), default="active")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    student = db.relationship("User", foreign_keys=[student_id])
    teacher = db.relationship("User", foreign_keys=[teacher_id])


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    sender = db.relationship("User", foreign_keys=[sender_id])
    receiver = db.relationship("User", foreign_keys=[receiver_id])


class Material(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=True)
    file_path = db.Column(db.String(255), nullable=False)
    kind = db.Column(db.String(40), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    teacher = db.relationship("User", foreign_keys=[teacher_id])


class Schedule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default="planned")

    teacher = db.relationship("User", foreign_keys=[teacher_id])
    student = db.relationship("User", foreign_keys=[student_id])


class LiveSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    title = db.Column(db.String(120), nullable=False)
    scheduled_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), default="scheduled")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    teacher = db.relationship("User", foreign_keys=[teacher_id])


class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    student = db.relationship("User", foreign_keys=[student_id])
    teacher = db.relationship("User", foreign_keys=[teacher_id])

    __table_args__ = (db.UniqueConstraint("student_id", "teacher_id", name="uq_rating_pair"),)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def get_rating_map(teacher_ids):
    if not teacher_ids:
        return {}
    rows = (
        db.session.query(
            Rating.teacher_id,
            func.avg(Rating.score).label("avg_score"),
            func.count(Rating.id).label("count"),
        )
        .filter(Rating.teacher_id.in_(teacher_ids))
        .group_by(Rating.teacher_id)
        .all()
    )
    return {
        row.teacher_id: {"avg": float(row.avg_score), "count": int(row.count)}
        for row in rows
    }


def ensure_admin():
    admin_email = os.environ.get("ADMIN_EMAIL", "maga@reedu.local")
    admin_password = os.environ.get("ADMIN_PASSWORD", "maga123")
    existing = User.query.filter_by(email=admin_email).first()
    if existing:
        return
    admin = User(
        role="admin",
        email=admin_email,
        password_hash=generate_password_hash(admin_password),
        first_name="Admin",
        last_name="User",
        birth_date=datetime(1990, 1, 1).date(),
        is_active=True,
    )
    db.session.add(admin)
    db.session.commit()


def init_storage():
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)


def init_db():
    db.create_all()
    ensure_admin()
    init_storage()


@app.route("/")
def index():
    teachers = (
        TeacherProfile.query.filter_by(status="approved")
        .join(User, TeacherProfile.user_id == User.id)
        .all()
    )
    rating_map = get_rating_map([teacher.user_id for teacher in teachers])
    return render_template("index.html", teachers=teachers, rating_map=rating_map)


@app.route("/register")
def register_choice():
    return render_template("register_choice.html")


@app.route("/pricing")
def pricing():
    return render_template("pricing.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/teachers")
def teachers():
    subject = request.args.get("subject", "").strip()
    query = TeacherProfile.query.filter_by(status="approved").join(User)
    if subject:
        query = query.filter(TeacherProfile.subject.ilike(f"%{subject}%"))
    teachers_list = query.all()
    rating_map = get_rating_map([teacher.user_id for teacher in teachers_list])
    return render_template(
        "teachers.html",
        teachers=teachers_list,
        subject=subject,
        rating_map=rating_map,
    )


@app.route("/register/<role>", methods=["GET", "POST"])
def register(role):
    if role not in {"teacher", "student"}:
        abort(404)
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        birth_date_raw = request.form.get("birth_date", "")
        if User.query.filter_by(email=email).first():
            flash("Bu email artıq qeydiyyatdan keçib.")
            return redirect(request.url)
        try:
            birth_date = datetime.strptime(birth_date_raw, "%Y-%m-%d").date()
        except ValueError:
            flash("Doğum tarixini düzgün formatda daxil edin.")
            return redirect(request.url)
        user = User(
            role=role,
            email=email,
            password_hash=generate_password_hash(password),
            first_name=first_name,
            last_name=last_name,
            birth_date=birth_date,
            is_active=True,
        )
        db.session.add(user)
        db.session.flush()
        if role == "teacher":
            try:
                rate = float(request.form.get("rate", "0") or 0)
            except ValueError:
                flash("Tədris məbləği düzgün deyil.")
                return redirect(request.url)
            profile = TeacherProfile(
                user_id=user.id,
                subject=request.form.get("subject", "").strip(),
                bio=request.form.get("bio", "").strip(),
                rate=rate,
                status="pending",
            )
            db.session.add(profile)
        else:
            profile = StudentProfile(
                user_id=user.id,
                grade=request.form.get("grade", "").strip(),
            )
            db.session.add(profile)
        db.session.commit()
        login_user(user)
        return redirect(url_for("dashboard"))
    return render_template("register.html", role=role)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password_hash, password):
            flash("Email və ya şifrə yalnışdır.")
            return redirect(url_for("login"))
        login_user(user)
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.role == "teacher":
        return redirect(url_for("teacher_dashboard"))
    if current_user.role == "student":
        return redirect(url_for("student_dashboard"))
    if current_user.role == "admin":
        return redirect(url_for("admin_dashboard"))
    return redirect(url_for("index"))


@app.route("/dashboard/teacher")
@login_required
def teacher_dashboard():
    if current_user.role != "teacher":
        abort(403)
    profile = current_user.teacher_profile
    subscriptions = Subscription.query.filter_by(teacher_id=current_user.id).all()
    messages = (
        Message.query.filter(
            (Message.sender_id == current_user.id) | (Message.receiver_id == current_user.id)
        )
        .order_by(Message.created_at.desc())
        .limit(20)
        .all()
    )
    materials = Material.query.filter_by(teacher_id=current_user.id).order_by(
        Material.created_at.desc()
    )
    schedules = Schedule.query.filter_by(teacher_id=current_user.id).order_by(
        Schedule.start_time.desc()
    )
    live_sessions = LiveSession.query.filter_by(teacher_id=current_user.id).order_by(
        LiveSession.created_at.desc()
    )
    return render_template(
        "teacher_dashboard.html",
        profile=profile,
        subscriptions=subscriptions,
        messages=messages,
        materials=materials,
        schedules=schedules,
        live_sessions=live_sessions,
    )


@app.route("/dashboard/student")
@login_required
def student_dashboard():
    if current_user.role != "student":
        abort(403)
    subject = request.args.get("subject", "").strip()
    teachers_query = TeacherProfile.query.filter_by(status="approved").join(User)
    if subject:
        teachers_query = teachers_query.filter(TeacherProfile.subject.ilike(f"%{subject}%"))
    teachers_list = teachers_query.all()
    subscriptions = Subscription.query.filter_by(student_id=current_user.id).all()
    subscribed_teacher_ids = {sub.teacher_id for sub in subscriptions}
    teacher_ids = {teacher.user_id for teacher in teachers_list} | subscribed_teacher_ids
    rating_map = get_rating_map(list(teacher_ids))
    student_ratings = {
        rating.teacher_id: rating.score
        for rating in Rating.query.filter_by(student_id=current_user.id).all()
    }
    materials = (
        Material.query.filter(Material.teacher_id.in_(subscribed_teacher_ids))
        .order_by(Material.created_at.desc())
        .all()
        if subscribed_teacher_ids
        else []
    )
    messages = (
        Message.query.filter(
            (Message.sender_id == current_user.id) | (Message.receiver_id == current_user.id)
        )
        .order_by(Message.created_at.desc())
        .limit(20)
        .all()
    )
    schedules = Schedule.query.filter_by(student_id=current_user.id).order_by(
        Schedule.start_time.desc()
    )
    return render_template(
        "student_dashboard.html",
        subject=subject,
        teachers=teachers_list,
        subscriptions=subscriptions,
        rating_map=rating_map,
        student_ratings=student_ratings,
        materials=materials,
        messages=messages,
        schedules=schedules,
    )


@app.route("/admin")
@login_required
def admin_dashboard():
    if current_user.role != "admin":
        abort(403)
    pending_teachers = TeacherProfile.query.filter_by(status="pending").all()
    teachers = TeacherProfile.query.all()
    students = StudentProfile.query.all()
    subscriptions = Subscription.query.order_by(Subscription.created_at.desc()).all()
    schedules = Schedule.query.order_by(Schedule.start_time.desc()).all()
    live_sessions = LiveSession.query.order_by(LiveSession.created_at.desc()).all()
    return render_template(
        "admin_dashboard.html",
        pending_teachers=pending_teachers,
        teachers=teachers,
        students=students,
        subscriptions=subscriptions,
        schedules=schedules,
        live_sessions=live_sessions,
    )


@app.post("/admin/teachers/<int:teacher_id>/approve")
@login_required
def approve_teacher(teacher_id):
    if current_user.role != "admin":
        abort(403)
    profile = TeacherProfile.query.get_or_404(teacher_id)
    profile.status = "approved"
    db.session.commit()
    flash("Müəllim təsdiqləndi.")
    return redirect(url_for("admin_dashboard"))


@app.post("/admin/teachers/<int:teacher_id>/reject")
@login_required
def reject_teacher(teacher_id):
    if current_user.role != "admin":
        abort(403)
    profile = TeacherProfile.query.get_or_404(teacher_id)
    profile.status = "rejected"
    db.session.commit()
    flash("Müəllim ləğv edildi.")
    return redirect(url_for("admin_dashboard"))


@app.post("/subscribe/<int:teacher_user_id>")
@login_required
def subscribe_teacher(teacher_user_id):
    if current_user.role != "student":
        abort(403)
    teacher_user = User.query.get_or_404(teacher_user_id)
    if teacher_user.role != "teacher":
        abort(400)
    if not teacher_user.teacher_profile or teacher_user.teacher_profile.status != "approved":
        flash("Bu müəllim hələ təsdiqlənməyib.")
        return redirect(url_for("student_dashboard"))
    existing = Subscription.query.filter_by(
        student_id=current_user.id, teacher_id=teacher_user_id
    ).first()
    if existing:
        flash("Bu müəllimə artıq abunə olmusunuz.")
        return redirect(url_for("student_dashboard"))
    db.session.add(Subscription(student_id=current_user.id, teacher_id=teacher_user_id))
    db.session.commit()
    flash("Abunəlik aktivləşdirildi (demo ödəniş).")
    return redirect(url_for("student_dashboard"))


@app.post("/ratings/submit")
@login_required
def submit_rating():
    if current_user.role != "student":
        abort(403)
    teacher_id = int(request.form.get("teacher_id", "0"))
    score_raw = request.form.get("score", "0")
    try:
        score = int(score_raw)
    except ValueError:
        score = 0
    if score not in {1, 2, 3, 4, 5}:
        flash("Reytinq 1-5 arası olmalıdır.")
        return redirect(url_for("student_dashboard"))
    subscribed = Subscription.query.filter_by(
        student_id=current_user.id, teacher_id=teacher_id
    ).first()
    if not subscribed:
        abort(403)
    existing = Rating.query.filter_by(
        student_id=current_user.id, teacher_id=teacher_id
    ).first()
    if existing:
        existing.score = score
    else:
        db.session.add(Rating(student_id=current_user.id, teacher_id=teacher_id, score=score))
    db.session.commit()
    flash("Reytinq saxlanıldı.")
    return redirect(url_for("student_dashboard"))


@app.post("/messages/send")
@login_required
def send_message():
    receiver_id = int(request.form.get("receiver_id", "0"))
    body = request.form.get("body", "").strip()
    if not body:
        flash("Mesaj boş ola bilməz.")
        return redirect(url_for("dashboard"))
    receiver = User.query.get_or_404(receiver_id)
    if current_user.role == "teacher":
        allowed = Subscription.query.filter_by(
            teacher_id=current_user.id, student_id=receiver.id
        ).first()
    elif current_user.role == "student":
        allowed = Subscription.query.filter_by(
            student_id=current_user.id, teacher_id=receiver.id
        ).first()
    else:
        allowed = None
    if not allowed and current_user.role != "admin":
        abort(403)
    db.session.add(Message(sender_id=current_user.id, receiver_id=receiver.id, body=body))
    db.session.commit()
    flash("Mesaj göndərildi.")
    return redirect(url_for("dashboard"))


@app.post("/materials/upload")
@login_required
def upload_material():
    if current_user.role != "teacher":
        abort(403)
    profile = current_user.teacher_profile
    if not profile or profile.status != "approved":
        flash("Material əlavə etmək üçün müəllim təsdiqi lazımdır.")
        return redirect(url_for("teacher_dashboard"))
    file = request.files.get("file")
    if not file or file.filename == "":
        flash("Fayl seçin.")
        return redirect(url_for("teacher_dashboard"))
    if not allowed_file(file.filename):
        flash("Fayl tipi dəstəklənmir.")
        return redirect(url_for("teacher_dashboard"))
    filename = secure_filename(file.filename)
    teacher_folder = os.path.join(app.config["UPLOAD_FOLDER"], f"teacher_{current_user.id}")
    os.makedirs(teacher_folder, exist_ok=True)
    file_path = os.path.join(teacher_folder, filename)
    file.save(file_path)
    extension = filename.rsplit(".", 1)[1].lower()
    kind = "video" if extension == "mp4" else "document"
    db.session.add(
        Material(
            teacher_id=current_user.id,
            title=request.form.get("title", "").strip(),
            description=request.form.get("description", "").strip(),
            file_path=file_path,
            kind=kind,
        )
    )
    db.session.commit()
    flash("Material əlavə edildi.")
    return redirect(url_for("teacher_dashboard"))


@app.route("/materials/<int:material_id>/download")
@login_required
def download_material(material_id):
    material = Material.query.get_or_404(material_id)
    if current_user.role == "student":
        subscribed = Subscription.query.filter_by(
            student_id=current_user.id, teacher_id=material.teacher_id
        ).first()
        if not subscribed:
            abort(403)
    elif current_user.role == "teacher" and material.teacher_id != current_user.id:
        abort(403)
    directory = os.path.dirname(material.file_path)
    filename = os.path.basename(material.file_path)
    return send_from_directory(directory, filename, as_attachment=True)


@app.post("/schedules/create")
@login_required
def create_schedule():
    if current_user.role != "teacher":
        abort(403)
    student_id = int(request.form.get("student_id", "0"))
    start_raw = request.form.get("start_time", "")
    end_raw = request.form.get("end_time", "")
    try:
        start_time = datetime.strptime(start_raw, "%Y-%m-%dT%H:%M")
        end_time = datetime.strptime(end_raw, "%Y-%m-%dT%H:%M")
    except ValueError:
        flash("Dərs vaxtını düzgün daxil edin.")
        return redirect(url_for("teacher_dashboard"))
    allowed = Subscription.query.filter_by(
        teacher_id=current_user.id, student_id=student_id
    ).first()
    if not allowed:
        abort(403)
    db.session.add(
        Schedule(
            teacher_id=current_user.id,
            student_id=student_id,
            start_time=start_time,
            end_time=end_time,
        )
    )
    db.session.commit()
    flash("Dərs cədvəli yaradıldı.")
    return redirect(url_for("teacher_dashboard"))


@app.post("/live-sessions/create")
@login_required
def create_live_session():
    if current_user.role != "teacher":
        abort(403)
    title = request.form.get("title", "").strip()
    scheduled_raw = request.form.get("scheduled_at", "")
    scheduled_at = None
    if scheduled_raw:
        try:
            scheduled_at = datetime.strptime(scheduled_raw, "%Y-%m-%dT%H:%M")
        except ValueError:
            flash("Canlı dərs vaxtını düzgün daxil edin.")
            return redirect(url_for("teacher_dashboard"))
    db.session.add(LiveSession(teacher_id=current_user.id, title=title, scheduled_at=scheduled_at))
    db.session.commit()
    flash("Canlı dərs yaradıldı.")
    return redirect(url_for("teacher_dashboard"))


@app.route("/uploads/<path:filename>")
def uploads(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


with app.app_context():
    init_db()


if __name__ == "__main__":
    app.run(debug=True)
