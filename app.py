import os
import io
import ssl
import re
import secrets
import smtplib
import threading
import json
import time
from collections import defaultdict
from urllib import request as urllib_request, error as urllib_error
from datetime import datetime, timedelta
from email.message import EmailMessage
from pathlib import Path

from flask import (
    Flask, render_template, request, redirect, url_for,
    send_file, session, flash, jsonify, abort
)
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect, text
from sqlalchemy.ext.hybrid import hybrid_property
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import escape
import pandas as pd

# ==========================
# APP CONFIGURATION
# ==========================
app = Flask(__name__)

# Load local environment variables from .env if present
ENV_PATH = Path(app.root_path) / '.env'
if ENV_PATH.exists():
    with ENV_PATH.open('r', encoding='utf-8') as env_file:
        for line in env_file:
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, value = line.split('=', 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value

# Generate a strong secret key if not provided
configured_secret = os.environ.get('SECRET_KEY', '').strip()
if not configured_secret or configured_secret in ('change-me-please', 'changeme'):
    configured_secret = secrets.token_hex(32)
app.config['SECRET_KEY'] = configured_secret

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///student.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=60)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2 MB upload limit

UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Email settings
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', '')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '')
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() in ('true', '1', 'yes')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get(
    'MAIL_DEFAULT_SENDER',
    app.config['MAIL_USERNAME'] or 'no-reply@example.com'
)

db = SQLAlchemy(app)

# ==========================
# LOGIN RATE LIMITING
# ==========================
_login_attempts = defaultdict(list)
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 300  # 5 minutes


def is_rate_limited(identifier):
    """Check if login attempts exceed threshold within the window."""
    now = time.time()
    attempts = _login_attempts[identifier]
    # Prune old attempts
    _login_attempts[identifier] = [t for t in attempts if now - t < LOGIN_WINDOW_SECONDS]
    return len(_login_attempts[identifier]) >= MAX_LOGIN_ATTEMPTS


def record_login_attempt(identifier):
    """Record a failed login attempt."""
    _login_attempts[identifier].append(time.time())


# ==========================
# CSRF PROTECTION
# ==========================
def generate_csrf_token():
    """Generate and store a CSRF token in the session."""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']


@app.before_request
def csrf_protect():
    """Validate CSRF token on state-changing requests."""
    if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
        # Skip for API JSON endpoints
        if request.is_json:
            return
        token = session.get('_csrf_token', None)
        form_token = request.form.get('_csrf_token', None)
        if not token or token != form_token:
            abort(403)


@app.context_processor
def inject_csrf():
    return {'csrf_token': generate_csrf_token}


# ==========================
# SESSION MANAGEMENT
# ==========================
@app.before_request
def manage_session():
    """Make sessions permanent and enforce idle timeout."""
    session.permanent = True
    session.modified = True


# ==========================
# AUTH DECORATOR
# ==========================
def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if 'role' not in session:
                flash('Please log in to access that page.', 'warning')
                return redirect(url_for('home'))
            if role and session.get('role') != role:
                flash('Access denied.', 'danger')
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return wrapped
    return decorator


@app.context_processor
def inject_user():
    return {
        'user_role': session.get('role'),
        'student_id': session.get('student_id')
    }


# ==========================
# VALIDATION HELPERS
# ==========================
def validate_marks(value, field_name='Marks'):
    """Validate that marks are a float between 0 and 100."""
    try:
        v = float(value)
    except (TypeError, ValueError):
        raise ValueError(f'{field_name} must be a number.')
    if v < 0 or v > 100:
        raise ValueError(f'{field_name} must be between 0 and 100.')
    return v


def validate_attendance(value):
    """Validate attendance is a float between 0 and 100."""
    return validate_marks(value, 'Attendance')


def validate_email(email):
    """Basic email format validation."""
    if not email:
        return ''
    email = email.strip()
    if email and not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        raise ValueError(f'Invalid email address: {email}')
    return email


def validate_required(value, field_name):
    """Ensure a field is not empty."""
    if not value or not str(value).strip():
        raise ValueError(f'{field_name} is required.')
    return str(value).strip()


def allowed_image(filename):
    """Check if file extension is an allowed image type."""
    ext = os.path.splitext(filename)[1].lower()
    return ext in ('.jpg', '.jpeg', '.png', '.gif')


# ==========================
# UTILITY FUNCTIONS
# ==========================
def get_student_rank(student):
    students = Student.query.filter_by(is_active=True).order_by(Student.marks.desc()).all()
    for index, s in enumerate(students, start=1):
        if s.id == student.id:
            return index
    return None


def query_ai(messages):
    openai_key = os.environ.get('OPENAI_API_KEY') or os.environ.get('OEPAI_API_KEY')
    gemini_key = os.environ.get('GEMINI_API_KEY')

    # Support Gemini via direct HTTP request (Free and recommended)
    if gemini_key and gemini_key.strip().lower() not in {'your_real_gemini_key', 'changeme', 'change-me-please', ''}:
        return query_gemini(messages, gemini_key)

    # Fallback to OpenAI if configured
    if openai_key and openai_key.strip().lower() not in {'your_real_openai_key', 'changeme', 'change-me-please', ''}:
        return query_openai_api(messages, openai_key)

    return None, 'No valid AI API key is configured. Please set GEMINI_API_KEY (free) or OPENAI_API_KEY in the environment.'

def query_gemini(messages, api_key):
    # Convert OpenAI message format to Gemini format
    gemini_messages = []
    system_instruction = ""
    for msg in messages:
        if msg['role'] == 'system':
            system_instruction += msg['content'] + "\n"
        elif msg['role'] == 'user':
            gemini_messages.append({'role': 'user', 'parts': [{'text': msg['content']}]})
        elif msg['role'] == 'assistant':
            gemini_messages.append({'role': 'model', 'parts': [{'text': msg['content']}]})
            
    payload = {
        'contents': gemini_messages,
        'generationConfig': {
            'temperature': 0.7,
            'maxOutputTokens': 400
        }
    }
    
    if system_instruction:
        payload['systemInstruction'] = {
            'role': 'system',
            'parts': [{'text': system_instruction.strip()}]
        }

    url = f'https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}'
    req = urllib_request.Request(
        url,
        data=json.dumps(payload).encode('utf-8'),
        headers={'Content-Type': 'application/json'},
        method='POST'
    )

    try:
        with urllib_request.urlopen(req, timeout=30) as response:
            data = json.load(response)
            if 'candidates' in data and data['candidates']:
                return data['candidates'][0]['content']['parts'][0]['text'].strip(), None
            return None, 'Gemini returned an empty response.'
    except urllib_error.HTTPError as exc:
        try:
            error_data = json.load(exc)
            message = error_data.get('error', {}).get('message', str(exc))
        except Exception:
            message = str(exc)
        return None, f'Gemini API error: {message}'
    except Exception as exc:
        return None, f'Unable to contact Gemini: {exc}'

def query_openai_api(messages, api_key):
    payload = json.dumps({
        'model': 'gpt-3.5-turbo',
        'messages': messages,
        'temperature': 0.7,
        'max_tokens': 400,
        'top_p': 1,
        'frequency_penalty': 0,
        'presence_penalty': 0
    }).encode('utf-8')

    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {api_key}'
    }

    req = urllib_request.Request(
        'https://api.openai.com/v1/chat/completions',
        data=payload,
        headers=headers,
        method='POST'
    )

    try:
        with urllib_request.urlopen(req, timeout=30) as response:
            data = json.load(response)
            return data['choices'][0]['message']['content'].strip(), None
    except urllib_error.HTTPError as exc:
        try:
            error_data = json.load(exc)
            message = error_data.get('error', {}).get('message', str(exc))
        except Exception:
            message = str(exc)
        return None, f'OpenAI API error: {message}'
    except Exception as exc:
        return None, f'Unable to contact OpenAI: {exc}'


def generate_student_report_pdf(student):
    students = Student.query.filter_by(is_active=True).order_by(Student.marks.desc()).all()
    rank = get_student_rank(student)
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    # Header
    pdf.setTitle(f"{student.name} Report Card")
    title_y = height - inch * 0.6
    pdf.setFillColor(colors.HexColor('#2c3e50'))
    pdf.setFont('Helvetica-Bold', 16)
    pdf.drawCentredString(width / 2, title_y, 'Student Performance Report')

    # Sub header/info block with subtle background
    info_y = title_y - 18
    box_x = 40
    box_w = width - box_x * 2
    box_h = 120
    pdf.setFillColor(colors.HexColor('#ecf0f1'))
    pdf.roundRect(box_x, info_y - box_h + 12, box_w, box_h, 6, fill=1, stroke=0)
    pdf.setFillColor(colors.black)
    pdf.setFont('Helvetica-Bold', 10)
    left_col_x = box_x + 12
    right_col_x = box_x + box_w / 2 + 6
    row_start = info_y - 18

    pdf.drawString(left_col_x, row_start, f"Name: {student.name}")
    pdf.drawString(right_col_x, row_start, f"USN: {student.usn}")
    pdf.setFont('Helvetica', 9)
    pdf.drawString(left_col_x, row_start - 16, f"Department: {student.department}")
    pdf.drawString(right_col_x, row_start - 16, f"Attendance: {student.attendance:.2f}%")
    pdf.drawString(left_col_x, row_start - 32, f"Rank: {rank if rank else 'N/A'}")
    pdf.drawString(right_col_x, row_start - 32, f"Result: {student.result()}")
    pdf.drawString(left_col_x, row_start - 48, f"Remarks: {student.remarks()}")

    # Subject table
    table_y = info_y - box_h - 18
    pdf.setFont('Helvetica-Bold', 11)
    pdf.setFillColor(colors.HexColor('#34495e'))
    pdf.drawString(box_x + 6, table_y, 'Subject')
    pdf.drawString(box_x + 220, table_y, 'Marks')
    pdf.setStrokeColor(colors.HexColor('#bdc3c7'))
    pdf.setLineWidth(0.5)
    pdf.line(box_x + 6, table_y - 6, box_x + box_w - 6, table_y - 6)

    pdf.setFont('Helvetica', 10)
    subjects = [
        ('Python', student.python),
        ('DBMS', student.dbms),
        ('DSA', student.dsa),
        ('Maths', student.maths),
        ('FCN', student.fcn),
    ]
    y = table_y - 22
    for name, mark in subjects:
        pdf.setFillColor(colors.black)
        pdf.drawString(box_x + 6, y, name)
        pdf.drawString(box_x + 220, y, f"{mark:.2f}")
        y -= 18

    # Summary block
    summary_y = y - 8
    pdf.setFont('Helvetica-Bold', 11)
    pdf.drawString(box_x + 6, summary_y, 'Summary')
    pdf.setFont('Helvetica', 9)
    pdf.drawString(box_x + 6, summary_y - 18, f"Average Marks: {student.average_marks():.2f}")
    pdf.drawString(box_x + 6, summary_y - 34, f"Email: {student.email or 'Not provided'}")
    pdf.drawString(box_x + 6, summary_y - 50, f"Parent Email: {student.parent_email or 'Not provided'}")

    pdf.setFont('Helvetica-Oblique', 8)
    pdf.setFillColor(colors.grey)
    pdf.drawString(box_x + 6, 40, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    pdf.showPage()
    pdf.save()
    buffer.seek(0)
    return buffer.getvalue()


def send_email_message(subject, body, recipients, attachment_bytes=None, attachment_name=None):
    if not app.config['MAIL_SERVER'] or not app.config['MAIL_USERNAME'] or not app.config['MAIL_PASSWORD']:
        raise RuntimeError('Email settings are not configured. Set MAIL_SERVER, MAIL_USERNAME, and MAIL_PASSWORD.')

    message = EmailMessage()
    message['Subject'] = subject
    message['From'] = app.config['MAIL_DEFAULT_SENDER']
    message['To'] = ', '.join(recipients)
    message.set_content(body)

    if attachment_bytes and attachment_name:
        message.add_attachment(
            attachment_bytes,
            maintype='application',
            subtype='pdf',
            filename=attachment_name
        )

    context = ssl.create_default_context()
    with smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT']) as server:
        if app.config['MAIL_USE_TLS']:
            server.starttls(context=context)
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        server.send_message(message)


def dispatch_monthly_report_emails():
    students = Student.query.filter_by(is_active=True).order_by(Student.marks.desc()).all()
    sent_count = 0
    errors = []

    for student in students:
        recipients = [email for email in [student.email, student.parent_email] if email]
        if not recipients:
            errors.append(f"Skipping {student.name}: no email address provided.")
            continue

        pdf_data = generate_student_report_pdf(student)
        subject = f"Monthly Performance Report for {student.name}"
        body = (
            f"Hello {student.name},\n\n"
            f"Please find attached your monthly performance report.\n\n"
            f"Rank: {get_student_rank(student)}\n"
            f"Average Marks: {student.average_marks():.2f}\n"
            f"Attendance: {student.attendance:.2f}%\n"
            f"Remarks: {student.remarks()}\n\n"
            "Regards,\n"
            "Academic Team"
        )

        try:
            send_email_message(subject, body, recipients, pdf_data, f"{student.name}_report.pdf")
            sent_count += 1
        except Exception as exc:
            errors.append(f"{student.name}: {exc}")

    return sent_count, errors


def schedule_monthly_reports():
    now = datetime.now()
    next_month = now.month % 12 + 1
    next_year = now.year + (1 if now.month == 12 else 0)
    next_run = datetime(next_year, next_month, 1, 9, 0, 0)
    delay = (next_run - now).total_seconds()

    def run_and_reschedule():
        with app.app_context():
            try:
                dispatch_monthly_report_emails()
            except Exception:
                pass
        schedule_monthly_reports()

    timer = threading.Timer(delay, run_and_reschedule)
    timer.daemon = True
    timer.start()


# ==========================
# MODELS
# ==========================
class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    usn = db.Column(db.String(20), unique=True, nullable=False)
    department = db.Column(db.String(50))
    middle_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    address = db.Column(db.String(255))
    dob = db.Column(db.String(20))
    parent_name = db.Column(db.String(150))
    parent_contact = db.Column(db.String(30))
    blood_group = db.Column(db.String(10))
    phone_number = db.Column(db.String(30))
    linkedin = db.Column(db.String(255))
    image_filename = db.Column(db.String(255))
    attendance = db.Column(db.Float, default=0.0)

    python = db.Column(db.Float, default=0.0)
    dbms = db.Column(db.Float, default=0.0)
    dsa = db.Column(db.Float, default=0.0)
    maths = db.Column(db.Float, default=0.0)
    fcn = db.Column(db.Float, default=0.0)
    email = db.Column(db.String(120))
    parent_email = db.Column(db.String(120))
    password_hash = db.Column(db.String(256))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

    def average_marks(self):
        return (
            self.python +
            self.dbms +
            self.dsa +
            self.maths +
            self.fcn
        ) / 5

    @hybrid_property
    def marks(self):
        return self.average_marks()

    @marks.expression
    def marks(cls):
        return (
            cls.python +
            cls.dbms +
            cls.dsa +
            cls.maths +
            cls.fcn
        ) / 5

    def result(self):
        avg = self.average_marks()
        if avg >= 85:
            return "Distinction"
        elif avg >= 60:
            return "First Class"
        elif avg >= 40:
            return "Pass"
        else:
            return "Fail"

    @property
    def full_name(self):
        parts = [self.name]
        if self.middle_name:
            parts.append(self.middle_name)
        if self.last_name:
            parts.append(self.last_name)
        return ' '.join(part for part in parts if part).strip()

    def remarks(self):
        if self.attendance < 75:
            return "Attendance is below expectations. Please prioritize class participation and follow up with instructors."
        if self.marks >= 85:
            return "Excellent performance. Keep maintaining this strong momentum."
        if self.marks >= 60:
            return "Good results. There is room for further improvement in some subjects."
        if self.marks >= 40:
            return "Passing, but further effort is needed for a more confident outcome."
        return "Needs improvement. Focus on both study habits and attendance to improve performance."


class Teacher(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    designation = db.Column(db.String(100))
    qualification = db.Column(db.String(150))
    contact_number = db.Column(db.String(30))
    email = db.Column(db.String(120), unique=True, nullable=False)
    department = db.Column(db.String(100))
    subjects_handled = db.Column(db.String(255))
    whatsapp_number = db.Column(db.String(30))
    contacting_times = db.Column(db.String(100))
    staff_room_no = db.Column(db.String(50))
    image_filename = db.Column(db.String(255))
    password_hash = db.Column(db.String(256))
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)


class QuizAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    subject = db.Column(db.String(50), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    total_questions = db.Column(db.Integer, nullable=False)
    date_attempted = db.Column(db.DateTime, default=datetime.now)


class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_by = db.Column(db.String(100))
    is_pinned = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)


class AttendanceLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(10), nullable=False, default='Present')  # Present, Absent, Late
    marked_by = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.now)

    student = db.relationship('Student', backref='attendance_logs')


# ==========================
# DB MIGRATION
# ==========================
def ensure_columns(table_name, model_class):
    """Generically add missing columns to an existing table."""
    inspector = inspect(db.engine)
    if table_name not in inspector.get_table_names():
        return
    existing = [col['name'] for col in inspector.get_columns(table_name)]
    mapper = inspect(model_class)
    for col in mapper.columns:
        if col.key not in existing:
            col_type = str(col.type)
            nullable = "NULL" if col.nullable else "NOT NULL"
            default = ""
            if col.default is not None:
                dv = col.default.arg
                if isinstance(dv, bool):
                    default = f" DEFAULT {1 if dv else 0}"
                elif isinstance(dv, (int, float)):
                    default = f" DEFAULT {dv}"
                elif isinstance(dv, str):
                    default = f" DEFAULT '{dv}'"
            try:
                sql = f'ALTER TABLE {table_name} ADD COLUMN {col.key} {col_type} {default}'
                db.session.execute(text(sql))
            except Exception:
                pass  # Column might already exist with different detection
    db.session.commit()


def migrate_existing_students():
    """Set default passwords for students that don't have one."""
    students = Student.query.filter(
        (Student.password_hash == None) | (Student.password_hash == '')
    ).all()
    for s in students:
        s.set_password('changeme')
    if students:
        db.session.commit()


with app.app_context():
    db.create_all()
    ensure_columns('student', Student)
    ensure_columns('teacher', Teacher)
    ensure_columns('announcement', Announcement)
    ensure_columns('attendance_log', AttendanceLog)
    migrate_existing_students()


# ==========================
# ERROR HANDLERS
# ==========================
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500


@app.errorhandler(403)
def forbidden(e):
    flash('Access denied or invalid request.', 'danger')
    return redirect(url_for('home'))


# ==========================
# HOME
# ==========================
@app.route('/')
def home():
    announcements = Announcement.query.order_by(
        Announcement.is_pinned.desc(),
        Announcement.created_at.desc()
    ).limit(5).all()
    return render_template('index.html', announcements=announcements)


# ==========================
# TEACHER REGISTRATION
# ==========================
@app.route('/teacher_register', methods=['GET', 'POST'])
def teacher_register():
    # Only allow registration if no teachers exist
    if Teacher.query.first():
        flash('A teacher account already exists. Please log in.', 'info')
        return redirect(url_for('teacher_login'))

    if request.method == 'POST':
        try:
            name = validate_required(request.form.get('name', ''), 'Name')
            email = validate_email(validate_required(request.form.get('email', ''), 'Email'))
            password = request.form.get('password', '').strip()
            confirm = request.form.get('confirm_password', '').strip()

            if len(password) < 6:
                raise ValueError('Password must be at least 6 characters.')
            if password != confirm:
                raise ValueError('Passwords do not match.')

            teacher = Teacher(name=name, email=email)
            teacher.set_password(password)
            db.session.add(teacher)
            db.session.commit()
            flash('Teacher account created! Please log in.', 'success')
            return redirect(url_for('teacher_login'))
        except ValueError as e:
            flash(str(e), 'danger')
        except Exception:
            db.session.rollback()
            flash('An error occurred during registration.', 'danger')

    return render_template('teacher_register.html')


# ==========================
# TEACHER LOGIN
# ==========================
@app.route('/teacher', methods=['GET', 'POST'])
def teacher_login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        if is_rate_limited(f'teacher:{email}'):
            flash('Too many login attempts. Please try again in 5 minutes.', 'danger')
            return render_template('teacher_login.html')

        teacher = Teacher.query.filter(db.func.lower(Teacher.email) == email).first()

        if teacher and teacher.check_password(password):
            session.clear()
            session['role'] = 'teacher'
            session['teacher_id'] = teacher.id
            session['teacher_name'] = teacher.name
            flash('Teacher login successful.', 'success')
            return redirect(url_for('instructor'))

        record_login_attempt(f'teacher:{email}')
        flash('Invalid email or password.', 'danger')

    # If no teachers exist, redirect to registration
    if not Teacher.query.first():
        return redirect(url_for('teacher_register'))

    return render_template('teacher_login.html')


# ==========================
# STUDENT LOGIN
# ==========================
@app.route('/student', methods=['GET', 'POST'])
def student():
    if request.method == 'POST':
        usn = request.form.get('usn', '').strip().upper()
        password = request.form.get('password', '')

        if is_rate_limited(f'student:{usn}'):
            flash('Too many login attempts. Please try again in 5 minutes.', 'danger')
            return render_template('student_login.html')

        student_obj = Student.query.filter(
            db.func.upper(Student.usn) == usn,
            Student.is_active == True
        ).first()

        if student_obj and student_obj.check_password(password):
            session.clear()
            session['role'] = 'student'
            session['student_id'] = student_obj.id
            flash('Student login successful.', 'success')
            return redirect(url_for('student_dashboard', id=student_obj.id))

        record_login_attempt(f'student:{usn}')
        flash('Invalid USN or password.', 'danger')

    return render_template('student_login.html')


# ==========================
# LOGOUT
# ==========================
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))


# ==========================
# TEACHER PROFILE
# ==========================
@app.route('/teacher_profile', methods=['GET', 'POST'])
@login_required(role='teacher')
def teacher_profile():
    teacher_id = session.get('teacher_id')
    teacher = Teacher.query.get_or_404(teacher_id) if teacher_id else Teacher.query.first()

    if not teacher:
        flash('Teacher profile not found.', 'danger')
        return redirect(url_for('instructor'))

    if request.method == 'POST':
        try:
            teacher.name = request.form.get('name', teacher.name or '').strip()
            teacher.designation = request.form.get('designation', teacher.designation or '').strip()
            teacher.qualification = request.form.get('qualification', teacher.qualification or '').strip()
            teacher.contact_number = request.form.get('contact_number', teacher.contact_number or '').strip()
            teacher.email = request.form.get('email', teacher.email or '').strip()
            teacher.department = request.form.get('department', teacher.department or '').strip()
            teacher.subjects_handled = request.form.get('subjects_handled', teacher.subjects_handled or '').strip()
            teacher.whatsapp_number = request.form.get('whatsapp_number', teacher.whatsapp_number or '').strip()
            teacher.contacting_times = request.form.get('contacting_times', teacher.contacting_times or '').strip()
            teacher.staff_room_no = request.form.get('staff_room_no', teacher.staff_room_no or '').strip()

            image = request.files.get('image')
            if image and image.filename:
                filename = secure_filename(image.filename)
                if allowed_image(filename):
                    ext = os.path.splitext(filename)[1].lower()
                    saved_name = f"teacher_{teacher.id}{ext}"
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], saved_name)
                    image.save(filepath)
                    teacher.image_filename = saved_name
                else:
                    flash('Invalid image format. Use JPG, PNG, or GIF.', 'warning')

            db.session.commit()
            flash('Teacher profile saved successfully.', 'success')
            return redirect(url_for('teacher_dashboard'))
        except Exception:
            db.session.rollback()
            flash('Error saving profile.', 'danger')

    return render_template('teacher_profile.html', teacher=teacher)


# ==========================
# INSTRUCTOR PAGE
# ==========================
@app.route('/instructor')
@login_required(role='teacher')
def instructor():
    students = Student.query.filter_by(is_active=True).all()
    total_students = len(students)
    avg_marks = round(sum(s.marks for s in students) / total_students, 2) if total_students else 0
    avg_attendance = round(sum(s.attendance for s in students) / total_students, 2) if total_students else 0
    pass_rate = round(sum(1 for s in students if s.marks >= 40) / total_students * 100, 2) if total_students else 0

    # Subject-wise averages
    subject_avg = {}
    subjects = {'python': 'Python', 'dbms': 'DBMS', 'dsa': 'DSA', 'maths': 'Maths', 'fcn': 'FCN'}
    for key, label in subjects.items():
        values = [getattr(s, key) for s in students]
        subject_avg[label] = round(sum(values) / len(values), 2) if values else 0

    # Performance distribution (count by grade)
    grade_dist = {
        'Distinction': sum(1 for s in students if s.marks >= 85),
        'First Class': sum(1 for s in students if 60 <= s.marks < 85),
        'Pass': sum(1 for s in students if 40 <= s.marks < 60),
        'Fail': sum(1 for s in students if s.marks < 40)
    }

    return render_template(
        'instructor.html',
        total_students=total_students,
        avg_marks=avg_marks,
        avg_attendance=avg_attendance,
        pass_rate=pass_rate,
        subject_avg=subject_avg,
        grade_dist=grade_dist
    )


# ==========================
# STUDENT DASHBOARD
# ==========================
@app.route('/student_dashboard/<int:id>')
@login_required(role='student')
def student_dashboard(id):
    if session.get('student_id') != id:
        flash('You are not authorized to view that student.', 'danger')
        return redirect(url_for('student'))

    student_obj = Student.query.get_or_404(id)
    announcements = Announcement.query.order_by(
        Announcement.is_pinned.desc(),
        Announcement.created_at.desc()
    ).limit(5).all()
    recent_quizzes = QuizAttempt.query.filter_by(student_id=id).order_by(
        QuizAttempt.date_attempted.desc()
    ).limit(5).all()

    return render_template(
        'student_dashboard.html',
        student=student_obj,
        announcements=announcements,
        recent_quizzes=recent_quizzes
    )


# ==========================
# STUDENT PROFILE
# ==========================
@app.route('/student_profile/<int:id>', methods=['GET', 'POST'])
@login_required(role='student')
def student_profile(id):
    if session.get('student_id') != id:
        flash('You are not authorized to edit that profile.', 'danger')
        return redirect(url_for('student'))

    student_obj = Student.query.get_or_404(id)

    if request.method == 'POST':
        try:
            student_obj.name = request.form.get('full_name', student_obj.name).strip()
            student_obj.middle_name = request.form.get('middle_name', '').strip()
            student_obj.last_name = request.form.get('last_name', '').strip()
            student_obj.address = request.form.get('address', '').strip()
            student_obj.dob = request.form.get('dob', '').strip()
            student_obj.parent_name = request.form.get('parent_name', '').strip()
            student_obj.parent_contact = request.form.get('parent_contact', '').strip()
            student_obj.blood_group = request.form.get('blood_group', '').strip()
            student_obj.phone_number = request.form.get('phone_number', '').strip()
            student_obj.linkedin = request.form.get('linkedin', '').strip()
            student_obj.email = validate_email(request.form.get('email', ''))
            student_obj.department = request.form.get('department', '').strip()

            image = request.files.get('image')
            if image and image.filename:
                filename = secure_filename(image.filename)
                if allowed_image(filename):
                    ext = os.path.splitext(filename)[1].lower()
                    saved_name = f"student_{student_obj.id}{ext}"
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], saved_name)
                    image.save(filepath)
                    student_obj.image_filename = saved_name
                else:
                    flash('Invalid image format. Use JPG, PNG, or GIF.', 'warning')

            db.session.commit()
            flash('Profile saved successfully.', 'success')
            return redirect(url_for('student_dashboard', id=student_obj.id))
        except ValueError as e:
            flash(str(e), 'danger')
        except Exception:
            db.session.rollback()
            flash('Error saving profile.', 'danger')

    return render_template('student_profile.html', student=student_obj)


# ==========================
# STUDENT CHANGE PASSWORD
# ==========================
@app.route('/student_change_password/<int:id>', methods=['GET', 'POST'])
@login_required(role='student')
def student_change_password(id):
    if session.get('student_id') != id:
        flash('Access denied.', 'danger')
        return redirect(url_for('student'))

    student_obj = Student.query.get_or_404(id)

    if request.method == 'POST':
        current = request.form.get('current_password', '')
        new_pass = request.form.get('new_password', '')
        confirm = request.form.get('confirm_password', '')

        if not student_obj.check_password(current):
            flash('Current password is incorrect.', 'danger')
        elif len(new_pass) < 6:
            flash('New password must be at least 6 characters.', 'danger')
        elif new_pass != confirm:
            flash('New passwords do not match.', 'danger')
        else:
            student_obj.set_password(new_pass)
            db.session.commit()
            flash('Password changed successfully.', 'success')
            return redirect(url_for('student_dashboard', id=id))

    return render_template('student_change_password.html', student=student_obj)


# ==========================
# AI CHAT
# ==========================
def get_local_assistant_response(student_obj, message):
    msg = message.lower().strip()

    # 1. Greetings
    if any(greet in msg for greet in ['hello', 'hi', 'hey', 'greetings', 'hola', 'good morning', 'good afternoon', 'good evening']):
        return (
            f"Hello {student_obj.name}! I am your AI academic tutor.\n\n"
            f"I can help you with your subjects, grades, attendance, rank, or teacher details. "
            f"Feel free to ask something like:\n"
            f"- **'What is my current rank?'**\n"
            f"- **'Show my python marks'**\n"
            f"- **'Is my attendance okay?'**\n"
            f"- **'Who is my teacher?'**\n"
            f"- **'What is DSA?'**"
        )

    # 2. Thank you
    if any(thx in msg for thx in ['thanks', 'thank you', 'ty', 'appreciate it']):
        return f"You're very welcome, {student_obj.name}! Let me know if you have any other questions. Keep up the hard work!"

    # 3. Rank
    if 'rank' in msg or 'position' in msg or 'topper' in msg or 'standing' in msg:
        rank = get_student_rank(student_obj)
        return (
            f"### Academic Rank\n"
            f"You are ranked **#{rank}** in the class based on your average score of **{student_obj.average_marks():.2f}**.\n\n"
            f"Keep pushing to reach the top spot!"
        )

    # 4. Attendance
    if 'attendance' in msg or 'present' in msg or 'absent' in msg or 'classes' in msg:
        if student_obj.attendance < 75:
            remarks = "⚠️ **Warning**: Your attendance is below the minimum required 75%. Please attend classes regularly to avoid a shortage of attendance."
        else:
            remarks = "✅ **Good job!** Your attendance is above the required 75% threshold. Keep maintaining this regularity."
        return (
            f"### Attendance Summary\n"
            f"Your current attendance is **{student_obj.attendance:.2f}%**.\n\n"
            f"{remarks}"
        )

    # 5. Specific Subject Marks
    subject_map = {
        'python': ('Python', student_obj.python),
        'dbms': ('DBMS', student_obj.dbms),
        'database': ('DBMS', student_obj.dbms),
        'sql': ('DBMS', student_obj.dbms),
        'dsa': ('DSA', student_obj.dsa),
        'data structure': ('DSA', student_obj.dsa),
        'algorithm': ('DSA', student_obj.dsa),
        'math': ('Mathematics', student_obj.maths),
        'algebra': ('Mathematics', student_obj.maths),
        'calculus': ('Mathematics', student_obj.maths),
        'fcn': ('FCN', student_obj.fcn),
        'network': ('FCN', student_obj.fcn),
        'tcp': ('FCN', student_obj.fcn),
        'routing': ('FCN', student_obj.fcn),
    }

    for keyword, (subj_name, score) in subject_map.items():
        if keyword in msg:
            grade_info = "Distinction" if score >= 85 else "First Class" if score >= 60 else "Pass" if score >= 40 else "Fail"
            return f"Your score in **{subj_name}** is **{score:.2f}/100** (Status: *{grade_info}*)."

    # 6. Overall Marks / Grades
    if any(keyword in msg for keyword in ['marks', 'grades', 'score', 'report', 'result', 'academic', 'gpa', 'average', 'performance']):
        return (
            f"### Academic Performance Summary\n"
            f"- **USN**: {student_obj.usn}\n"
            f"- **Student Name**: {student_obj.full_name}\n"
            f"- **Average Marks**: **{student_obj.average_marks():.2f}**\n"
            f"- **Result Status**: **{student_obj.result()}**\n"
            f"- **Faculty Remarks**: *\"{student_obj.remarks()}\"*\n\n"
            f"**Subject Breakdown:**\n"
            f"1. **Python**: {student_obj.python:.2f} / 100\n"
            f"2. **DBMS**: {student_obj.dbms:.2f} / 100\n"
            f"3. **DSA**: {student_obj.dsa:.2f} / 100\n"
            f"4. **Mathematics**: {student_obj.maths:.2f} / 100\n"
            f"5. **FCN**: {student_obj.fcn:.2f} / 100"
        )

    # 7. Teacher / Instructor Details
    if any(keyword in msg for keyword in ['teacher', 'instructor', 'faculty', 'professor', 'staff', 'handled']):
        teachers = Teacher.query.all()
        if not teachers:
            return "No faculty members have been registered in the system yet. Please contact the administrator."

        response_str = "### Faculty Directory\nHere are the registered instructors in the department:\n\n"
        for t in teachers:
            response_str += (
                f"- **{t.name}** ({t.designation or 'Faculty'})\n"
                f"  - *Qualification*: {t.qualification or 'N/A'}\n"
                f"  - *Department*: {t.department or 'N/A'}\n"
                f"  - *Subjects*: {t.subjects_handled or 'N/A'}\n"
                f"  - *Contact*: {t.email or 'N/A'} | Staff Room: {t.staff_room_no or 'N/A'}\n"
                f"  - *WhatsApp/Consulting*: {t.whatsapp_number or 'N/A'} (Hours: {t.contacting_times or 'N/A'})\n\n"
            )
        return response_str

    # 8. Profile Details
    if any(keyword in msg for keyword in ['profile', 'address', 'dob', 'linkedin', 'blood', 'parent', 'phone', 'contact']):
        return (
            f"### Student Profile Information\n"
            f"- **USN**: {student_obj.usn}\n"
            f"- **Full Name**: {student_obj.full_name}\n"
            f"- **Department**: {student_obj.department}\n"
            f"- **DOB**: {student_obj.dob or 'Not set'}\n"
            f"- **Blood Group**: {student_obj.blood_group or 'Not set'}\n"
            f"- **Contact Number**: {student_obj.phone_number or 'Not set'}\n"
            f"- **Email Address**: {student_obj.email or 'Not set'}\n"
            f"- **Parent/Guardian Name**: {student_obj.parent_name or 'Not set'}\n"
            f"- **Parent Contact**: {student_obj.parent_contact or 'Not set'}\n"
            f"- **LinkedIn Profile**: {student_obj.linkedin or 'Not set'}"
        )

    # 9. Study Help
    if any(keyword in msg for keyword in ['study', 'prep', 'exam', 'prepare', 'help', 'fail', 'improve', 'learn']):
        low_subjects = []
        for name, score in [('Python', student_obj.python), ('DBMS', student_obj.dbms), ('DSA', student_obj.dsa), ('Mathematics', student_obj.maths), ('FCN', student_obj.fcn)]:
            if score < 50:
                low_subjects.append(f"{name} ({score:.1f})")

        if low_subjects:
            subj_list = ", ".join(low_subjects)
            return (
                f"### Exam Preparation & Improvement Plan\n"
                f"Based on your current records, you should pay special attention to the following subjects where your score is below 50:\n"
                f"👉 **{subj_list}**\n\n"
                f"**Recommended Action Items:**\n"
                f"1. **Consult Instructors:** Check the Faculty Directory and visit during consulting hours.\n"
                f"2. **Daily Practice:** Spend at least 45 minutes daily on coding or database queries.\n"
                f"3. **Mock Tests:** Solve previous year question papers under exam conditions.\n"
                f"4. **Attendance Boost:** Attend classes regularly to secure internal assessment marks."
            )
        else:
            return (
                f"### Exam Preparation Strategy\n"
                f"Excellent news: you have strong marks across all subjects! To maximize your score:\n\n"
                f"1. **Advanced Topics:** Study optional/advanced chapters.\n"
                f"2. **Peer Mentoring:** Explaining concepts solidifies understanding.\n"
                f"3. **Time Management:** Practice writing descriptive answers for exam duration."
            )

    # 10. Help Menu
    if 'help' in msg or 'menu' in msg or 'option' in msg:
        return (
            f"### AI Doubt Solver Help Menu\n"
            f"I can assist you with database details and academic queries. Just ask me:\n"
            f"1. **Grades/Report Card**: *'How are my marks?'*, *'Show my grade status'*\n"
            f"2. **Rank/Position**: *'What is my class rank?'*\n"
            f"3. **Attendance Status**: *'Is my attendance okay?'*\n"
            f"4. **Subjects & Concepts**: *'Explain DSA'*, *'What is DBMS?'*\n"
            f"5. **Faculty Directory**: *'List my teachers'*\n"
            f"6. **Student Profile**: *'My profile address'*\n"
            f"7. **Study Advice**: *'How to prepare for exam?'*"
        )

    # 11. Fallback
    words = msg.replace('?', '').split()
    stopwords = {'what', 'is', 'a', 'an', 'the', 'explain', 'define', 'how', 'does', 'why', 'who', 'where', 'to', 'for', 'of', 'in', 'on', 'with', 'about'}
    filtered = [w for w in words if w not in stopwords]
    topic = " ".join(filtered) if filtered else ""
    topic_str = f' regarding **"{topic}"**' if topic else ""
    return (
        f"### Academic Assistant (Database Mode)\n"
        f"I received your question{topic_str}.\n\n"
        f"Since I am running in local offline mode, I can only resolve database queries and subject concepts. "
        f"For specific questions, I recommend checking your course syllabus or asking your instructor."
    )


def get_ai_key_error():
    openai_key = os.environ.get('OPENAI_API_KEY') or os.environ.get('OEPAI_API_KEY')
    gemini_key = os.environ.get('GEMINI_API_KEY')
    
    placeholder_values = {'your_real_openai_key', 'your_real_gemini_key', 'changeme', 'change-me-please', ''}
    
    has_valid_openai = openai_key and openai_key.strip().lower() not in placeholder_values and not openai_key.strip().lower().startswith('your_')
    has_valid_gemini = gemini_key and gemini_key.strip().lower() not in placeholder_values and not gemini_key.strip().lower().startswith('your_')
    
    if has_valid_openai or has_valid_gemini:
        return None

    return 'No AI API key is configured. You need a free GEMINI_API_KEY or an OPENAI_API_KEY.'


@app.route('/student/<int:id>/chat')
@login_required(role='student')
def student_chat(id):
    student_obj = Student.query.get_or_404(id)
    ai_error = get_ai_key_error()
    return render_template('student_chat.html', student=student_obj, ai_error=ai_error)


@app.route('/api/student_chat/<int:id>', methods=['POST'])
@login_required(role='student')
def student_chat_api(id):
    if session.get('student_id') != id:
        return jsonify({'error': 'Unauthorized access.'}), 403

    data = request.get_json() or {}
    message = data.get('message', '').strip()
    if not message:
        return jsonify({'error': 'Please enter a question.'}), 400

    student_obj = Student.query.get_or_404(id)
    msg_lower = message.lower()

    personal_keywords = [
        'rank', 'position', 'standing', 'topper',
        'attendance', 'present', 'absent', 'classes',
        'marks', 'grades', 'score', 'report', 'result', 'academic', 'gpa', 'average', 'performance',
        'teacher', 'instructor', 'faculty', 'professor', 'staff', 'handled',
        'profile', 'address', 'dob', 'linkedin', 'blood', 'parent', 'phone', 'contact', 'my', 'me', 'i'
    ]

    is_personal_query = any(keyword in msg_lower for keyword in personal_keywords)
    ai_error = get_ai_key_error()

    if is_personal_query or ai_error:
        if 'attendance' in msg_lower:
            ans = f"Your current attendance is {student_obj.attendance:.2f}%. "
            if student_obj.attendance < 75:
                ans += "You are currently at risk of attendance shortage. Please attend more classes."
            else:
                ans += "You are maintaining a good attendance record."
            return jsonify({'answer': ans})
        elif 'marks' in msg_lower or 'score' in msg_lower or 'grade' in msg_lower or 'result' in msg_lower:
            return jsonify({'answer': f"Your overall average marks are {student_obj.average_marks():.2f}%. Your result status is: {student_obj.result()}."})
        elif ai_error:
            # Complain about AI key only if no specific local answer triggered
            return jsonify({'answer': "I'm currently in offline mode because no AI API key is configured. I can only answer basic questions about your attendance or marks."})
        else:
            answer = get_local_assistant_response(student_obj, message)
            return jsonify({'answer': answer})

    # Prepare system message with context
    system_prompt = f"""You are a helpful academic AI assistant for a student named {student_obj.name}. 
Their current standing: 
- Department: {student_obj.department}
- Overall Average Marks: {student_obj.average_marks():.2f}%
- Attendance: {student_obj.attendance:.2f}%
- Result Status: {student_obj.result()}
Subject Breakdown: Python ({student_obj.python}), DBMS ({student_obj.dbms}), DSA ({student_obj.dsa}), Maths ({student_obj.maths}), FCN ({student_obj.fcn}).

Answer their questions encouragingly and concisely. Use formatting like **bold** and bullet points where helpful."""

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": message}
    ]

    answer, error = query_ai(messages)
    if error:
        answer = get_local_assistant_response(student_obj, message)

    return jsonify({'answer': answer})


# ==========================
# MOCK QUIZ SYSTEM
# ==========================
QUIZ_QUESTIONS = {
    'Python': [
        {
            'question': 'Which of the following is an invalid variable name in Python?',
            'options': ['my_var', 'var_3', '3_var', '_myvar'],
            'correct_index': 2,
            'explanation': 'Variable names in Python cannot start with a number.'
        },
        {
            'question': 'What is the output of print(type(1 / 2)) in Python 3?',
            'options': ["<class 'int'>", "<class 'float'>", "<class 'double'>", "Error"],
            'correct_index': 1,
            'explanation': 'In Python 3, the division operator (/) always returns a floating-point number.'
        },
        {
            'question': 'Which method is used to add an element at the end of a list in Python?',
            'options': ['insert()', 'add()', 'append()', 'push()'],
            'correct_index': 2,
            'explanation': 'The append() method adds an element to the end of a list.'
        },
        {
            'question': 'How do you write comments in Python?',
            'options': ['// comment', '/* comment */', '# comment', '<!-- comment -->'],
            'correct_index': 2,
            'explanation': 'Python uses the hash symbol (#) to indicate a single-line comment.'
        },
        {
            'question': 'What does range(1, 5) generate?',
            'options': ['[1, 2, 3, 4, 5]', '[1, 2, 3, 4]', '[2, 3, 4, 5]', '[1, 3, 5]'],
            'correct_index': 1,
            'explanation': 'The range(start, stop) function generates integers from start up to (but excluding) stop.'
        }
    ],
    'DBMS': [
        {
            'question': 'What does SQL stand for?',
            'options': ['Structured Query Language', 'Strong Query Language', 'Simple Query Language', 'Structured Question Language'],
            'correct_index': 0,
            'explanation': 'SQL stands for Structured Query Language.'
        },
        {
            'question': 'Which key uniquely identifies each record in a database table?',
            'options': ['Foreign Key', 'Unique Key', 'Primary Key', 'Composite Key'],
            'correct_index': 2,
            'explanation': 'A Primary Key uniquely identifies each row in a database table.'
        },
        {
            'question': 'What does ACID stand for in DBMS transactions?',
            'options': [
                'Atomicity, Consistency, Isolation, Durability',
                'Accuracy, Consistency, Isolation, Dependency',
                'Atomicity, Concurrency, Isolation, Durability',
                'Access, Control, Integrity, Durability'
            ],
            'correct_index': 0,
            'explanation': 'ACID properties guarantee reliable database transactions.'
        },
        {
            'question': 'Which SQL command is used to remove a table structure from a database?',
            'options': ['DELETE', 'REMOVE', 'DROP', 'TRUNCATE'],
            'correct_index': 2,
            'explanation': 'DROP removes both the table schema definition and all its data.'
        },
        {
            'question': 'Which JOIN returns all rows when there is a match in either left or right table?',
            'options': ['INNER JOIN', 'LEFT JOIN', 'RIGHT JOIN', 'FULL OUTER JOIN'],
            'correct_index': 3,
            'explanation': 'A FULL OUTER JOIN returns all unmatched rows from both tables.'
        }
    ],
    'DSA': [
        {
            'question': 'Which data structure operates on a Last In, First Out (LIFO) basis?',
            'options': ['Queue', 'Stack', 'Linked List', 'Tree'],
            'correct_index': 1,
            'explanation': 'Stacks operate on a LIFO basis.'
        },
        {
            'question': 'What is the worst-case time complexity of Binary Search?',
            'options': ['O(1)', 'O(n)', 'O(log n)', 'O(n log n)'],
            'correct_index': 2,
            'explanation': 'Binary Search has a logarithmic O(log n) time complexity.'
        },
        {
            'question': 'Which data structure uses pointers to link nodes sequentially in memory?',
            'options': ['Array', 'Linked List', 'Stack', 'Queue'],
            'correct_index': 1,
            'explanation': 'A Linked List stores elements in nodes with reference pointers.'
        },
        {
            'question': 'What is the average time complexity of inserting a node in a balanced BST?',
            'options': ['O(1)', 'O(log n)', 'O(n)', 'O(n log n)'],
            'correct_index': 1,
            'explanation': 'In a balanced BST, insertion takes O(log n) time.'
        },
        {
            'question': 'Which algorithm is commonly used to find the shortest path in a weighted graph?',
            'options': ["Kruskal's Algorithm", "Dijkstra's Algorithm", 'DFS', 'BFS'],
            'correct_index': 1,
            'explanation': "Dijkstra's algorithm finds shortest paths from a single source vertex."
        }
    ],
    'Maths': [
        {
            'question': 'What is the determinant of a 2x2 identity matrix?',
            'options': ['0', '1', '-1', '2'],
            'correct_index': 1,
            'explanation': 'The determinant of an identity matrix is 1.'
        },
        {
            'question': 'If two events A and B are independent, what is P(A and B)?',
            'options': ['P(A) + P(B)', 'P(A) * P(B)', 'P(A) / P(B)', 'P(A) - P(B)'],
            'correct_index': 1,
            'explanation': 'For independent events, P(A∩B) = P(A) × P(B).'
        },
        {
            'question': 'What is the derivative of x^2 with respect to x?',
            'options': ['x', '2', '2x', '2x^2'],
            'correct_index': 2,
            'explanation': 'By the power rule, d/dx(x^n) = n × x^(n-1).'
        },
        {
            'question': 'In logic, when is a conditional statement P -> Q false?',
            'options': [
                'When P is true and Q is false',
                'When P is false and Q is true',
                'When both P and Q are false',
                'When both P and Q are true'
            ],
            'correct_index': 0,
            'explanation': 'A conditional is false only when P is true and Q is false.'
        },
        {
            'question': 'What is the sum of interior angles in a triangle?',
            'options': ['90 degrees', '180 degrees', '270 degrees', '360 degrees'],
            'correct_index': 1,
            'explanation': 'Interior angles of any Euclidean triangle sum to 180 degrees.'
        }
    ],
    'FCN': [
        {
            'question': 'Which layer of the OSI model is responsible for routing packets across networks?',
            'options': ['Physical Layer', 'Data Link Layer', 'Network Layer', 'Transport Layer'],
            'correct_index': 2,
            'explanation': 'The Network Layer handles routing packets and selecting paths.'
        },
        {
            'question': 'What is the standard port number used for HTTPS?',
            'options': ['80', '443', '21', '22'],
            'correct_index': 1,
            'explanation': 'HTTPS uses port 443 by default.'
        },
        {
            'question': 'What protocol maps an IP address to a physical MAC address?',
            'options': ['DHCP', 'DNS', 'ARP', 'ICMP'],
            'correct_index': 2,
            'explanation': 'ARP resolves an IPv4 address to its associated MAC address.'
        },
        {
            'question': 'Which protocol is connection-oriented and guarantees reliable data delivery?',
            'options': ['UDP', 'TCP', 'IP', 'DNS'],
            'correct_index': 1,
            'explanation': 'TCP uses handshakes and acknowledgments for reliable delivery.'
        },
        {
            'question': 'What is the default subnet mask for a Class C IP address?',
            'options': ['255.0.0.0', '255.255.0.0', '255.255.255.0', '255.255.255.255'],
            'correct_index': 2,
            'explanation': 'Class C networks use the /24 prefix (255.255.255.0).'
        }
    ]
}


@app.route('/student_quiz/<int:id>')
@login_required(role='student')
def student_quiz(id):
    if session.get('student_id') != id:
        flash('You are not authorized to view this page.', 'danger')
        return redirect(url_for('student'))

    student_obj = Student.query.get_or_404(id)
    attempts = QuizAttempt.query.filter_by(student_id=id).order_by(QuizAttempt.date_attempted.desc()).all()

    subjects = {
        'Python': {'name': 'Python Programming', 'attempts': 0, 'max_score': 0},
        'DBMS': {'name': 'Database Systems (DBMS)', 'attempts': 0, 'max_score': 0},
        'DSA': {'name': 'Data Structures & Algorithms', 'attempts': 0, 'max_score': 0},
        'Maths': {'name': 'Engineering Mathematics', 'attempts': 0, 'max_score': 0},
        'FCN': {'name': 'Foundations of Computer Networks', 'attempts': 0, 'max_score': 0}
    }

    for att in attempts:
        subj_key = att.subject
        if subj_key in subjects:
            subjects[subj_key]['attempts'] += 1
            if att.score > subjects[subj_key]['max_score']:
                subjects[subj_key]['max_score'] = att.score

    return render_template('student_quiz.html', student=student_obj, attempts=attempts, subjects=subjects)


@app.route('/api/quiz/questions/<subject>')
@login_required(role='student')
def api_quiz_questions(subject):
    if subject not in QUIZ_QUESTIONS:
        return jsonify({'error': 'Subject not found.'}), 404
    return jsonify({'questions': QUIZ_QUESTIONS[subject]})


@app.route('/api/quiz/submit/<int:id>', methods=['POST'])
@login_required(role='student')
def api_quiz_submit(id):
    if session.get('student_id') != id:
        return jsonify({'error': 'Unauthorized.'}), 403

    data = request.get_json() or {}
    subject = data.get('subject')
    score = data.get('score')
    total = data.get('total')

    if not subject or score is None or total is None:
        return jsonify({'error': 'Invalid request data.'}), 400

    try:
        attempt = QuizAttempt(
            student_id=id,
            subject=subject,
            score=int(score),
            total_questions=int(total)
        )
        db.session.add(attempt)
        db.session.commit()
        return jsonify({'status': 'success', 'attempt_id': attempt.id})
    except Exception:
        db.session.rollback()
        return jsonify({'error': 'Failed to save quiz attempt.'}), 500


# ==========================
# ANNOUNCEMENTS
# ==========================
@app.route('/announcements')
@login_required(role='teacher')
def announcements():
    all_announcements = Announcement.query.order_by(
        Announcement.is_pinned.desc(),
        Announcement.created_at.desc()
    ).all()
    return render_template('announcements.html', announcements=all_announcements)


@app.route('/announcement/create', methods=['GET', 'POST'])
@login_required(role='teacher')
def create_announcement():
    if request.method == 'POST':
        try:
            title = validate_required(request.form.get('title', ''), 'Title')
            content = validate_required(request.form.get('content', ''), 'Content')
            is_pinned = request.form.get('is_pinned') == 'on'

            announcement = Announcement(
                title=title,
                content=content,
                created_by=session.get('teacher_name', 'Teacher'),
                is_pinned=is_pinned
            )
            db.session.add(announcement)
            db.session.commit()
            flash('Announcement published successfully.', 'success')
            return redirect(url_for('announcements'))
        except ValueError as e:
            flash(str(e), 'danger')
        except Exception:
            db.session.rollback()
            flash('Error creating announcement.', 'danger')

    return render_template('create_announcement.html')


@app.route('/announcement/delete/<int:id>', methods=['POST'])
@login_required(role='teacher')
def delete_announcement(id):
    announcement = Announcement.query.get_or_404(id)
    try:
        db.session.delete(announcement)
        db.session.commit()
        flash('Announcement deleted.', 'success')
    except Exception:
        db.session.rollback()
        flash('Error deleting announcement.', 'danger')
    return redirect(url_for('announcements'))


# ==========================
# TEACHER DASHBOARD
# ==========================
@app.route('/teacher_dashboard')
@login_required(role='teacher')
def teacher_dashboard():
    search = request.args.get('search', '')
    dept_filter = request.args.get('department', '')

    query = Student.query.filter_by(is_active=True)
    if search:
        query = query.filter(
            (Student.name.contains(search)) |
            (Student.usn.contains(search))
        )
    if dept_filter:
        query = query.filter(Student.department == dept_filter)

    students = query.all()
    all_students = Student.query.filter_by(is_active=True).all()

    # Get unique departments for filter dropdown
    departments = sorted(set(s.department for s in all_students if s.department))

    total_students = len(students)
    avg_marks = round(sum(s.marks for s in students) / total_students, 2) if total_students else 0
    avg_attendance = round(sum(s.attendance for s in students) / total_students, 2) if total_students else 0
    pass_rate = round(sum(1 for s in students if s.marks >= 40) / total_students * 100, 2) if total_students else 0
    low_attendance_count = sum(1 for s in students if s.attendance < 75)
    at_risk_count = sum(1 for s in students if s.marks < 50 and s.attendance < 75)
    top_students = sorted(students, key=lambda s: s.marks, reverse=True)[:3]

    teacher_id = session.get('teacher_id')
    teacher = Teacher.query.get(teacher_id) if teacher_id else Teacher.query.first()

    subject_stats = {}
    for key, label in [
        ('python', 'Python'),
        ('dbms', 'DBMS'),
        ('dsa', 'DSA'),
        ('maths', 'Maths'),
        ('fcn', 'FCN')
    ]:
        values = [getattr(s, key) for s in students]
        subject_stats[label] = {
            'avg': round(sum(values) / len(values), 2) if values else 0,
            'max': round(max(values), 2) if values else 0,
            'min': round(min(values), 2) if values else 0
        }

    recent_announcements = Announcement.query.order_by(
        Announcement.created_at.desc()
    ).limit(3).all()

    return render_template(
        'teacher_dashboard.html',
        students=students,
        total_students=total_students,
        avg_marks=avg_marks,
        avg_attendance=avg_attendance,
        pass_rate=pass_rate,
        subject_stats=subject_stats,
        low_attendance_count=low_attendance_count,
        at_risk_count=at_risk_count,
        top_students=top_students,
        teacher=teacher,
        departments=departments,
        recent_announcements=recent_announcements
    )


# ==========================
# ADD STUDENT
# ==========================
@app.route('/add_student', methods=['GET', 'POST'])
@login_required(role='teacher')
def add_student():
    if request.method == 'POST':
        try:
            name = validate_required(request.form.get('name', ''), 'Name')
            usn = validate_required(request.form.get('usn', ''), 'USN').upper()
            department = validate_required(request.form.get('department', ''), 'Department')

            # Check for duplicate USN
            existing = Student.query.filter(db.func.upper(Student.usn) == usn).first()
            if existing:
                raise ValueError(f'A student with USN {usn} already exists.')

            attendance = validate_attendance(request.form.get('attendance', 0))
            python_marks = validate_marks(request.form.get('python', 0), 'Python')
            dbms_marks = validate_marks(request.form.get('dbms', 0), 'DBMS')
            dsa_marks = validate_marks(request.form.get('dsa', 0), 'DSA')
            maths_marks = validate_marks(request.form.get('maths', 0), 'Maths')
            fcn_marks = validate_marks(request.form.get('fcn', 0), 'FCN')
            email = validate_email(request.form.get('email', ''))
            parent_email = validate_email(request.form.get('parent_email', ''))

            password = request.form.get('password', '').strip()
            if not password:
                password = 'changeme'

            new_student = Student(
                name=name,
                usn=usn,
                department=department,
                attendance=attendance,
                python=python_marks,
                dbms=dbms_marks,
                dsa=dsa_marks,
                maths=maths_marks,
                fcn=fcn_marks,
                email=email,
                parent_email=parent_email
            )
            new_student.set_password(password)
            db.session.add(new_student)
            db.session.commit()
            flash(f'Student {name} added successfully. Default password: {password}', 'success')
            return redirect(url_for('teacher_dashboard'))
        except ValueError as e:
            flash(str(e), 'danger')
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding student: {e}', 'danger')

    return render_template('add_student.html')


# ==========================
# EDIT STUDENT
# ==========================
@app.route('/edit_student/<int:id>', methods=['GET', 'POST'])
@login_required(role='teacher')
def edit_student(id):
    student_obj = Student.query.get_or_404(id)

    if request.method == 'POST':
        try:
            student_obj.name = validate_required(request.form.get('name', ''), 'Name')
            student_obj.usn = validate_required(request.form.get('usn', ''), 'USN').upper()
            student_obj.department = validate_required(request.form.get('department', ''), 'Department')
            student_obj.email = validate_email(request.form.get('email', ''))
            student_obj.parent_email = validate_email(request.form.get('parent_email', ''))
            student_obj.attendance = validate_attendance(request.form.get('attendance', 0))
            student_obj.python = validate_marks(request.form.get('python', 0), 'Python')
            student_obj.dbms = validate_marks(request.form.get('dbms', 0), 'DBMS')
            student_obj.dsa = validate_marks(request.form.get('dsa', 0), 'DSA')
            student_obj.maths = validate_marks(request.form.get('maths', 0), 'Maths')
            student_obj.fcn = validate_marks(request.form.get('fcn', 0), 'FCN')

            # Optional password reset
            new_password = request.form.get('new_password', '').strip()
            if new_password:
                if len(new_password) < 6:
                    raise ValueError('Password must be at least 6 characters.')
                student_obj.set_password(new_password)

            db.session.commit()
            flash('Student updated successfully.', 'success')
            return redirect(url_for('teacher_dashboard'))
        except ValueError as e:
            flash(str(e), 'danger')
        except Exception:
            db.session.rollback()
            flash('Error updating student.', 'danger')

    return render_template('edit_student.html', student=student_obj)


# ==========================
# DELETE STUDENT (soft delete via POST)
# ==========================
@app.route('/delete_student/<int:id>', methods=['POST'])
@login_required(role='teacher')
def delete_student(id):
    student_obj = Student.query.get_or_404(id)
    try:
        student_obj.is_active = False
        db.session.commit()
        flash(f'Student {student_obj.name} has been removed.', 'success')
    except Exception:
        db.session.rollback()
        flash('Error removing student.', 'danger')
    return redirect(url_for('teacher_dashboard'))


# ==========================
# ATTENDANCE UPDATE (SINGLE)
# ==========================
@app.route('/update_attendance/<int:id>', methods=['GET', 'POST'])
@login_required(role='teacher')
def update_attendance(id):
    student_obj = Student.query.get_or_404(id)

    if request.method == 'POST':
        try:
            student_obj.attendance = validate_attendance(request.form.get('attendance', 0))
            db.session.commit()
            flash('Attendance updated.', 'success')
            return redirect(url_for('teacher_dashboard'))
        except ValueError as e:
            flash(str(e), 'danger')
        except Exception:
            db.session.rollback()
            flash('Error updating attendance.', 'danger')

    # Get attendance logs for this student
    logs = AttendanceLog.query.filter_by(student_id=id).order_by(AttendanceLog.date.desc()).limit(30).all()
    return render_template('attendance.html', student=student_obj, logs=logs)


# ==========================
# BULK ATTENDANCE
# ==========================
@app.route('/bulk_attendance', methods=['GET', 'POST'])
@login_required(role='teacher')
def bulk_attendance():
    students = Student.query.filter_by(is_active=True).order_by(Student.name).all()

    if request.method == 'POST':
        date_str = request.form.get('date', '')
        try:
            att_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        except ValueError:
            flash('Invalid date format.', 'danger')
            return render_template('bulk_attendance.html', students=students)

        # Check if attendance already marked for this date
        existing = AttendanceLog.query.filter_by(date=att_date).first()
        if existing:
            # Delete existing records for this date to allow re-marking
            AttendanceLog.query.filter_by(date=att_date).delete()

        teacher_name = session.get('teacher_name', 'Teacher')
        present_ids = request.form.getlist('present')

        try:
            for s in students:
                status = 'Present' if str(s.id) in present_ids else 'Absent'
                log = AttendanceLog(
                    student_id=s.id,
                    date=att_date,
                    status=status,
                    marked_by=teacher_name
                )
                db.session.add(log)

            # Recalculate attendance percentages
            for s in students:
                total_logs = AttendanceLog.query.filter_by(student_id=s.id).count()
                present_logs = AttendanceLog.query.filter_by(student_id=s.id, status='Present').count()
                s.attendance = round((present_logs / total_logs) * 100, 2) if total_logs > 0 else 0.0

            db.session.commit()
            flash(f'Attendance marked for {att_date.strftime("%d %b %Y")}.', 'success')
            return redirect(url_for('bulk_attendance'))
        except Exception:
            db.session.rollback()
            flash('Error saving attendance.', 'danger')

    # Get recent attendance dates
    recent_dates = db.session.query(AttendanceLog.date).distinct().order_by(AttendanceLog.date.desc()).limit(10).all()
    recent_dates = [d[0] for d in recent_dates]

    return render_template('bulk_attendance.html', students=students, recent_dates=recent_dates)


# ==========================
# ATTENDANCE PAGE
# ==========================
@app.route('/student_attendance')
@login_required(role='teacher')
def student_attendance():
    students = Student.query.filter_by(is_active=True).all()
    return render_template('student_attendance.html', students=students)


# ==========================
# ANALYTICS
# ==========================
@app.route('/analytics')
@login_required(role='teacher')
def analytics():
    students = Student.query.filter_by(is_active=True).all()
    total_students = len(students)

    names = [s.name for s in students]
    marks = [s.average_marks() for s in students]
    attendance = [s.attendance for s in students]

    avg_marks = round(sum(marks) / len(marks), 2) if marks else 0
    avg_attendance = round(sum(attendance) / len(attendance), 2) if attendance else 0

    # Department-wise breakdown
    dept_data = {}
    for s in students:
        dept = s.department or 'Unknown'
        if dept not in dept_data:
            dept_data[dept] = {'count': 0, 'total_marks': 0, 'total_attendance': 0}
        dept_data[dept]['count'] += 1
        dept_data[dept]['total_marks'] += s.average_marks()
        dept_data[dept]['total_attendance'] += s.attendance

    for dept in dept_data:
        c = dept_data[dept]['count']
        dept_data[dept]['avg_marks'] = round(dept_data[dept]['total_marks'] / c, 2)
        dept_data[dept]['avg_attendance'] = round(dept_data[dept]['total_attendance'] / c, 2)

    return render_template(
        'analytics.html',
        total_students=total_students,
        avg_marks=avg_marks,
        avg_attendance=avg_attendance,
        names=names,
        marks=marks,
        attendance=attendance,
        dept_data=dept_data
    )


# ==========================
# EXPORT EXCEL
# ==========================
@app.route('/export_excel')
@login_required(role='teacher')
def export_excel():
    students = Student.query.filter_by(is_active=True).all()
    data = []

    for s in students:
        data.append({
            "ID": s.id,
            "Name": s.name,
            "USN": s.usn,
            "Department": s.department,
            "Python": s.python,
            "DBMS": s.dbms,
            "DSA": s.dsa,
            "Maths": s.maths,
            "FCN": s.fcn,
            "Attendance": s.attendance,
            "Average Marks": round(s.marks, 2),
            "Result": s.result(),
            "Email": s.email or '',
            "Parent Email": s.parent_email or ''
        })

    df = pd.DataFrame(data)
    buffer = io.BytesIO()
    with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Students')
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name='student_report.xlsx',
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )


# ==========================
# TOPPER
# ==========================
@app.route('/topper')
@login_required(role='teacher')
def topper():
    students = Student.query.filter_by(is_active=True).all()

    if not students:
        flash('No students found.', 'warning')
        return redirect(url_for('teacher_dashboard'))

    top = max(students, key=lambda s: s.average_marks())
    return render_template('topper.html', topper=top)


# ==========================
# RANKLIST
# ==========================
@app.route('/ranklist')
@login_required(role='teacher')
def ranklist():
    students = Student.query.filter_by(is_active=True).all()
    students = sorted(students, key=lambda s: s.average_marks(), reverse=True)
    return render_template('ranklist.html', students=students)


# ==========================
# EXPORT PDF
# ==========================
@app.route('/export_pdf')
@login_required(role='teacher')
def export_pdf():
    students = Student.query.filter_by(is_active=True).order_by(Student.marks.desc()).all()
    buffer = io.BytesIO()

    pdf = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    pdf.setTitle('Student Performance Report')
    pdf.setFont('Helvetica-Bold', 14)
    pdf.drawCentredString(width / 2, height - inch * 0.6, 'Student Performance Report')
    pdf.setFont('Helvetica', 9)
    pdf.drawCentredString(width / 2, height - inch * 0.85, 'Generated by Student Performance Analyzer')

    line_y = height - inch * 1.2
    pdf.setFont('Helvetica-Bold', 9)
    pdf.drawString(36, line_y, 'USN')
    pdf.drawString(110, line_y, 'Name')
    pdf.drawString(340, line_y, 'Attendance')
    pdf.drawString(430, line_y, 'Avg Marks')
    pdf.drawString(500, line_y, 'Result')
    pdf.setFont('Helvetica', 9)
    line_y -= 14

    for s in students:
        if line_y < 72:
            pdf.showPage()
            line_y = height - inch * 0.6
            pdf.setFont('Helvetica-Bold', 9)
            pdf.drawString(36, line_y, 'USN')
            pdf.drawString(110, line_y, 'Name')
            pdf.drawString(340, line_y, 'Attendance')
            pdf.drawString(430, line_y, 'Avg Marks')
            pdf.drawString(500, line_y, 'Result')
            line_y -= 14
            pdf.setFont('Helvetica', 9)

        pdf.drawString(40, line_y, str(s.usn))
        pdf.drawString(120, line_y, s.name[:24])
        pdf.drawString(330, line_y, f"{s.attendance:.2f}%")
        pdf.drawString(430, line_y, f"{s.marks:.2f}")
        pdf.drawString(520, line_y, s.result())
        line_y -= 18

    pdf.save()
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name='student_report.pdf',
        mimetype='application/pdf'
    )


# ==========================
# STUDENT REPORT PDF
# ==========================
@app.route('/student_report/<int:id>')
@login_required(role='teacher')
def student_report(id):
    student_obj = Student.query.get_or_404(id)
    pdf_data = generate_student_report_pdf(student_obj)
    return send_file(
        io.BytesIO(pdf_data),
        as_attachment=True,
        download_name=f"{student_obj.name.replace(' ', '_')}_report.pdf",
        mimetype='application/pdf'
    )


# ==========================
# EMAIL SINGLE STUDENT REPORT
# ==========================
@app.route('/email_student_report/<int:id>')
@login_required(role='teacher')
def email_student_report(id):
    student_obj = Student.query.get_or_404(id)
    recipients = [email for email in [student_obj.email, student_obj.parent_email] if email]

    if not recipients:
        flash('No student or parent email is configured for this student.', 'warning')
        return redirect(url_for('teacher_dashboard'))

    pdf_data = generate_student_report_pdf(student_obj)
    subject = f"Performance Report for {student_obj.name}"
    body = (
        f"Hello {student_obj.name},\n\n"
        "Please find your performance report attached.\n\n"
        f"Rank: {get_student_rank(student_obj)}\n"
        f"Average Marks: {student_obj.average_marks():.2f}\n"
        f"Attendance: {student_obj.attendance:.2f}%\n"
        f"Remarks: {student_obj.remarks()}\n\n"
        "Regards,\n"
        "Academic Team"
    )

    try:
        send_email_message(subject, body, recipients, pdf_data, f"{student_obj.name.replace(' ', '_')}_report.pdf")
        flash(f"Report emailed to {', '.join(recipients)}.", 'success')
    except Exception as exc:
        flash(f'Error sending report: {exc}', 'danger')

    return redirect(url_for('teacher_dashboard'))


# ==========================
# MONTHLY EMAIL REPORTS
# ==========================
@app.route('/send_monthly_reports')
@login_required(role='teacher')
def send_monthly_reports():
    try:
        sent_count, errors = dispatch_monthly_report_emails()
        if sent_count:
            flash(f'Successfully emailed monthly reports for {sent_count} students.', 'success')
        if errors:
            flash('Some reports could not be sent: ' + '; '.join(errors[:3]), 'warning')
    except Exception as exc:
        flash(f'Failed to send monthly reports: {exc}', 'danger')

    return redirect(url_for('teacher_dashboard'))


# ==========================
# RUN APP
# ==========================
if __name__ == "__main__":
    if os.environ.get('WERKZEUG_RUN_MAIN') == 'true' or not app.debug:
        schedule_monthly_reports()
    app.run(debug=True)