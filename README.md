# Student ERP — Academic Performance Management System

A production-ready Flask web application for managing student academic records, attendance, quizzes, and performance analytics.

## Features

- **Teacher Portal**: Full student CRUD, bulk attendance marking, announcements, subject analytics, PDF/Excel exports, email reports
- **Student Portal**: Dashboard with grades/attendance, AI doubt-solver chat, mock quizzes, profile management, announcements
- **Security**: Password-hashed authentication for both roles, CSRF protection, session security, rate-limited login
- **Reports**: Individual and batch PDF report generation, Excel export, monthly email report scheduling
- **Analytics**: Subject-wise performance charts (Chart.js), attendance tracking, rank lists, grade distributions

## Quick Start

```bash
# 1. Create virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment
# Edit .env with your settings (see .env for guidance)

# 4. Run the application
python app.py
```

The app starts at **http://127.0.0.1:5000**

## First-Time Setup

1. Navigate to **Instructor Login** and click **Register**
2. Create your teacher account with name, email, and password
3. Login and start adding students (default student password: `changeme`)
4. Students log in with their USN + password

## Environment Variables

| Variable | Description | Required |
|---|---|---|
| `SECRET_KEY` | Flask session secret (auto-generated if missing) | Auto |
| `OPENAI_API_KEY` | OpenAI key for AI chat feature | Optional |
| `MAIL_SERVER` | SMTP server (e.g. `smtp.gmail.com`) | Optional |
| `MAIL_PORT` | SMTP port (default `587`) | Optional |
| `MAIL_USERNAME` | SMTP login email | Optional |
| `MAIL_PASSWORD` | SMTP login password / app password | Optional |

## Tech Stack

- **Backend**: Flask, SQLAlchemy, SQLite
- **Frontend**: Jinja2 templates, vanilla CSS, Chart.js
- **Reports**: ReportLab (PDF), Pandas + openpyxl (Excel)
- **Email**: Python stdlib `smtplib` + `email`
