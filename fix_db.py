from app import app, db, Teacher
app.app_context().push()
deleted = Teacher.query.filter_by(email=None).delete()
db.session.commit()
print(f"Deleted {deleted} phantom teacher records.")
