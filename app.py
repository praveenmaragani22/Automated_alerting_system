import os
import urllib.parse
import secrets
import random
import string
from flask import Flask, render_template, request, redirect, flash, session, url_for, jsonify
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from bson.objectid import ObjectId
from datetime import datetime, timedelta, timezone
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.mongodb import MongoDBJobStore
import smtplib
from email.message import EmailMessage
import pytz
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Load environment variables
load_dotenv()

app = Flask(__name__, template_folder=os.path.abspath('.'))
app.secret_key = os.getenv("SECRET_KEY", "default_secret_key")
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Encode MongoDB credentials
username = urllib.parse.quote_plus(os.getenv("MONGO_USER"))
password = urllib.parse.quote_plus(os.getenv("MONGO_PASS"))

# MongoDB URI
mongo_uri = f"mongodb+srv://{username}:{password}@cluster0.yzhs3nf.mongodb.net/alerting_system?retryWrites=true&w=majority&appName=Cluster0"
app.config["MONGO_URI"] = mongo_uri
mongo = PyMongo(app)

# Email config
EMAIL_ADDRESS = os.getenv("EMAIL_USER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASS")
APP_DOMAIN = os.getenv("APP_DOMAIN", "http://localhost:5000")

# Scheduler setup with MongoDB store
jobstores = {
    'default': MongoDBJobStore(database='alerting_system', collection='scheduled_jobs', client=mongo.cx)
}
scheduler = BackgroundScheduler(jobstores=jobstores, timezone=pytz.UTC)
scheduler.start()

_indexes_created = False  # index setup tracker

# Send email function
def send_email(to, subject, content, html_content=None):
    msg = EmailMessage()
    msg.set_content(content)
    if html_content:
        msg.add_alternative(html_content, subtype='html')

    msg['Subject'] = subject
    msg['From'] = f"Automated Alert System <{EMAIL_ADDRESS}>"
    msg['To'] = to

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
        print(f"Email sent to {to}")
        return True
    except Exception as e:
        print(f"Email send failed: {e}")
        return False

# Generate one-time login token
def generate_login_token(email):
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(pytz.UTC) + timedelta(hours=24)

    mongo.db.login_tokens.insert_one({
        'email': email,
        'token': token,
        'expires_at': expires_at,
        'used': False
    })

    return token

# Schedule task email reminders
def schedule_task_emails(task):
    try:
        task_datetime_str = f"{task['task_date']} {task['task_time']}"
        utc_datetime = datetime.strptime(task_datetime_str, "%Y-%m-%d %H:%M").replace(tzinfo=pytz.UTC)

        email = task['email']
        name = task['name']
        task_name = task['task_name']
        task_id = str(task['_id'])

        for suffix in ['1hour', 'now', '1hour_after']:
            try:
                scheduler.remove_job(f"{task_id}_{suffix}")
            except Exception:
                pass

        content = f"""
        Hello {name},

        This is a reminder for your task: {task_name}
        Scheduled at: {task_datetime_str}

        - Automated Alert System
        """

        scheduler.add_job(send_email, 'date', run_date=utc_datetime - timedelta(hours=1),
                          args=[email, f"Reminder: {task_name} in 1 hour", content], id=f"{task_id}_1hour")

        scheduler.add_job(send_email, 'date', run_date=utc_datetime,
                          args=[email, f"Time to start: {task_name}", content], id=f"{task_id}_now")

        scheduler.add_job(send_email, 'date', run_date=utc_datetime + timedelta(hours=1),
                          args=[email, f"Follow up: {task_name}", content], id=f"{task_id}_1hour_after")

    except Exception as e:
        print(f"Task scheduling failed: {e}")

@app.before_request
def setup_indexes():
    global _indexes_created
    if not _indexes_created and not request.path.startswith('/static'):
        try:
            mongo.db.users.create_index("email", unique=True)
            mongo.db.users.create_index("phone", unique=True)
            mongo.db.tasks.create_index("task_name")
            mongo.db.login_tokens.create_index("token", unique=True)
            mongo.db.login_tokens.create_index([("expires_at", 1)], expireAfterSeconds=0)
            mongo.db.password_reset_otp.create_index("email")
            mongo.db.password_reset_otp.create_index([("expires_at", 1)], expireAfterSeconds=0)
            _indexes_created = True
            print("Indexes created.")
        except Exception as e:
            print(f"Index creation failed: {e}")

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template("register.html")

    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    phone = data.get('phone')
    password = data.get('password')

    try:
        existing_user = mongo.db.users.find_one({"$or": [{"email": email}, {"phone": phone}]})
        if existing_user:
            return jsonify({"success": False, "message": "User already registered. Please log in."}), 400

        hashed_password = generate_password_hash(password)
        mongo.db.users.insert_one({
            "name": name,
            "email": email,
            "phone": phone,
            "password": hashed_password
        })

        login_url = "https://automatedschedulingandalertingsystemguni.onrender.com/login"
        email_body = f"""
        Hi {name},
        
        Thank you for registering to the Automated Scheduling and Alerting System!
        
        You can now log in here: {login_url}
        
        Best regards,
        Your Team
        """
        
        send_email(email, "Registration Successful", email_body)
        return jsonify({"success": True, "message": "Registration successful! Check your email for the login link."})

    except Exception as e:
        return jsonify({"success": False, "message": f"An error occurred: {str(e)}"}), 500

@app.route('/login')
def login():
    token = request.args.get('token')
    if not token:
        flash("Invalid login link")
        return render_template("login.html")

    token_data = mongo.db.login_tokens.find_one({
        'token': token,
        'used': False,
        'expires_at': {'$gt': datetime.now(pytz.UTC)}
    })

    if not token_data:
        flash("Invalid or expired login link")
        return render_template("login.html")

    user = mongo.db.users.find_one({'email': token_data['email']})
    if not user:
        flash("User not found")
        return render_template("login.html")

    mongo.db.login_tokens.update_one({'_id': token_data['_id']}, {'$set': {'used': True}})
    session['user_id'] = str(user['_id'])
    session['name'] = user['name']
    session['email'] = user['email']
    flash("Logged in successfully!")
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please log in first.")
        return redirect(url_for('home'))
    return f"Welcome {session['name']}! (Dashboard Coming Soon)"

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'GET':
        return render_template("forgotpassword.html")
    
    data = request.get_json()
    email = data.get('email')
    
    user = mongo.db.users.find_one({"email": email})
    if not user:
        return jsonify({"success": False, "message": "Email not registered."}), 404

    otp = f"{random.randint(0, 999999):06d}"
    otp_expiry = datetime.now(pytz.UTC) + timedelta(minutes=5)

    mongo.db.password_reset_otp.update_one(
        {'email': email},
        {'$set': {
            'otp': otp,
            'expires_at': otp_expiry,
            'verified': False
        }},
        upsert=True
    )

    send_email(email, "Password Reset OTP", f"Hi {user['name']},\n\nYour OTP is: {otp}\n\nValid for 5 minutes.")
    return jsonify({"success": True, "message": "OTP sent to your email."})

@app.route('/verify-otp', methods=['POST'])
@limiter.limit("5 per minute")
def verify_otp():
    try:
        data = request.get_json()
        email = data.get('email')
        user_otp = data.get('otp')

        if not all([email, user_otp]):
            return jsonify({"success": False, "message": "Email and OTP are required"}), 400

        otp_record = mongo.db.password_reset_otp.find_one(
            {"email": email},
            sort=[("expires_at", -1)]
        )

        if not otp_record:
            return jsonify({"success": False, "message": "No OTP found for this email"}), 404

        if datetime.now(timezone.utc) > otp_expiry:
            return jsonify({"success": False, "message": "OTP has expired"}), 401

        if user_otp != otp_record['otp']:
            return jsonify({"success": False, "message": "Invalid OTP"}), 401

        mongo.db.password_reset_otp.update_one(
            {"_id": otp_record["_id"]},
            {"$set": {"verified": True}}
        )

        return jsonify({"success": True, "message": "OTP verified successfully"})

    except Exception as e:
        app.logger.error(f"OTP Verification Error: {str(e)}")
        return jsonify({"success": False, "message": "An error occurred during OTP verification"}), 500

@app.route('/reset-password', methods=['POST'])
def reset_password():
    try:
        data = request.get_json()
        email = data.get('email')
        new_password = data.get('new_password')

        if not all([email, new_password]):
            return jsonify({"success": False, "message": "Email and new password are required"}), 400

        record = mongo.db.password_reset_otp.find_one({
            'email': email,
            'verified': True
        })
        
        if not record:
            return jsonify({'success': False, 'message': 'OTP not verified'}), 400

        hashed_password = generate_password_hash(new_password)
        mongo.db.users.update_one(
            {'email': email},
            {'$set': {'password': hashed_password}}
        )
        
        mongo.db.password_reset_otp.delete_one({'email': email})

        return jsonify({'success': True, 'message': 'Password reset successfully'})

    except Exception as e:
        app.logger.error(f"Password Reset Error: {str(e)}")
        return jsonify({'success': False, 'message': 'An error occurred during password reset'}), 500

if __name__ == '__main__':
    with app.app_context():
        active_tasks = mongo.db.tasks.find({
            "deleted": {"$ne": True},
            "task_date": {"$gte": datetime.now(pytz.UTC).strftime('%Y-%m-%d')}
        })
        for task in active_tasks:
            try:
                schedule_task_emails(task)
            except Exception as e:
                print(f"Task reschedule failed for {task.get('_id')}: {e}")

    app.run(debug=True)
