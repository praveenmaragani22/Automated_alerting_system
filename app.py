import os
import urllib.parse
import secrets
from flask import Flask, render_template, request, redirect, flash, session, url_for, jsonify
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from bson.objectid import ObjectId
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.mongodb import MongoDBJobStore
import smtplib
from email.message import EmailMessage
import pytz

# Load environment variables
load_dotenv()

app = Flask(__name__, template_folder=os.path.abspath('.'))
app.secret_key = os.getenv("SECRET_KEY", "default_secret_key")

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

# APScheduler setup
jobstores = {
    'default': MongoDBJobStore(database='alerting_system', collection='scheduled_jobs', client=mongo.cx)
}
scheduler = BackgroundScheduler(jobstores=jobstores, timezone=pytz.UTC)
scheduler.start()

_indexes_created = False

# ---------------------- Utility Functions ----------------------

def send_email(to, subject, content, html_content=None):
    msg = EmailMessage()
    msg.set_content(content)
    if html_content:
        msg.add_alternative(html_content, subtype='html')

    msg['Subject'] = subject
    msg['From'] = f"Automated Alert System <{EMAIL_ADDRESS}>"
    msg['To'] = to
    msg['Reply-To'] = EMAIL_ADDRESS
    msg['X-Mailer'] = 'Python'
    msg['Precedence'] = 'bulk'
    msg['MIME-Version'] = '1.0'
    msg['Content-Type'] = 'text/plain; charset=utf-8'
    msg['List-Unsubscribe'] = f'<{APP_DOMAIN}/unsubscribe?email={to}>'

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
        print(f"Email sent to {to}")
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

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

def schedule_task_emails(task):
    try:
        task_datetime_str = f"{task['task_date']} {task['task_time']}"
        local_tz = pytz.timezone('UTC')
        naive_datetime = datetime.strptime(task_datetime_str, "%Y-%m-%d %H:%M")
        local_datetime = local_tz.localize(naive_datetime)
        utc_datetime = local_datetime.astimezone(pytz.UTC)

        email = task['email']
        name = task['name']
        task_name = task['task_name']
        task_id = str(task['_id'])

        scheduler.remove_job(f"{task_id}_1hour", jobstore=None)
        scheduler.remove_job(f"{task_id}_now", jobstore=None)
        scheduler.remove_job(f"{task_id}_1hour_after", jobstore=None)

        email_content = f"""
        Hello {name},

        This is a reminder about your task: {task_name}

        Task Time: {task_datetime_str}

        ---
        Automated Alert System
        """

        scheduler.add_job(
            send_email, 'date',
            run_date=utc_datetime - timedelta(hours=1),
            args=[email, f"Reminder: {task_name} in 1 hour", email_content],
            id=f"{task_id}_1hour"
        )

        scheduler.add_job(
            send_email, 'date',
            run_date=utc_datetime,
            args=[email, f"Time to start: {task_name}", email_content],
            id=f"{task_id}_now"
        )

        scheduler.add_job(
            send_email, 'date',
            run_date=utc_datetime + timedelta(hours=1),
            args=[email, f"Follow up: {task_name}", email_content],
            id=f"{task_id}_1hour_after"
        )

        print(f"Scheduled emails for task {task_name} at {utc_datetime}")
    except Exception as e:
        print(f"Error scheduling task emails: {e}")

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
            mongo.db.password_reset_otp.create_index([("expires_at", 1)], expireAfterSeconds=0)
            _indexes_created = True
            print("Indexes created")
        except Exception as e:
            print(f"Index creation failed: {e}")

# ---------------------- Routes ----------------------

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
            "password": hashed_password,
            "created_at": datetime.now(pytz.UTC)
        })

        login_token = generate_login_token(email)
        login_url = f"{APP_DOMAIN}/login?token={login_token}"

        subject = "Welcome to Automated Alert System"
        text_content = f"""
        Hi {name},

        Thanks for registering!

        Login directly using this link (valid for 24 hours): {login_url}
        """
        html_content = f"""
        <html>
            <body>
                <p>Hi {name},</p>
                <p>Thanks for registering!</p>
                <p><a href="{login_url}">Click here to login</a> (valid for 24 hours)</p>
            </body>
        </html>
        """

        send_email(email, subject, text_content, html_content)

        return jsonify({"success": True, "message": "Registration successful! Check your email."})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        user = mongo.db.users.find_one({'email': email})
        if user and check_password_hash(user['password'], password):
            session['user_id'] = str(user['_id'])
            session['email'] = user['email']
            session['name'] = user['name']
            return jsonify({'success': True, 'message': 'Logged in successfully'})
        else:
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

    # GET: Login via token
    token = request.args.get('token')
    if not token:
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
    session['email'] = user['email']
    session['name'] = user['name']
    flash("Logged in successfully")
    return redirect(url_for('dashboard'))

@app.route('/forgotpassword', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'GET':
        return render_template("forgotpassword.html")

    data = request.get_json()
    email = data.get('email')

    user = mongo.db.users.find_one({'email': email})
    if not user:
        return jsonify({'success': False, 'message': 'Email not found'}), 404

    otp = f"{secrets.randbelow(1000000):06d}"
    expiry = datetime.now(pytz.UTC) + timedelta(minutes=10)

    mongo.db.password_reset_otp.update_one(
        {'email': email},
        {'$set': {'otp': otp, 'expires_at': expiry, 'verified': False}},
        upsert=True
    )

    subject = "Password Reset OTP"
    text = f"Your OTP is {otp}. It expires in 10 minutes."
    html = f"<p>Your OTP is <b>{otp}</b>. It expires in 10 minutes.</p>"

    if send_email(email, subject, text, html):
        return jsonify({'success': True, 'message': 'OTP sent to your email'})
    return jsonify({'success': False, 'message': 'Failed to send OTP'}), 500

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')

    record = mongo.db.password_reset_otp.find_one({'email': email})
    if not record or record['otp'] != otp or datetime.now(pytz.UTC) > record['expires_at']:
        return jsonify({'success': False, 'message': 'Invalid or expired OTP'}), 400

    mongo.db.password_reset_otp.update_one({'email': email}, {'$set': {'verified': True}})
    return jsonify({'success': True, 'message': 'OTP verified'})

@app.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email = data.get('email')
    new_password = data.get('new_password')

    record = mongo.db.password_reset_otp.find_one({'email': email})
    if not record or not record.get('verified'):
        return jsonify({'success': False, 'message': 'OTP not verified'}), 400

    hashed_password = generate_password_hash(new_password)
    mongo.db.users.update_one({'email': email}, {'$set': {'password': hashed_password}})
    mongo.db.password_reset_otp.delete_one({'email': email})

    return jsonify({'success': True, 'message': 'Password reset successful'})

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return f"Welcome {session['name']}! Dashboard under construction."

# ---------------------- Startup Task Rescheduling ----------------------

if __name__ == '__main__':
    with app.app_context():
        tasks = mongo.db.tasks.find({
            "deleted": {"$ne": True},
            "task_date": {"$gte": datetime.now(pytz.UTC).strftime('%Y-%m-%d')}
        })
        for task in tasks:
            try:
                schedule_task_emails(task)
            except Exception as e:
                print(f"Error rescheduling task: {e}")

    app.run(debug=True)
