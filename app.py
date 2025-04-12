import os
import urllib.parse
import secrets
from flask import Flask, render_template_string, request, redirect, flash, session, url_for
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

# Load .env variables
load_dotenv()

app = Flask(__name__)
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

# Configure scheduler
jobstores = {
    'default': MongoDBJobStore(database='alerting_system', collection='scheduled_jobs', client=mongo.cx)
}
scheduler = BackgroundScheduler(jobstores=jobstores, timezone=pytz.UTC)
scheduler.start()

# HTML Templates
INDEX_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Automated Alert System</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        .nav { display: flex; justify-content: space-between; margin-bottom: 20px; }
        .btn { display: inline-block; padding: 10px 15px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; }
        .btn:hover { background: #0056b3; }
        .flash { padding: 10px; background: #f8d7da; color: #721c24; margin-bottom: 20px; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="nav">
        <h1>Automated Alert System</h1>
        <div>
            <a href="/login" class="btn">Login</a>
            <a href="/register" class="btn">Register</a>
        </div>
    </div>
    {% with messages = get_flashed_messages() %}
        {% if messages %}
            <div class="flash">
                {% for message in messages %}
                    <p>{{ message }}</p>
                {% endfor %}
            </div>
        {% endif %}
    {% endwith %}
    <p>Welcome to the Automated Alert System. Register or login to manage your tasks and reminders.</p>
</body>
</html>
"""

LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; }
        input { width: 100%; padding: 8px; box-sizing: border-box; }
        .btn { padding: 10px 15px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; }
        .btn:hover { background: #0056b3; }
        .flash { padding: 10px; background: #f8d7da; color: #721c24; margin-bottom: 20px; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>Login</h1>
    {% with messages = get_flashed_messages() %}
        {% if messages %}
            <div class="flash">
                {% for message in messages %}
                    <p>{{ message }}</p>
                {% endfor %}
            </div>
        {% endif %}
    {% endwith %}
    <form method="POST" action="/login">
        <div class="form-group">
            <label for="email">Email:</label>
            <input type="email" id="email" name="email" required>
        </div>
        <div class="form-group">
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required>
        </div>
        <button type="submit" class="btn">Login</button>
    </form>
    <p>Don't have an account? <a href="/register">Register here</a></p>
    <p><a href="/forgot_password">Forgot password?</a></p>
</body>
</html>
"""

REGISTER_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Register</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; }
        input { width: 100%; padding: 8px; box-sizing: border-box; }
        .btn { padding: 10px 15px; background: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer; }
        .btn:hover { background: #218838; }
        .flash { padding: 10px; background: #f8d7da; color: #721c24; margin-bottom: 20px; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>Register</h1>
    {% with messages = get_flashed_messages() %}
        {% if messages %}
            <div class="flash">
                {% for message in messages %}
                    <p>{{ message }}</p>
                {% endfor %}
            </div>
        {% endif %}
    {% endwith %}
    <form method="POST" action="/register">
        <div class="form-group">
            <label for="name">Full Name:</label>
            <input type="text" id="name" name="name" required>
        </div>
        <div class="form-group">
            <label for="email">Email:</label>
            <input type="email" id="email" name="email" required>
        </div>
        <div class="form-group">
            <label for="phone">Phone:</label>
            <input type="tel" id="phone" name="phone" required>
        </div>
        <div class="form-group">
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required>
        </div>
        <div class="form-group">
            <label for="confirm_password">Confirm Password:</label>
            <input type="password" id="confirm_password" name="confirm_password" required>
        </div>
        <button type="submit" class="btn">Register</button>
    </form>
    <p>Already have an account? <a href="/login">Login here</a></p>
</body>
</html>
"""

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        .nav { display: flex; justify-content: space-between; margin-bottom: 20px; }
        .btn { display: inline-block; padding: 10px 15px; color: white; text-decoration: none; border-radius: 5px; }
        .btn-primary { background: #007bff; }
        .btn-primary:hover { background: #0056b3; }
        .btn-danger { background: #dc3545; }
        .btn-danger:hover { background: #c82333; }
        .btn-success { background: #28a745; }
        .btn-success:hover { background: #218838; }
        .flash { padding: 10px; background: #f8d7da; color: #721c24; margin-bottom: 20px; border-radius: 5px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        .task-form { background: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; }
        input, select { width: 100%; padding: 8px; box-sizing: border-box; }
    </style>
</head>
<body>
    <div class="nav">
        <h1>Welcome, {{ name }}!</h1>
        <div>
            <a href="/logout" class="btn btn-danger">Logout</a>
        </div>
    </div>
    {% with messages = get_flashed_messages() %}
        {% if messages %}
            <div class="flash">
                {% for message in messages %}
                    <p>{{ message }}</p>
                {% endfor %}
            </div>
        {% endif %}
    {% endwith %}
    
    <div class="task-form">
        <h2>Add New Task</h2>
        <form method="POST" action="/add_task">
            <div class="form-group">
                <label for="task_name">Task Name:</label>
                <input type="text" id="task_name" name="task_name" required>
            </div>
            <div class="form-group">
                <label for="task_date">Date:</label>
                <input type="date" id="task_date" name="task_date" required>
            </div>
            <div class="form-group">
                <label for="task_time">Time:</label>
                <input type="time" id="task_time" name="task_time" required>
            </div>
            <button type="submit" class="btn btn-primary">Add Task</button>
        </form>
    </div>
    
    <h2>Your Tasks</h2>
    {% if tasks %}
        <table>
            <thead>
                <tr>
                    <th>Task Name</th>
                    <th>Date</th>
                    <th>Time</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                {% for task in tasks %}
                    <tr>
                        <td>{{ task.task_name }}</td>
                        <td>{{ task.task_date }}</td>
                        <td>{{ task.task_time }}</td>
                        <td>
                            <a href="/delete_task/{{ task._id }}" class="btn btn-danger">Delete</a>
                        </td>
                    </tr>
                {% endfor %}
            </tbody>
        </table>
    {% else %}
        <p>No tasks found. Add your first task above.</p>
    {% endif %}
</body>
</html>
"""

FORGOT_PASSWORD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Forgot Password</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; }
        input { width: 100%; padding: 8px; box-sizing: border-box; }
        .btn { padding: 10px 15px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; }
        .btn:hover { background: #0056b3; }
        .flash { padding: 10px; background: #f8d7da; color: #721c24; margin-bottom: 20px; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>Forgot Password</h1>
    {% with messages = get_flashed_messages() %}
        {% if messages %}
            <div class="flash">
                {% for message in messages %}
                    <p>{{ message }}</p>
                {% endfor %}
            </div>
        {% endif %}
    {% endwith %}
    <form method="POST" action="/forgot_password">
        <div class="form-group">
            <label for="email">Email:</label>
            <input type="email" id="email" name="email" required>
        </div>
        <button type="submit" class="btn">Send Reset Link</button>
    </form>
    <p>Remember your password? <a href="/login">Login here</a></p>
</body>
</html>
"""

VERIFY_OTP_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Verify OTP</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; }
        input { width: 100%; padding: 8px; box-sizing: border-box; }
        .btn { padding: 10px 15px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; }
        .btn:hover { background: #0056b3; }
        .flash { padding: 10px; background: #f8d7da; color: #721c24; margin-bottom: 20px; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>Verify OTP</h1>
    {% with messages = get_flashed_messages() %}
        {% if messages %}
            <div class="flash">
                {% for message in messages %}
                    <p>{{ message }}</p>
                {% endfor %}
            </div>
        {% endif %}
    {% endwith %}
    <form method="POST" action="/verify_otp">
        <input type="hidden" name="email" value="{{ email }}">
        <div class="form-group">
            <label for="otp">Enter OTP sent to your email:</label>
            <input type="text" id="otp" name="otp" required>
        </div>
        <button type="submit" class="btn">Verify OTP</button>
    </form>
</body>
</html>
"""

RESET_PASSWORD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Reset Password</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; }
        input { width: 100%; padding: 8px; box-sizing: border-box; }
        .btn { padding: 10px 15px; background: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer; }
        .btn:hover { background: #218838; }
        .flash { padding: 10px; background: #f8d7da; color: #721c24; margin-bottom: 20px; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>Reset Password</h1>
    {% with messages = get_flashed_messages() %}
        {% if messages %}
            <div class="flash">
                {% for message in messages %}
                    <p>{{ message }}</p>
                {% endfor %}
            </div>
        {% endif %}
    {% endwith %}
    <form method="POST" action="/reset_password">
        <input type="hidden" name="email" value="{{ email }}">
        <div class="form-group">
            <label for="new_password">New Password:</label>
            <input type="password" id="new_password" name="new_password" required>
        </div>
        <div class="form-group">
            <label for="confirm_password">Confirm Password:</label>
            <input type="password" id="confirm_password" name="confirm_password" required>
        </div>
        <button type="submit" class="btn">Reset Password</button>
    </form>
</body>
</html>
"""

# Helper functions
def send_email(to, subject, content, html_content=None):
    msg = EmailMessage()
    msg.set_content(content)
    if html_content:
        msg.add_alternative(html_content, subtype='html')
    
    msg['Subject'] = subject
    msg['From'] = f"Automated Alert System <{EMAIL_ADDRESS}>"
    msg['To'] = to
    msg['Reply-To'] = EMAIL_ADDRESS

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
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
        naive_datetime = datetime.strptime(task_datetime_str, "%Y-%m-%d %H:%M")
        local_datetime = pytz.UTC.localize(naive_datetime)
        
        email = task['email']
        name = task['name']
        task_name = task['task_name']
        task_id = str(task['_id'])

        # Remove existing jobs
        scheduler.remove_job(f"{task_id}_1hour")
        scheduler.remove_job(f"{task_id}_now")
        scheduler.remove_job(f"{task_id}_1hour_after")

        # Schedule new jobs
        email_content = f"Reminder for your task: {task_name} at {task_datetime_str}"
        
        scheduler.add_job(
            send_email,
            'date',
            run_date=local_datetime - timedelta(hours=1),
            args=[email, f"Reminder: {task_name} in 1 hour", email_content],
            id=f"{task_id}_1hour"
        )

        scheduler.add_job(
            send_email,
            'date',
            run_date=local_datetime,
            args=[email, f"Time to start: {task_name}", email_content],
            id=f"{task_id}_now"
        )

        scheduler.add_job(
            send_email,
            'date',
            run_date=local_datetime + timedelta(hours=1),
            args=[email, f"Follow up: {task_name}", email_content],
            id=f"{task_id}_1hour_after"
        )

    except Exception as e:
        print(f"Failed to schedule task emails: {e}")

@app.before_request
def setup_indexes():
    try:
        mongo.db.users.create_index("email", unique=True)
        mongo.db.users.create_index("phone", unique=True)
        mongo.db.tasks.create_index("task_name")
        mongo.db.login_tokens.create_index("token", unique=True)
        mongo.db.login_tokens.create_index([("expires_at", 1)], expireAfterSeconds=0)
        mongo.db.password_reset_otp.create_index([("expires_at", 1)], expireAfterSeconds=0)
    except Exception as e:
        print(f"Index setup failed: {e}")

# Routes
@app.route('/')
def home():
    return render_template_string(INDEX_HTML)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        token = request.args.get('token')
        if token:
            token_data = mongo.db.login_tokens.find_one({
                'token': token,
                'used': False,
                'expires_at': {'$gt': datetime.now(pytz.UTC)}
            })
            
            if token_data:
                user = mongo.db.users.find_one({'email': token_data['email']})
                if user:
                    mongo.db.login_tokens.update_one(
                        {'_id': token_data['_id']},
                        {'$set': {'used': True}}
                    )
                    session['user_id'] = str(user['_id'])
                    session['name'] = user['name']
                    session['email'] = user['email']
                    flash("Logged in successfully!")
                    return redirect(url_for('dashboard'))
        
        return render_template_string(LOGIN_HTML)
    
    email = request.form.get('email')
    password = request.form.get('password')
    
    user = mongo.db.users.find_one({'email': email})
    
    if not user or not check_password_hash(user['password'], password):
        flash('Invalid email or password')
        return redirect(url_for('login'))
    
    session['user_id'] = str(user['_id'])
    session['name'] = user['name']
    session['email'] = user['email']
    
    return redirect(url_for('dashboard'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template_string(REGISTER_HTML)
    
    name = request.form.get('name')
    email = request.form.get('email')
    phone = request.form.get('phone')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')

    if password != confirm_password:
        flash("Passwords don't match")
        return redirect(url_for('register'))

    try:
        existing_user = mongo.db.users.find_one({"$or": [{"email": email}, {"phone": phone}]})
        if existing_user:
            flash("User already registered. Please log in.")
            return redirect(url_for('login'))

        hashed_password = generate_password_hash(password)
        mongo.db.users.insert_one({
            "name": name,
            "email": email,
            "phone": phone,
            "password": hashed_password,
            "verified": False,
            "created_at": datetime.now(pytz.UTC)
        })

        login_token = generate_login_token(email)
        login_url = f"{APP_DOMAIN}/login?token={login_token}"
        
        subject = "Welcome to Automated Alert System"
        text_content = f"Hi {name},\n\nUse this link to login: {login_url}"
        
        send_email(email, subject, text_content)

        flash("Registration successful! Check your email for login instructions.")
        return redirect(url_for('login'))
    except Exception as e:
        flash(f"Error: {str(e)}")
        return redirect(url_for('register'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_tasks = list(mongo.db.tasks.find({
        'user_id': session['user_id'],
        'deleted': {'$ne': True}
    }))
    
    return render_template_string(DASHBOARD_HTML, tasks=user_tasks, name=session['name'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'GET':
        return render_template_string(FORGOT_PASSWORD_HTML)
    
    email = request.form.get('email')
    user = mongo.db.users.find_one({'email': email})
    
    if not user:
        flash("Email not found")
        return redirect(url_for('forgot_password'))
    
    otp = secrets.randbelow(1000000)
    otp_str = f"{otp:06d}"
    otp_expiry = datetime.now(pytz.UTC) + timedelta(minutes=10)

    mongo.db.password_reset_otp.update_one(
        {'email': email},
        {'$set': {
            'otp': otp_str,
            'expires_at': otp_expiry,
            'verified': False
        }},
        upsert=True
    )

    subject = "Your Password Reset OTP"
    text = f"Your OTP is: {otp_str}. Valid for 10 minutes."
    
    if send_email(email, subject, text):
        flash("OTP sent to your email")
        return render_template_string(VERIFY_OTP_HTML, email=email)
    else:
        flash("Failed to send email")
        return redirect(url_for('forgot_password'))

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    email = request.form.get('email')
    otp = request.form.get('otp')

    record = mongo.db.password_reset_otp.find_one({'email': email})
    if not record or record['otp'] != otp or datetime.now(pytz.UTC) > record['expires_at']:
        flash("Invalid or expired OTP")
        return render_template_string(VERIFY_OTP_HTML, email=email)
    
    mongo.db.password_reset_otp.update_one({'email': email}, {'$set': {'verified': True}})
    return render_template_string(RESET_PASSWORD_HTML, email=email)

@app.route('/reset_password', methods=['POST'])
def reset_password():
    email = request.form.get('email')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if new_password != confirm_password:
        flash("Passwords don't match")
        return render_template_string(RESET_PASSWORD_HTML, email=email)
    
    record = mongo.db.password_reset_otp.find_one({'email': email})
    if not record or not record.get('verified'):
        flash("OTP not verified")
        return redirect(url_for('forgot_password'))
    
    hashed_password = generate_password_hash(new_password)
    mongo.db.users.update_one({'email': email}, {'$set': {'password': hashed_password}})
    mongo.db.password_reset_otp.delete_one({'email': email})

    flash("Password reset successfully")
    return redirect(url_for('login'))

@app.route('/add_task', methods=['POST'])
def add_task():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    task_name = request.form.get('task_name')
    task_date = request.form.get('task_date')
    task_time = request.form.get('task_time')
    
    task = {
        'user_id': session['user_id'],
        'name': session['name'],
        'email': session['email'],
        'task_name': task_name,
        'task_date': task_date,
        'task_time': task_time,
        'created_at': datetime.now(pytz.UTC),
        'deleted': False
    }
    
    result = mongo.db.tasks.insert_one(task)
    task['_id'] = result.inserted_id
    
    schedule_task_emails(task)
    
    flash("Task added successfully!")
    return redirect(url_for('dashboard'))

@app.route('/delete_task/<task_id>')
def delete_task(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    mongo.db.tasks.update_one(
        {'_id': ObjectId(task_id), 'user_id': session['user_id']},
        {'$set': {'deleted': True}}
    )
    
    scheduler.remove_job(f"{task_id}_1hour")
    scheduler.remove_job(f"{task_id}_now")
    scheduler.remove_job(f"{task_id}_1hour_after")
    
    flash("Task deleted successfully!")
    return redirect(url_for('dashboard'))

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
                print(f"Error rescheduling task {task['_id']}: {e}")
    
    app.run(debug=True)
