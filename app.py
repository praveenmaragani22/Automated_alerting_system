import os
from flask import Flask, render_template, request, redirect, flash, session, url_for, jsonify
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from bson.objectid import ObjectId
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
import smtplib
from email.message import EmailMessage

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "default_secret_key")

# MongoDB config
app.config["MONGO_URI"] = os.getenv("MONGO_URI")
mongo = PyMongo(app)

if mongo.db is None:
    raise Exception("MongoDB connection failed. Check your MONGO_URI and network access.")

# Email Config
EMAIL_ADDRESS = os.getenv("EMAIL_USER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASS")

# Scheduler
scheduler = BackgroundScheduler()
scheduler.start()

# Create indexes
mongo.db.users.create_index("email", unique=True)
mongo.db.users.create_index("phone", unique=True)
mongo.db.tasks.create_index("task_name")

def send_email(to, subject, content):
    msg = EmailMessage()
    msg.set_content(content)
    msg['Subject'] = subject
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = to

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
    except Exception as e:
        print(f"Email sending error: {e}")

def schedule_task_emails(task):
    try:
        task_datetime = datetime.strptime(f"{task['task_date']} {task['task_time']}", "%Y-%m-%d %H:%M")
        email, name, task_name = task['email'], task['name'], task['task_name']

        scheduler.add_job(send_email, 'date', run_date=task_datetime - timedelta(hours=1),
                          args=[email, "1 Hour Left", f"Hey {name}, 1 hour left for task: {task_name}"])

        scheduler.add_job(send_email, 'date', run_date=task_datetime,
                          args=[email, "Time to Work", f"Hey {name}, it's time to do your task: {task_name}"])

        scheduler.add_job(send_email, 'date', run_date=task_datetime + timedelta(hours=1),
                          args=[email, "Follow Up", f"Hey {name}, did you finish: {task_name}? 1 hour passed."])

    except Exception as e:
        print(f"Scheduling error: {e}")

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template("register.html")

    data = request.get_json()
    name, email, phone, password = data.get('name'), data.get('email'), data.get('phone'), data.get('password')

    try:
        if mongo.db.users.find_one({"$or": [{"email": email}, {"phone": phone}]}):
            return jsonify({"success": False, "message": "User already registered."}), 400

        hashed_password = generate_password_hash(password)
        mongo.db.users.insert_one({
            "name": name,
            "email": email,
            "phone": phone,
            "password": hashed_password
        })

        send_email(email, "Registration Successful",
                   f"Hi {name}, you've registered successfully! Add your tasks and we'll remind you on time!")

        return jsonify({"success": True, "message": "Registration successful!"})

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        identifier, password = data.get('identifier'), data.get('password')

        user = mongo.db.users.find_one({"$or": [{"email": identifier}, {"phone": identifier}]})
        if user and check_password_hash(user['password'], password):
            session['user_id'] = str(user['_id'])
            session['name'] = user['name']
            session['email'] = user['email']
            return jsonify({"success": True, "message": "Login successful!"})
        else:
            return jsonify({"success": False, "message": "Invalid credentials."}), 401

    return render_template("login.html")

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please log in.", "warning")
        return redirect(url_for('login'))

    user = mongo.db.users.find_one({"_id": ObjectId(session['user_id'])})
    today = datetime.today().strftime('%Y-%m-%d')
    thirty_days_ago = (datetime.today() - timedelta(days=30)).strftime('%Y-%m-%d')

    tasks = list(mongo.db.tasks.find({
        "email": user["email"],
        "task_date": {"$gte": thirty_days_ago},
        "deleted": {"$ne": True}
    }))

    return render_template("dashboard.html", user=user, tasks=tasks)

@app.route('/previous_tasks')
def previous_tasks():
    if 'user_id' not in session:
        flash("Please log in.", "warning")
        return redirect(url_for('login'))

    user = mongo.db.users.find_one({"_id": ObjectId(session['user_id'])})
    thirty_days_ago = (datetime.today() - timedelta(days=30)).strftime('%Y-%m-%d')

    tasks = list(mongo.db.tasks.find({
        "email": user["email"],
        "$or": [{"task_date": {"$lt": thirty_days_ago}}, {"deleted": True}]
    }))

    return render_template("previous_tasks.html", user=user, tasks=tasks)

@app.route('/addtask', methods=['GET', 'POST'])
def add_task():
    if 'user_id' not in session:
        flash("Please log in.", "warning")
        return redirect(url_for('login'))

    user = mongo.db.users.find_one({"_id": ObjectId(session['user_id'])})

    if request.method == 'POST':
        task_name = request.form['task_name']
        task_date = request.form['task_date']
        task_time = request.form['task_time']

        mongo.db.tasks.insert_one({
            "name": user["name"],
            "email": user["email"],
            "task_name": task_name,
            "task_date": task_date,
            "task_time": task_time,
            "status": "Pending",
            "delete_after": (datetime.today() + timedelta(days=30)).strftime('%Y-%m-%d')
        })

        task = mongo.db.tasks.find_one({
            "email": user["email"],
            "task_name": task_name,
            "task_date": task_date,
            "task_time": task_time
        })

        schedule_task_emails(task)

        flash("Task added and scheduled!", "success")
        return redirect(url_for('dashboard'))

    return render_template("addtask.html", user=user)

@app.route('/complete_task/<task_id>', methods=['POST'])
def complete_task(task_id):
    if 'user_id' not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 403

    task = mongo.db.tasks.find_one({"_id": ObjectId(task_id)})
    if not task:
        return jsonify({"success": False, "message": "Task not found"}), 404

    mongo.db.tasks.update_one({"_id": ObjectId(task_id)}, {"$set": {"status": "Completed"}})
    return jsonify({"success": True, "message": "Task marked complete"}), 200

@app.route('/delete_task/<task_id>', methods=['POST'])
def delete_task(task_id):
    if 'user_id' not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 403

    task = mongo.db.tasks.find_one({"_id": ObjectId(task_id)})
    if not task:
        return jsonify({"success": False, "message": "Task not found"}), 404

    mongo.db.tasks.update_one({"_id": ObjectId(task_id)}, {"$set": {"deleted": True}})
    return jsonify({"success": True, "message": "Task marked as deleted"}), 200

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
