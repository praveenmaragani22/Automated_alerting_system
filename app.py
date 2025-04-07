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

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "04e41340029c3ea064efbf45a775f4548c8910637b638f232d9dafd25a43125f")

# MongoDB Atlas Configuration (fallback to localhost if not set)
app.config["MONGO_URI"] = os.getenv("MONGO_URI","mongodb+srv://root:<Praveen@2004>@cluster0.yzhs3nf.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
mongo = PyMongo(app)

# Email Configuration
EMAIL_ADDRESS = os.getenv("EMAIL_USER", "your_email@gmail.com")
EMAIL_PASSWORD = os.getenv("EMAIL_PASS", "your_app_password")

# Background Scheduler
scheduler = BackgroundScheduler()
scheduler.start()

# Ensure indexes for faster lookups
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
        print(f"Error sending email: {e}")

def schedule_task_emails(task):
    try:
        task_datetime_str = f"{task['task_date']} {task['task_time']}"
        task_datetime = datetime.strptime(task_datetime_str, "%Y-%m-%d %H:%M")

        email = task['email']
        name = task['name']
        task_name = task['task_name']

        scheduler.add_job(send_email, 'date', run_date=task_datetime - timedelta(hours=1),
                          args=[email, "1 Hour Left",
                                f"Hey {name}, you have 1 hour left to complete the task: {task_name}"])

        scheduler.add_job(send_email, 'date', run_date=task_datetime,
                          args=[email, "Time to Work",
                                f"Hey {name}, it's time to do your task: {task_name}"])

        scheduler.add_job(send_email, 'date', run_date=task_datetime + timedelta(hours=1),
                          args=[email, "Follow Up",
                                f"Hey {name}, did you complete your task: {task_name}? 1 hour has passed."])

    except Exception as e:
        print(f"Failed to schedule task emails: {e}")

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

        send_email(email, "Registration Successful", f"Hi {name}, you have successfully registered to the Automated Scheduling And Alerting System now you can login And add tasks so,we can send a remainder to you about your task.So there is no anymore chance to Miss your Important Works Any issues feel free to contact us...Thank you..")
        return jsonify({"success": True, "message": "Registration successful! Now you can log in."})

    except Exception as e:
        return jsonify({"success": False, "message": f"An error occurred: {str(e)}"}), 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        identifier = data.get('identifier')
        password = data.get('password')

        user = mongo.db.users.find_one({"$or": [{"email": identifier}, {"phone": identifier}]})

        if user and check_password_hash(user['password'], password):
            session['user_id'] = str(user['_id'])
            session['name'] = user['name']
            session['email'] = user['email']
            return jsonify({"success": True, "message": "Login successful! Redirecting..."})
        else:
            return jsonify({"success": False, "message": "Invalid email/phone or password. Please try again."}), 401

    return render_template("login.html")

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user = mongo.db.users.find_one({"_id": ObjectId(session['user_id'])})
        
        today = datetime.today().strftime('%Y-%m-%d')
        thirty_days_ago = (datetime.today() - timedelta(days=30)).strftime('%Y-%m-%d')

        tasks = list(mongo.db.tasks.find({
            "email": user["email"],
            "task_date": {"$gte": thirty_days_ago},
            "deleted": {"$ne": True}
        }))

        return render_template("dashboard.html", user=user, tasks=tasks)

    flash("Please log in first.", "warning")
    return redirect(url_for('login'))

@app.route('/previous_tasks')
def previous_tasks():
    if 'user_id' in session:
        user = mongo.db.users.find_one({"_id": ObjectId(session['user_id'])})

        thirty_days_ago = (datetime.today() - timedelta(days=30)).strftime('%Y-%m-%d')

        tasks = list(mongo.db.tasks.find({
            "email": user["email"],
            "$or": [
                {"task_date": {"$lt": thirty_days_ago}},  
                {"deleted": True}
            ]
        }))

        return render_template("previous_tasks.html", user=user, tasks=tasks)

    flash("Please log in first.", "warning")
    return redirect(url_for('login'))

@app.route('/addtask', methods=['GET', 'POST'])
def add_task():
    if 'user_id' not in session:
        flash("Please log in first.", "warning")
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

        flash("Task added successfully and notifications scheduled!", "success")
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
    return jsonify({"success": True, "message": "Task marked as complete"}), 200

@app.route('/delete_task/<task_id>', methods=['POST'])
def delete_task(task_id):
    if 'user_id' not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 403

    task = mongo.db.tasks.find_one({"_id": ObjectId(task_id)})
    if not task:
        return jsonify({"success": False, "message": "Task not found"}), 404

    mongo.db.tasks.update_one({"_id": ObjectId(task_id)}, {"$set": {"deleted": True}})
    return jsonify({"success": True, "message": "Task removed from dashboard and stored in previous tasks"}), 200

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
