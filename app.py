import os
import secrets
from datetime import datetime, timedelta, timezone
import pymongo
import random
import string
import base64
import uuid
import hashlib
import time
import json
import stripe
import uuid
import paypalrestsdk
import hmac
from decimal import Decimal
from datetime import datetime
from pymongo import MongoClient
import requests
import paypalrestsdk
import json
from flask import Flask, render_template, request, redirect, session, url_for, jsonify, flash, get_flashed_messages
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from flask import url_for
from bson import ObjectId
from functools import wraps
from flask import abort
from flask import send_file, abort

# Load environment variables
from dotenv import load_dotenv
load_dotenv() 

def generate_reset_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def verify_reset_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
        return email
    except Exception:
        return False
    # Decorator to protect admin routes
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("is_admin"):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function
def kyc_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_email" not in session:
            return redirect(url_for("login"))
        
        user = users_collection.find_one({"email": session["user_email"]})
        if not user or user.get("kyc_status") != "verified":
            flash("KYC verification required to access this feature.", "warning")
            return redirect(url_for("kyc_verification"))
        
        return f(*args, **kwargs)
    return decorated_function

def ensure_utc_datetime(dt):
    """Ensure a datetime is timezone-aware and in UTC"""
    if dt is None:
        return None
    
    if dt.tzinfo is None:
        # If naive, assume UTC
        return dt.replace(tzinfo=timezone.utc)
    else:
        # If aware, convert to UTC
        return dt.astimezone(timezone.utc)



# Configuration
MONGO_URI = os.getenv("MONGO_URI")
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY")
PAYSTACK_PUBLIC_KEY = os.getenv("PAYSTACK_PUBLIC_KEY")
PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY")
SECURITY_PASSWORD_SALT = os.getenv("SECURITY_PASSWORD_SALT")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")

# Validate configuration
if not MONGO_URI:
    raise ValueError("MONGO_URI is missing.")
if not PAYSTACK_PUBLIC_KEY or not PAYSTACK_SECRET_KEY:
    raise ValueError("Paystack keys are missing.")

# Connect to MongoDB
try:
    client = MongoClient(MONGO_URI)
    db = client["investment_app"]
    users_collection = db["users"]
    coinbase_payments_collection = db["coinbase_payments"]
    paypal_payments_collection = db["paypal_payments"]
    paystack_card_payments_collection = db["paystack_card_payments"]
    card_payments_collection = db["card_payments"]
    paystack_international_payments = db["paystack_international_payments"] 
except pymongo.errors.ConnectionFailure as e:
    print(f"MongoDB Connection Error: {e}")
    exit(1)


# Flask App Configuration
app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY
app.config['SECURITY_PASSWORD_SALT'] = SECURITY_PASSWORD_SALT
# File Upload Configuration
UPLOAD_FOLDER = os.path.abspath("static/uploads/")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# Email Configuration from environment variables
MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp.gmail.com")
MAIL_PORT = int(os.getenv("MAIL_PORT", "587"))
MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "True").lower() == "true"
MAIL_USE_SSL = os.getenv("MAIL_USE_SSL", "False").lower() == "true"
MAIL_USERNAME = os.getenv("MAIL_USERNAME")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")
MAIL_DEFAULT_SENDER_NAME = os.getenv("MAIL_DEFAULT_SENDER_NAME", "Big Winners")
MAIL_DEFAULT_SENDER_EMAIL = os.getenv("MAIL_DEFAULT_SENDER_EMAIL")

# Email Configuration
email_config = {
    'MAIL_SERVER': MAIL_SERVER,
    'MAIL_PORT': MAIL_PORT,
    'MAIL_USE_TLS': MAIL_USE_TLS,
    'MAIL_USE_SSL': MAIL_USE_SSL,
    'MAIL_USERNAME': MAIL_USERNAME,
    'MAIL_PASSWORD': MAIL_PASSWORD,
    'MAIL_DEFAULT_SENDER': (MAIL_DEFAULT_SENDER_NAME, MAIL_DEFAULT_SENDER_EMAIL)
}

# Remove None values from config
email_config = {k: v for k, v in email_config.items() if v is not None}
app.config.update(email_config)
mail = Mail(app)

# PayPal Configuration 
PAYPAL_MODE = os.getenv("PAYPAL_MODE", "live")
PAYPAL_CLIENT_ID = os.getenv("PAYPAL_CLIENT_ID")
PAYPAL_CLIENT_SECRET = os.getenv("PAYPAL_CLIENT_SECRET")
PAYPAL_WEBHOOK_ID = os.getenv("PAYPAL_WEBHOOK_ID")
PAYPAL_MERCHANT_EMAIL = os.getenv("PAYPAL_MERCHANT_EMAIL", "mugokaruirua@gmail.com")  

# Initialize PayPal SDK
paypalrestsdk.configure({
    "mode": PAYPAL_MODE,
    "client_id": PAYPAL_CLIENT_ID,
    "client_secret": PAYPAL_CLIENT_SECRET
})
# Helper Functions
def generate_reset_token(email):
    serializer = URLSafeTimedSerializer(app.secret_key)
    return serializer.dumps(email, salt=app.config["SECURITY_PASSWORD_SALT"])


def verify_reset_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.secret_key)
    try:
        email = serializer.loads(token, salt=app.config["SECURITY_PASSWORD_SALT"], max_age=expiration)
        return email
    except Exception:
        return False
    
# Add KYC collections
kyc_collection = db["kyc_verifications"]

@app.route("/")
def welcome():
    return render_template("welcome.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        try:
            # Collect user input
            required_fields = [
                "fullname", "email", "username", "phone", "country",
                "password", "security_question", "security_answer", "gender"
            ]
            data = {key: request.form.get(key) for key in required_fields}

            # Check for missing fields
            if not all(data.values()):
                flash("Please fill in all required fields.", "danger")
                return redirect(url_for("register"))

            # Terms and Conditions checkbox validation
            if not request.form.get("accept_terms"):
                flash("You must accept the Terms and Conditions.", "danger")
                return redirect(url_for("register"))

            # Check for duplicate entries in MongoDB
            if users_collection.find_one({"email": data["email"]}):
                flash("Email already in use. Please choose a different email.", "danger")
                return redirect(url_for("register"))
            if users_collection.find_one({"username": data["username"]}):
                flash("Username already in use. Please choose a different username.", "danger")
                return redirect(url_for("register"))
            if users_collection.find_one({"phone": data["phone"]}):
                flash("Phone number already in use. Please choose a different phone number.", "danger")
                return redirect(url_for("register"))

            # Hash the password
            data["password"] = generate_password_hash(data["password"], method="scrypt")

            # Add default fields
            data["profile_picture"] = "default.jpg"
            data["initial_investment"] = 0.0
            data["investment_time"] = None
            data["investment_status"] = "none"
            
            # Add KYC status fields
            data["kyc_status"] = "not_verified"
            data["kyc_submitted_at"] = None
            data["kyc_notification_dismissed"] = False
            data["kyc_notification_last_shown"] = None
            
            # Insert the user into MongoDB
            result = users_collection.insert_one(data)
            
            # Update the session
            session.update({
                "user_email": data["email"],
                "user": data["username"],
                "profile_picture": data["profile_picture"],
                "user_id": str(result.inserted_id),
                "kyc_status": "not_verified",  # Add KYC status to session
                "kyc_notification_dismissed": False
            })
            
            flash("Registration successful! Welcome to your dashboard.", "success")
            return redirect(url_for("dashboard"))  # Redirect to dashboard instead of KYC
            
        except Exception as e:
            print(f"Error during registration: {e}")
            flash("An error occurred during registration. Please try again later.", "danger")
            return redirect(url_for("register"))

    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        try:
            email = request.form.get("email")
            password = request.form.get("password")

            if not email or not password:
                flash("Email and password are required.", "danger")
                return redirect(url_for("login"))

            # Find the user by email
            user = users_collection.find_one({"email": email})
            if user and check_password_hash(user["password"], password):
                # Clear existing session
                session.clear()
                
                # Set new session variables
                session["user_id"] = str(user["_id"])
                session["user"] = user["username"]
                session["user_email"] = email
                session["profile_picture"] = user.get("profile_picture", "default.jpg")
                session["kyc_status"] = user.get("kyc_status", "not_verified")
                session["investment_status"] = user.get("investment_status", "none")
                
                # If user is admin, set admin flag
                if user.get("is_admin"):
                    session["is_admin"] = True
                
                flash("Login successful!", "success")
                return redirect(url_for("dashboard"))

            flash("Invalid email or password.", "danger")
            return redirect(url_for("login"))
        except Exception as e:
            print(f"Error during login: {e}")
            flash("An error occurred during login. Please try again later.", "danger")
            return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/check_crypto_payment_status", methods=["GET"])
def check_crypto_payment_status():
    """Check if user has pending crypto payments"""
    if "user_email" not in session:
        return jsonify({"has_pending": False}), 401
    
    try:
        pending_payment = crypto_payments_collection.find_one({
            "user_id": session["user_id"],
            "status": "pending"
        })
        
        return jsonify({
            "has_pending": pending_payment is not None,
            "amount_usd": pending_payment.get("amount_usd", 0) if pending_payment else 0,
            "crypto_type": pending_payment.get("crypto_type", "") if pending_payment else "",
            "submitted_at": pending_payment.get("created_at").isoformat() if pending_payment and pending_payment.get("created_at") else None
        })
    except Exception as e:
        return jsonify({"has_pending": False, "error": str(e)})
@app.route("/index")
def index():
    return render_template("index.html")


@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")
        if not email:
            flash("Email is required", "error")
            return redirect(url_for("forgot_password"))

        user = users_collection.find_one({"email": email})
        if not user:
            # Security: Don't reveal if user exists
            flash("This email does not exist.", "info")
            return redirect(url_for("forgot_password"))

        # Generate token (expires in 1 hour)
        token = generate_reset_token(email)
        reset_url = url_for('reset_password', token=token, _external=True)

        try:
            msg = Message(
                "Password Reset Request",
                recipients=[email],
                sender=app.config["MAIL_DEFAULT_SENDER"]
            )
            
            # Plain text version
            msg.body = f"""Click the link to reset your password:
{reset_url}

If you didn't request this, please ignore this email."""
            
            # HTML version with button
            msg.html = f"""
            <h2>Password Reset Request</h2>
            <p>Click the button below to reset your password:</p>
            <a href="{reset_url}" style="
                background-color: #4CAF50;
                color: white;
                padding: 10px 20px;
                text-decoration: none;
                border-radius: 5px;
                display: inline-block;
            ">Reset Password</a>
            <p>Or copy this link: {reset_url}</p>
            <p><em>This link expires in 1 hour.</em></p>
            """
            
            mail.send(msg)
            flash("Password reset link has been sent to your email", "success")
            return redirect(url_for("forgot_password"))
        
        except Exception as e:
            print(f"Email error: {str(e)}")
            flash("Failed to send reset link. Please try again later.", "error")
            return redirect(url_for("forgot_password"))
    
    return render_template("forgot_password.html")

@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    # Verify token
    email = verify_reset_token(token)
    if not email:
        flash("Invalid or expired reset link", "error")
        return redirect(url_for("forgot_password"))

    user = users_collection.find_one({"email": email})
    if not user:
        flash("User not found", "error")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        if not new_password or new_password != confirm_password:
            flash("Passwords don't match", "error")
            return redirect(url_for("reset_password", token=token))

        # Update password and clear token
        hashed_password = generate_password_hash(new_password)
        users_collection.update_one(
            {"email": email},
            {"$set": {"password": hashed_password}}
        )
        
        flash("Password updated successfully! Please login", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", token=token)
@app.route("/dashboard")
def dashboard():
    if "user_email" not in session:
        return redirect(url_for("login"))

    user = users_collection.find_one({"email": session["user_email"]})
    if not user:
        session.clear()
        return redirect(url_for("login"))

    # Add KYC status to session
    session["kyc_status"] = user.get("kyc_status", "not_verified")
    
    # Check if we should show KYC notification
    show_kyc_notification = False
    notification_type = "none"
    
    if session["kyc_status"] == "not_verified":
        # Check if user has dismissed the notification
        kyc_notification_dismissed = user.get("kyc_notification_dismissed", False)
        
        # Only show notification if not dismissed in the last 24 hours
        if not kyc_notification_dismissed:
            show_kyc_notification = True
            notification_type = "kyc_required"
            # Update last shown time
            users_collection.update_one(
                {"_id": user["_id"]},
                {"$set": {"kyc_notification_last_shown": datetime.now(timezone.utc)}}
            )
    
    # Handle different investment statuses
    investment_status = user.get("investment_status", "none")
    
    # For pending crypto payments, show different message
    if investment_status == "pending_crypto_payment":
        # Check for crypto payment
        crypto_payment = crypto_payments_collection.find_one({
            "user_id": session["user_id"],
            "status": "pending"
        })
        
        if crypto_payment:
            session.update({
                "investment": f"${crypto_payment.get('amount_usd', 0):.2f} - Pending Approval",
                "total_investment": f"${crypto_payment.get('amount_usd', 0):.2f}",
                "investment_status": "pending_crypto_payment",
                "time_progress": 0,
                "time_remaining": "Awaiting Approval"
            })
        else:
            session.update({
                "investment": "Payment Pending",
                "total_investment": "$0.00",
                "investment_status": "pending_crypto_payment",
                "time_progress": 0,
                "time_remaining": "Awaiting Approval"
            })
    elif investment_status == "active" and user.get("investment_time"):
        # Calculate investment progress for active investments
        investment_time = ensure_utc_datetime(user["investment_time"])
        current_time = datetime.now(timezone.utc)
        maturity_time = investment_time + timedelta(hours=6)
        elapsed_time = (current_time - investment_time).total_seconds()
        total_duration = timedelta(hours=6).total_seconds()
        time_progress = min(max(elapsed_time / total_duration, 0), 1)
        time_left = max(maturity_time - current_time, timedelta(0))
        hours, minutes = divmod(time_left.seconds, 3600)
        minutes = minutes // 60
        time_remaining = f"{hours}h {minutes}m"
        
        initial_investment = float(user.get("initial_investment", 0))
        session.update(
            {
                "investment": f"${initial_investment:.2f} invested",
                "total_investment": f"${initial_investment:.2f}",
                "investment_status": investment_status,
                "time_progress": round(time_progress * 100, 1),
                "time_remaining": time_remaining,
            }
        )
    else:
        # No active investment
        initial_investment = float(user.get("initial_investment", 0))
        session.update(
            {
                "investment": "No active investment",
                "total_investment": f"${initial_investment:.2f}",
                "investment_status": investment_status,
                "time_progress": 0,
                "time_remaining": "Not started",
            }
        )
    
    # Check for pending reviews count for badge
    pending_reviews_count = pending_reviews_collection.count_documents({
        "user_id": session["user_id"],
        "status": "pending"
    })
    
    # Check for any flashed messages
    flashed_messages = []
    for category, message in get_flashed_messages(with_categories=True):
        flashed_messages.append({"category": category, "message": message})
    
    # Get user's KYC submission if pending
    user_kyc_submission = None
    if session["kyc_status"] == "pending":
        user_kyc_submission = kyc_collection.find_one({
            "user_id": session["user_id"],
            "status": "pending"
        })
    
    return render_template(
        "dashboard.html", 
        session=session, 
        show_kyc_notification=show_kyc_notification,
        notification_type=notification_type,
        pending_reviews_count=pending_reviews_count,
        user_kyc_submission=user_kyc_submission,
        flashed_messages=flashed_messages
    )

@app.route("/forex_data")
def forex_data():
    return jsonify({"forex_url": "https://fxpricing.com/fx-widget/market-currency-rates-widget.php?id=1,2,3,5,14,20"})

@app.route("/invest")
@kyc_required
def invest():
    if "user_email" not in session:
        return redirect(url_for("login"))

    error = request.args.get('error')
    if error:
        flash(error, 'error')
    
    return render_template("invest.html")

@app.route("/upload-profile-picture", methods=["POST"])
def upload_profile_picture():
    if "user_email" not in session:
        flash("User not logged in!", "error")
        return redirect(url_for("account_settings"))

    file = request.files.get("profile_pic")
    if not file:
        flash("No file uploaded!", "error")
        return redirect(url_for("account_settings"))

    filename = secure_filename(session["user_email"] + ".jpg")
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(file_path)

    users_collection.update_one(
        {"email": session["user_email"]}, 
        {"$set": {"profile_picture": filename}}
    )
    session["profile_picture"] = filename

    flash("Profile picture updated!", "success")
    return redirect(url_for("account_settings"))

@app.route("/remove-profile-picture", methods=["POST"])
def remove_profile_picture():
    if "user_email" not in session:
        return jsonify({"error": "User not logged in!"}), 401

    file_path = os.path.join(app.config["UPLOAD_FOLDER"], session["user_email"] + ".jpg")
    if os.path.exists(file_path):
        os.remove(file_path)

    users_collection.update_one(
        {"email": session["user_email"]}, 
        {"$set": {"profile_picture": "default.jpg"}}
    )
    session["profile_picture"] = "default.jpg"

    flash("Profile picture removed successfully!", "success")
    return redirect(url_for("account_settings"))

@app.route("/convert_currency", methods=["GET"])
def convert_currency():
    amount = request.args.get("amount")
    from_currency = request.args.get("from")
    to_currency = request.args.get("to")

    if not amount or not from_currency or not to_currency:
        return jsonify({"error": "Missing required parameters"}), 400

    try:
        response = requests.get(f"https://api.exchangerate-api.com/v4/latest/{from_currency}")
        response.raise_for_status()
        rate = response.json()["rates"].get(to_currency)

        if not rate:
            return jsonify({"error": "Invalid currency selected"}), 400

        # Add margin (e.g., 3% worse for user)
        margin = 0.000
        rate_with_margin = rate * (1 - margin)
        return jsonify({
            "converted": round(float(amount) * rate_with_margin, 2), 
            "rate": round(rate_with_margin, 4)
        }), 200
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Failed to fetch exchange rates: {str(e)}"}), 500
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("welcome"))

@app.route("/terms")
def terms():
    return render_template("terms.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/privacy")
def privacy():
    return render_template("privacy.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/initialize_transaction", methods=["POST"])
def initialize_transaction():
    if "user_email" not in session:
        return jsonify({"status": False, "message": "User not logged in"}), 401

    try:
        data = request.get_json()
        amount_kes = float(data.get("amount"))
        plan = data.get("plan", "unknown")

        if not amount_kes:
            return jsonify({"status": False, "message": "Missing amount"}), 400

        # ✅ Convert KES → USD internally (no HTTP recursion)
        try:
            amount_usd = convert_currency_internal(amount_kes, "KES", "USD")
        except Exception as e:
            return jsonify({"status": False, "message": f"Currency conversion failed: {str(e)}"}), 400

        headers = {
            "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
            "Content-Type": "application/json"
        }

        payload = {
            "email": session["user_email"],
            "amount": int(amount_kes * 100),
            "currency": "KES",
            "callback_url": url_for('paystack_callback', _external=True),
            "metadata": {
                "plan": plan,
                "amount_usd": amount_usd,
                "user_id": session.get("user_id")
            }
        }

        response = requests.post(
            "https://api.paystack.co/transaction/initialize",
            headers=headers,
            json=payload
        )
        response_data = response.json()

        if response_data.get("status"):
            return jsonify(response_data)

        return jsonify({
            "status": False,
            "message": response_data.get("message", "Payment initialization failed")
        }), 400

    except Exception as e:
        return jsonify({"status": False, "message": str(e)}), 500


@app.route('/paystack_callback', methods=['GET'])
def paystack_callback():
    reference = request.args.get('reference')
    if not reference:
        flash("Payment reference missing!", "error")
        return redirect(url_for("invest"))

    try:
        headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"}
        response = requests.get(
            f"https://api.paystack.co/transaction/verify/{reference}",
            headers=headers
        )
        data = response.json()
        print(f"Paystack verification response: {data}")

        if data["status"] and data["data"]["status"] == "success":
            metadata = data["data"].get("metadata", {})
            user_id = metadata.get("user_id")
            
            if not user_id:
                flash("User identification missing in payment", "error")
                return redirect(url_for("dashboard"))

            # Validate ObjectId
            try:
                user_id_obj = ObjectId(user_id)
            except Exception as e:
                print(f"Invalid ObjectId: {user_id}, Error: {e}")
                flash("Invalid user ID", "error")
                return redirect(url_for("dashboard"))

            # Proceed with updates
            amount_usd = float(metadata.get("amount_usd", 0))
            investment_time = datetime.now(timezone.utc)
            update_data = {
                "initial_investment": amount_usd,
                "investment_time": investment_time,
                "investment_status": "active"
            }

            # Update MongoDB
            result = users_collection.update_one(
                {"_id": user_id_obj},  # Use the validated ObjectId
                {"$set": update_data}
            )
            print(f"Updated user {user_id} with: {update_data}")

            if result.modified_count == 0:
                print("Warning: No document was updated. Check the user ID.")

            # Update session if the current user matches
            if session.get("user_id") == user_id:
                session.update({
                    "investment": f"${amount_usd:.2f} invested",
                    "total_investment": f"${amount_usd:.2f}",
                    "investment_status": "active"
                })

            flash("Payment successful! Your investment is now active.", "success")
            return redirect(url_for("dashboard"))

        flash("Payment verification failed!", "error")
        return redirect(url_for("dashboard"))

    except Exception as e:
        print(f"Error in paystack_callback: {e}")
        flash("Payment processing error.", "error")
        return redirect(url_for("dashboard"))
@app.route("/account-settings", methods=["GET", "POST"])
def account_settings():
    if "user_email" not in session:
        return redirect(url_for("login"))

    user = users_collection.find_one({"email": session["user_email"]})
    if not user:
        session.clear()
        return redirect(url_for("login"))

    if request.method == "POST":
        # Handle form submissions
        pass

    return render_template("account_settings.html", session=session)

@app.route("/change-password", methods=["POST"])
def change_password():
    if "user_email" not in session:
        flash("User not logged in!", "error")
        return redirect(url_for("account_settings"))

    old_password = request.form.get("old_password")
    new_password = request.form.get("new_password")
    confirm_password = request.form.get("confirm_password")

    if not all([old_password, new_password, confirm_password]):
        flash("All fields are required!", "error")
        return redirect(url_for("account_settings"))

    if new_password != confirm_password:
        flash("Passwords do not match!", "error")
        return redirect(url_for("account_settings"))

    user = users_collection.find_one({"email": session["user_email"]})
    if not user or not check_password_hash(user["password"], old_password):
        flash("Old password is incorrect!", "error")
        return redirect(url_for("account_settings"))

    hashed_password = generate_password_hash(new_password)
    users_collection.update_one(
        {"email": session["user_email"]}, 
        {"$set": {"password": hashed_password}}
    )

    flash("Password changed successfully!", "success")
    return redirect(url_for("account_settings"))

@app.route("/check_withdrawal", methods=["POST"])
def check_withdrawal():
    """Check if withdrawal is available with timezone-aware datetime handling"""
    if "user_email" not in session:
        return jsonify({"error": "User not logged in!"}), 401

    user = users_collection.find_one({"email": session["user_email"]})
    
    if not user:
        return jsonify({"error": "User not found!"}), 404
    
    investment_status = user.get("investment_status", "none")
    
    # If no active investment
    if investment_status != "active" or "investment_time" not in user:
        return jsonify({
            "status": "no_investment",
            "message": "No active investment found!",
            "can_withdraw": False
        }), 200

    try:
        # Use timezone-aware datetime handling
        investment_time = ensure_utc_datetime(user["investment_time"])
        current_time = datetime.now(timezone.utc)
        maturity_time = investment_time + timedelta(hours=6)
        
        # Ensure maturity_time is timezone-aware
        if maturity_time.tzinfo is None:
            maturity_time = maturity_time.replace(tzinfo=timezone.utc)
        
        time_remaining = maturity_time - current_time

        # If investment hasn't matured yet
        if current_time < maturity_time:
            hours = int(time_remaining.total_seconds() // 3600)
            minutes = int((time_remaining.total_seconds() % 3600) // 60)
            seconds = int(time_remaining.total_seconds() % 60)
            
            return jsonify({
                "status": "pending",
                "message": f"Profits will mature in {hours}h {minutes}m {seconds}s",
                "can_withdraw": False,
                "time_remaining_seconds": int(time_remaining.total_seconds()),
                "maturity_time": maturity_time.isoformat(),
                "current_time": current_time.isoformat()
            }), 200
        
        # Investment has matured
        initial_amount = float(user.get("initial_investment", 0))
        required_payment = initial_amount * 2
        
        return jsonify({
            "status": "ready",
            "message": f"Pay ${required_payment:.2f} to withdraw profits",
            "required_payment": required_payment,
            "can_withdraw": True,
            "maturity_time": maturity_time.isoformat(),
            "current_time": current_time.isoformat(),
            "elapsed_hours": round((current_time - investment_time).total_seconds() / 3600, 2)
        }), 200
        
    except Exception as e:
        print(f"Error in check_withdrawal: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "error": "Failed to check withdrawal status",
            "details": str(e)
        }), 500

@app.route("/process_withdrawal", methods=["POST"])
@kyc_required
def process_withdrawal():
    """Process withdrawal payment with timezone-aware datetime handling"""
    if "user_email" not in session:
        return jsonify({"error": "User not logged in!"}), 401

    try:
        user = users_collection.find_one({"email": session["user_email"]})
        
        if not user:
            return jsonify({"error": "User not found!"}), 404
        
        investment_status = user.get("investment_status", "none")
        
        # Validate investment status
        if investment_status != "active" or "investment_time" not in user:
            return jsonify({"error": "No active investment found!"}), 400

        # Check maturity with timezone-aware datetime handling
        investment_time = ensure_utc_datetime(user["investment_time"])
        current_time = datetime.now(timezone.utc)
        maturity_time = investment_time + timedelta(hours=6)
        
        # Ensure maturity_time is timezone-aware
        if maturity_time.tzinfo is None:
            maturity_time = maturity_time.replace(tzinfo=timezone.utc)
        
        # Check if investment has matured
        if current_time < maturity_time:
            time_left = maturity_time - current_time
            hours = int(time_left.total_seconds() // 3600)
            minutes = int((time_left.total_seconds() % 3600) // 60)
            
            return jsonify({
                "error": f"Withdrawal not yet available! Please wait {hours}h {minutes}m for maturity."
            }), 400

        # Calculate required payment
        initial_amount_usd = float(user.get("initial_investment", 0))
        required_payment_usd = initial_amount_usd * 2

        # Convert to KES for payment processing
        conversion_response = requests.get(
            f"http://{request.host}/convert_currency?amount={required_payment_usd}&from=USD&to=KES"
        )
        conversion_data = conversion_response.json()
        
        if "error" in conversion_data:
            return jsonify({"error": f"Currency conversion failed: {conversion_data['error']}"}), 400
            
        required_payment_kes = conversion_data["converted"]

        # Initialize Paystack payment
        headers = {
            "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
            "Content-Type": "application/json"
        }

        payload = {
            "email": session["user_email"],
            "amount": int(required_payment_kes * 100),
            "currency": "KES",
            "callback_url": url_for('withdrawal_callback', _external=True),
            "metadata": {
                "purpose": "withdrawal_fee",
                "original_amount_usd": required_payment_usd,
                "converted_amount_kes": required_payment_kes,
                "initial_investment": initial_amount_usd,
                "plan": user.get("investment_plan", "unknown"),
                "is_withdrawal": True,
                "user_id": session.get("user_id"),
                "investment_matured_at": maturity_time.isoformat(),
                "withdrawal_requested_at": current_time.isoformat()
            }
        }

        response = requests.post(
            "https://api.paystack.co/transaction/initialize",
            headers=headers,
            json=payload
        )
        response_data = response.json()

        if response_data.get("status"):
            # Log withdrawal attempt
            withdrawal_log = {
                "user_id": session["user_id"],
                "email": session["user_email"],
                "initial_investment": initial_amount_usd,
                "required_payment_usd": required_payment_usd,
                "required_payment_kes": required_payment_kes,
                "paystack_reference": response_data["data"]["reference"],
                "investment_time": investment_time,
                "maturity_time": maturity_time,
                "requested_at": current_time,
                "status": "pending_payment",
                "payment_gateway": "paystack"
            }
            
            # Store in a separate collection for tracking
            db["withdrawal_requests"].insert_one(withdrawal_log)
            
            return jsonify({
                "status": True,
                "message": "Payment initialized successfully",
                "data": response_data["data"],
                "amount_kes": required_payment_kes,
                "amount_usd": required_payment_usd,
                "reference": response_data["data"]["reference"],
                "authorization_url": response_data["data"]["authorization_url"]
            })
        
        # Handle Paystack error
        return jsonify({
            "status": False,
            "message": response_data.get("message", "Payment initialization failed"),
            "details": response_data
        }), 400

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Payment gateway error: {str(e)}"}), 500
    except Exception as e:
        print(f"Error in process_withdrawal: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Withdrawal processing failed: {str(e)}"}), 500

@app.route("/withdrawal_callback", methods=["GET"])
def withdrawal_callback():
    reference = request.args.get('reference')

    if not reference:
        flash("Withdrawal reference missing!", "error")
        return redirect(url_for("dashboard"))

    try:
        headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"}
        response = requests.get(
            f"https://api.paystack.co/transaction/verify/{reference}",
            headers=headers
        )
        data = response.json()

        if data["status"] and data["data"]["status"] == "success":
            metadata = data["data"].get("metadata", {})
            user_id = metadata.get("user_id")
            
            if not user_id:
                flash("User identification missing in withdrawal", "error")
                return redirect(url_for("dashboard"))

            # Mark investment as completed
            users_collection.update_one(
                {"_id": user_id},
                {"$set": {
                    "investment_status": "completed",
                    "withdrawal_time": datetime.now(timezone.utc)
                }}
            )

            # Refresh session if current user
            if session.get("user_id") == user_id:
                session["investment_status"] = "completed"
                flash("Withdrawal processed successfully!", "success")

            return redirect(url_for("dashboard"))

        flash("Withdrawal verification failed!", "error")
        return redirect(url_for("dashboard"))

    except Exception as e:
        flash(f"Withdrawal processing error: {str(e)}", "error")
        return redirect(url_for("dashboard"))

@app.route("/api/investment_details", methods=["GET"])
def investment_details():
    if "user_email" not in session:
        return jsonify({"error": "User not logged in!"}), 401

    user = users_collection.find_one({"email": session["user_email"]})
    print(f"Fetched user data for /api/investment_details: {user}")  # Add this log

    if not user:
        return jsonify({
            "amount_invested": 0.0,
            "investment_status": "none"
        }), 200

    return jsonify({
        "amount_invested": float(user.get("initial_investment", 0.0)),
        "investment_status": user.get("investment_status", "none")
    }), 200

@app.route("/api/realtime_investment_data", methods=["GET"])
def realtime_investment_data():
    """API endpoint for real-time investment data with timezone-aware datetime handling"""
    if "user_email" not in session:
        return jsonify({"error": "User not logged in!"}), 401

    user = users_collection.find_one({"email": session["user_email"]})
    if not user:
        return jsonify({"error": "User not found"}), 404

    investment_status = user.get("investment_status", "none")
    
    # Handle pending crypto payment status
    if investment_status == "pending_crypto_payment":
        # Get crypto payment details
        crypto_payment = crypto_payments_collection.find_one({
            "user_id": session["user_id"],
            "status": "pending"
        })
        
        if crypto_payment:
            amount_usd = float(crypto_payment.get("amount_usd", 0))
            return jsonify({
                "profit": 0.0,
                "initial_investment": amount_usd,
                "current_value": amount_usd,
                "time_progress": 0.0,
                "hours_remaining": 0,
                "minutes_remaining": 0,
                "investment_status": "pending_crypto_payment",
                "pending_message": "Payment awaiting admin approval"
            }), 200
        else:
            return jsonify({
                "profit": 0.0,
                "initial_investment": 0.0,
                "current_value": 0.0,
                "time_progress": 0.0,
                "hours_remaining": 0,
                "minutes_remaining": 0,
                "investment_status": "pending_crypto_payment"
            }), 200
    
    # Handle missing investment_time
    investment_time = user.get("investment_time")
    if not investment_time or investment_status != "active":
        initial_investment = float(user.get("initial_investment", 0.0))
        return jsonify({
            "profit": 0.0,
            "initial_investment": initial_investment,
            "current_value": initial_investment,
            "time_progress": 0.0,
            "hours_remaining": 0,
            "minutes_remaining": 0,
            "investment_status": investment_status
        }), 200

    try:
        # Calculate investment progress with timezone-aware datetimes
        investment_time = ensure_utc_datetime(investment_time)
        initial_investment = float(user.get("initial_investment", 0.0))
        current_time = datetime.now(timezone.utc)
        maturity_time = investment_time + timedelta(hours=6)

        # Ensure maturity_time is also timezone-aware
        if maturity_time.tzinfo is None:
            maturity_time = maturity_time.replace(tzinfo=timezone.utc)

        # Calculate elapsed time and progress
        elapsed_time = (current_time - investment_time).total_seconds()
        total_duration = timedelta(hours=6).total_seconds()
        
        # Handle edge cases
        if elapsed_time < 0:
            elapsed_time = 0
        if elapsed_time > total_duration:
            elapsed_time = total_duration
            
        time_progress = elapsed_time / total_duration

        # Calculate investment value (400% return over 6 hours)
        current_value = initial_investment * (1 + 4 * time_progress)
        profit = current_value - initial_investment

        # Calculate time remaining
        time_left = max(maturity_time - current_time, timedelta(0))
        hours_remaining = int(time_left.total_seconds() // 3600)
        minutes_remaining = int((time_left.total_seconds() % 3600) // 60)

        return jsonify({
            "profit": round(profit, 2),
            "initial_investment": round(initial_investment, 2),
            "current_value": round(current_value, 2),
            "time_progress": round(time_progress * 100, 2),
            "hours_remaining": hours_remaining,
            "minutes_remaining": minutes_remaining,
            "investment_status": investment_status,
            "maturity_time": maturity_time.isoformat(),
            "current_time": current_time.isoformat()
        }), 200
        
    except Exception as e:
        print(f"Error in /api/realtime_investment_data: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "error": "Failed to fetch investment data",
            "details": str(e)
        }), 500
    
@app.route("/manual_payment_notice", methods=["POST"])
def manual_payment_notice():
    if "user_email" not in session:
        return jsonify({"status": "error", "message": "Not logged in"}), 401

    data = request.get_json()
    amount_usd = float(data.get("amount_usd", 0))
    local_amount = data.get("local_amount")
    plan = data.get("plan")
    country = data.get("country")
    transaction_id = data.get("transaction_id", "")  # <-- NEW

    # Save this payment request in a new collection for admin review
    pending = {
        "user_id": session["user_id"],
        "username": session["user"],
        "email": session["user_email"],
        "plan": plan,
        "country": country,
        "amount_usd": amount_usd,
        "local_amount": local_amount,
        "transaction_id": transaction_id,  # <-- NEW
        "status": "pending",
        "created_at": datetime.now(timezone.utc)
    }
    db["pending_manual_payments"].insert_one(pending)

    # Optionally: Mark user as "pending_manual_payment"
    users_collection.update_one(
        {"_id": ObjectId(session["user_id"])},
        {"$set": {"investment_status": "pending_manual_payment"}}
    )

    return jsonify({"status": "pending"})
# Example: Manual admin registration (should be removed after first use!)
@app.route("/admin_register", methods=["GET", "POST"])
def admin_register():
    ADMIN_SECRET = "Big_Winners"
    if request.method == "POST":
        secret = request.form.get("secret")
        fullname = request.form.get("fullname")
        email = request.form.get("email")
        username = request.form.get("username")
        password = request.form.get("password")
        if secret != ADMIN_SECRET:
            flash("Invalid secret!", "danger")
            return redirect(url_for("admin_register"))
        # Your user creation logic here, for example:
        if users_collection.find_one({"email": email}):
            flash("Email already registered.", "danger")
            return redirect(url_for("admin_register"))
        hashed_pw = generate_password_hash(password)
        users_collection.insert_one({
            "fullname": fullname,
            "email": email,
            "username": username,
            "password": hashed_pw,
            "is_admin": True
        })
        flash("Admin registered!", "success")
        return redirect(url_for("admin_login"))
    return render_template("admin_register.html")
@app.route("/admin_login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = users_collection.find_one({"email": email, "is_admin": True})
        if user and check_password_hash(user["password"], password):
            session.update({
                "user_id": str(user["_id"]),
                "user": user["username"],
                "user_email": email,
                "profile_picture": user.get("profile_picture", "default.jpg"),
                "is_admin": True
            })
            return redirect(url_for("admin_dashboard"))
        flash("Invalid admin credentials", "danger")
        return redirect(url_for("admin_login"))
    return render_template("admin_login.html")

@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    # Optionally pop other session items if needed
    return redirect(url_for("admin_login"))

@app.route("/admin")
@admin_required
def admin_dashboard():
    # Pending payments for table
    pending_payments = list(db["pending_manual_payments"].find({"status": "pending"}))
    pending_crypto_count = crypto_payments_collection.count_documents({"status": "pending"})
    twenty_four_hours_ago = datetime.now(timezone.utc) - timedelta(hours=24)
    
    new_users_last_24h = users_collection.count_documents({
        "created_at": {"$gte": twenty_four_hours_ago}
    }) if users_collection.find_one({"created_at": {"$exists": True}}) else 0
    
    payments_last_24h = card_payments_collection.count_documents({
        "created_at": {"$gte": twenty_four_hours_ago}
    })
    
    kyc_submissions_last_24h = kyc_collection.count_documents({
        "submitted_at": {"$gte": twenty_four_hours_ago}
    })

    # All users
    users = list(users_collection.find({}))
    user_count = len(users)
    emails = [u["email"] for u in users]

    # Users who have invested (example: adjust field names as needed)
    invested_users = [u for u in users if u.get("investment_status") == "active" and u.get("initial_investment")]
    invested_count = len(invested_users)
    total_invested = sum(float(u.get("initial_investment", 0)) for u in invested_users)

    pending_kyc_count = kyc_collection.count_documents({"status": "pending"})

    return render_template(
        "admin_dashboard.html",
        pending_payments=pending_payments,
        user_count=user_count,
        invested_count=invested_count,
        total_invested=total_invested,
        emails=emails,
        invested_users=invested_users,
        pending_crypto_count=pending_crypto_count,
        pending_kyc_count=pending_kyc_count,
        new_users_last_24h=new_users_last_24h,
        payments_last_24h=payments_last_24h,
        kyc_submissions_last_24h=kyc_submissions_last_24h,
        current_time=datetime.now(timezone.utc),
        pending_reviews_count=pending_reviews_collection.count_documents({"status": "pending"})
    )

# Example route to approve a manual payment
@app.route("/admin/approve_payment/<payment_id>", methods=["POST"])
@admin_required
def approve_payment(payment_id):
    payment = db["pending_manual_payments"].find_one({"_id": ObjectId(payment_id)})
    if not payment:
        abort(404)
    # Update user investment
    users_collection.update_one(
        {"_id": ObjectId(payment["user_id"])},
        {"$set": {
            "investment_status": "active",
            "initial_investment": payment["amount_usd"],
            "investment_time": datetime.now(timezone.utc)
        }}
    )
    # Mark payment as approved
    db["pending_manual_payments"].update_one(
        {"_id": ObjectId(payment_id)},
        {"$set": {"status": "approved", "approved_at": datetime.now(timezone.utc)}}
    )
    flash("Payment approved and investment activated!", "success")
    return redirect(url_for("admin_dashboard"))
@app.route("/admin/reject_payment/<payment_id>", methods=["POST"])
@admin_required
def reject_payment(payment_id):
    from bson import ObjectId
    # Update the payment status to "rejected"
    db["pending_manual_payments"].update_one(
        {"_id": ObjectId(payment_id)},
        {"$set": {"status": "rejected"}}
    )
    flash("Payment has been rejected.", "warning")
    return redirect(url_for("admin_dashboard"))

# Add after your existing collections
reviews_collection = db["reviews"]
pending_reviews_collection = db["pending_reviews"]

# Add these routes before the main block
@app.route("/submit_review", methods=["POST"])
def submit_review():
    if "user_email" not in session:
        return jsonify({"status": "error", "message": "Not logged in"}), 401

    try:
        data = request.get_json()
        rating = int(data.get("rating", 0))
        review_text = data.get("review_text", "").strip()
        
        if not review_text or rating < 1 or rating > 5:
            return jsonify({"status": "error", "message": "Invalid review data"}), 400

        # Save to pending reviews for admin approval
        review_data = {
            "user_id": session["user_id"],
            "username": session["user"],
            "email": session["user_email"],
            "rating": rating,
            "review_text": review_text,
            "status": "pending",
            "created_at": datetime.now(timezone.utc)
        }
        
        pending_reviews_collection.insert_one(review_data)
        
        return jsonify({"status": "success", "message": "Review submitted for approval"})
        
    except Exception as e:
        return jsonify({"status": "error", "message": "Failed to submit review"}), 500

@app.route("/get_approved_reviews")
def get_approved_reviews():
    try:
        # Get only approved reviews
        approved_reviews = list(reviews_collection.find(
            {"status": "approved"}, 
            {"_id": 0, "username": 1, "rating": 1, "review_text": 1, "created_at": 1}
        ).sort("created_at", -1).limit(10))  # Show latest 10 reviews
        
        # Convert ObjectId and datetime to string for JSON serialization
        for review in approved_reviews:
            if "created_at" in review:
                review["created_at"] = review["created_at"].strftime("%Y-%m-%d")
                
        return jsonify({"reviews": approved_reviews})
    except Exception as e:
        return jsonify({"reviews": []})

# Admin routes for review management
@app.route("/admin/pending_reviews")
@admin_required
def admin_pending_reviews():
    # Get both pending and approved reviews
    pending_reviews = list(pending_reviews_collection.find({"status": "pending"}))
    approved_reviews = list(reviews_collection.find({"status": "approved"}).sort("approved_at", -1))
    
    return render_template("admin_reviews.html", 
                         pending_reviews=pending_reviews, 
                         approved_reviews=approved_reviews)
@app.route("/admin/delete_review/<review_id>", methods=["POST"])
@admin_required
def delete_review(review_id):
    try:
        # Try to delete from approved reviews first
        result = reviews_collection.delete_one({"_id": ObjectId(review_id)})
        
        if result.deleted_count == 0:
            # If not found in approved, try pending reviews
            result = pending_reviews_collection.delete_one({"_id": ObjectId(review_id)})
        
        if result.deleted_count > 0:
            flash("Review deleted successfully!", "success")
        else:
            flash("Review not found!", "warning")
            
        return redirect(url_for('admin_pending_reviews'))
        
    except Exception as e:
        flash("Error deleting review", "danger")
        return redirect(url_for('admin_pending_reviews'))
    
@app.route("/admin/approve_review/<review_id>", methods=["POST"])
@admin_required
def approve_review(review_id):
    try:
        review = pending_reviews_collection.find_one({"_id": ObjectId(review_id)})
        if not review:
            abort(404)
        
        # Move to approved reviews collection
        approved_review = review.copy()
        approved_review["status"] = "approved"
        approved_review["approved_at"] = datetime.now(timezone.utc)
        
        reviews_collection.insert_one(approved_review)
        pending_reviews_collection.delete_one({"_id": ObjectId(review_id)})
        
        flash("Review approved successfully!", "success")
        return redirect(url_for("admin_pending_reviews"))
        
    except Exception as e:
        flash("Error approving review", "danger")
        return redirect(url_for("admin_pending_reviews"))

@app.route("/admin/reject_review/<review_id>", methods=["POST"])
@admin_required
def reject_review(review_id):
    try:
        pending_reviews_collection.delete_one({"_id": ObjectId(review_id)})
        flash("Review rejected successfully!", "warning")
        return redirect(url_for("admin_pending_reviews"))
    except Exception as e:
        flash("Error rejecting review", "danger")
        return redirect(url_for("admin_pending_reviews"))


@app.route("/dismiss_kyc_notification", methods=["POST"])
def dismiss_kyc_notification():
    """Dismiss KYC notification for the current user"""
    if "user_email" not in session:
        return jsonify({"success": False, "message": "Not logged in"}), 401
    
    try:
        # Update user's notification dismissal status
        users_collection.update_one(
            {"_id": ObjectId(session["user_id"])},
            {"$set": {
                "kyc_notification_dismissed": True,
                "kyc_notification_dismissed_at": datetime.now(timezone.utc)
            }}
        )
        
        # Update session
        session["kyc_notification_dismissed"] = True
        
        return jsonify({
            "success": True, 
            "message": "Notification dismissed",
            "redirect_url": url_for("dashboard")
        })
        
    except Exception as e:
        print(f"Error dismissing KYC notification: {e}")
        return jsonify({"success": False, "message": "Internal server error"}), 500


@app.route("/reset_kyc_notification", methods=["POST"])
def reset_kyc_notification():
    """Reset KYC notification (e.g., after visiting KYC page without submitting)"""
    if "user_email" not in session:
        return jsonify({"success": False, "message": "Not logged in"}), 401
    
    try:
        # Reset user's notification dismissal status
        users_collection.update_one(
            {"_id": ObjectId(session["user_id"])},
            {"$set": {
                "kyc_notification_dismissed": False,
                "kyc_notification_last_shown": None
            }}
        )
        
        # Update session
        session["kyc_notification_dismissed"] = False
        
        return jsonify({
            "success": True, 
            "message": "Notification reset",
            "redirect_url": url_for("dashboard")
        })
        
    except Exception as e:
        print(f"Error resetting KYC notification: {e}")
        return jsonify({"success": False, "message": "Internal server error"}), 500


@app.route("/get_kyc_status", methods=["GET"])
def get_kyc_status():
    """API endpoint to get current KYC status"""
    if "user_email" not in session:
        return jsonify({"success": False, "message": "Not logged in"}), 401
    
    try:
        user = users_collection.find_one({"email": session["user_email"]})
        if not user:
            return jsonify({"success": False, "message": "User not found"}), 404
        
        kyc_status = user.get("kyc_status", "not_verified")
        notification_dismissed = user.get("kyc_notification_dismissed", False)
        
        # Check for pending KYC submission
        pending_kyc = kyc_collection.find_one({
            "user_id": session["user_id"],
            "status": "pending"
        })
        
        return jsonify({
            "success": True,
            "kyc_status": kyc_status,
            "notification_dismissed": notification_dismissed,
            "has_pending_submission": pending_kyc is not None,
            "submission_date": pending_kyc.get("submitted_at").strftime("%Y-%m-%d") if pending_kyc else None
        })
        
    except Exception as e:
        print(f"Error getting KYC status: {e}")
        return jsonify({"success": False, "message": "Internal server error"}), 500


@app.route("/kyc_verification")
def kyc_verification():
    """KYC verification page"""
    if "user_email" not in session:
        return redirect(url_for("login"))
    
    # Check if KYC is already submitted or verified
    user = users_collection.find_one({"email": session["user_email"]})
    if not user:
        session.clear()
        return redirect(url_for("login"))
    
    kyc_status = user.get("kyc_status", "not_verified")
    
    if kyc_status == "verified":
        flash("Your account is already verified!", "success")
        return redirect(url_for("dashboard"))
    
    # Check if KYC is pending
    kyc = kyc_collection.find_one({"user_id": session["user_id"], "status": "pending"})
    
    # Reset notification when user visits KYC page (they're taking action)
    users_collection.update_one(
        {"_id": ObjectId(session["user_id"])},
        {"$set": {
            "kyc_notification_dismissed": True,
            "kyc_notification_last_shown": datetime.now(timezone.utc)
        }}
    )
    session["kyc_notification_dismissed"] = True
    
    if kyc:
        # User can view their submission but not resubmit
        return render_template("kyc_verification.html", 
                             can_resubmit=False, 
                             kyc_data=kyc,
                             kyc_status="pending",
                             submission_date=kyc.get("submitted_at").strftime("%Y-%m-%d %H:%M"))
    
    # User can submit new KYC
    return render_template("kyc_verification.html", 
                         can_resubmit=True, 
                         kyc_data=None,
                         kyc_status="not_verified",
                         submission_date=None)


@app.route("/submit_kyc", methods=["POST"])
def submit_kyc():
    """Submit KYC verification documents with image storage"""
    if "user_email" not in session:
        return jsonify({"success": False, "message": "Not logged in"}), 401
    
    try:
        data = request.get_json()
        
        # ========== VALIDATION PHASE ==========
        # Validate required fields
        required_fields = ["front_id", "back_id", "face_image"]
        for field in required_fields:
            if not data.get(field):
                return jsonify({
                    "success": False, 
                    "message": f"Missing {field.replace('_', ' ').title()}"
                }), 400
        
        user_id = session["user_id"]
        username = session["user"]
        email = session["user_email"]
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        
        # ========== FILE PREPARATION PHASE ==========
        # Create KYC uploads directory if it doesn't exist
        kyc_upload_dir = os.path.join(app.config["UPLOAD_FOLDER"], "kyc_docs")
        os.makedirs(kyc_upload_dir, exist_ok=True)
        
        saved_files = {}
        errors_occurred = False
        saved_filepaths = []  # Track saved files for cleanup
        
        for field in required_fields:
            try:
                # Extract and decode base64 data
                base64_data = data[field]
                if base64_data.startswith('data:image'):
                    # Remove data URL prefix if present
                    base64_data = base64_data.split(',')[1] if ',' in base64_data else base64_data
                
                image_data = base64.b64decode(base64_data)
                
                # Validate image size (5MB max)
                if len(image_data) > 5 * 1024 * 1024:
                    return jsonify({
                        "success": False, 
                        "message": f"{field.replace('_', ' ').title()} exceeds 5MB limit"
                    }), 400
                
                # Generate filename
                file_ext = ".jpg"
                filename = f"kyc_{user_id}_{field}_{timestamp}{file_ext}"
                filepath = os.path.join(kyc_upload_dir, filename)
                
                # Save file
                with open(filepath, 'wb') as f:
                    f.write(image_data)
                
                # Track saved files
                saved_files[field] = filename
                saved_filepaths.append(filepath)
                
                # Compress large images
                if os.path.getsize(filepath) > 2 * 1024 * 1024:  # > 2MB
                    compress_image(filepath)
                    
            except base64.binascii.Error:
                return jsonify({
                    "success": False, 
                    "message": f"Invalid image format for {field.replace('_', ' ').title()}"
                }), 400
            except Exception as e:
                print(f"Error processing {field} image: {e}")
                errors_occurred = True
                break
        
        # Clean up on error
        if errors_occurred:
            for filepath in saved_filepaths:
                try:
                    os.remove(filepath)
                except:
                    pass
            return jsonify({
                "success": False, 
                "message": "Failed to process images. Please try again."
            }), 500
        
        # ========== DATABASE OPERATION PHASE ==========
        # Check for existing pending KYC
        existing_kyc = kyc_collection.find_one({
            "user_id": user_id, 
            "status": "pending"
        })
        
        # Prepare KYC data
        kyc_data = {
            "user_id": user_id,
            "email": email,
            "username": username,
            "fullname": data.get("fullname", ""),
            # File-based access
            "front_id_filename": saved_files["front_id"],
            "back_id_filename": saved_files["back_id"],
            "face_image_filename": saved_files["face_image"],
            # Base64 data for immediate display
            "front_id_data": data["front_id"],
            "back_id_data": data["back_id"],
            "face_image_data": data["face_image"],
            "status": "pending",
            "submitted_at": datetime.now(timezone.utc),
            "reviewed_at": None,
            "reviewed_by": None,
            "notes": "",
            "doc_type": data.get("doc_type", "national_id"),
            "doc_number": data.get("doc_number", "")
        }
        
        # Handle existing KYC or create new
        if existing_kyc:
            # Clean up old files before updating
            old_fields = ["front_id_filename", "back_id_filename", "face_image_filename"]
            for field in old_fields:
                if field in existing_kyc and existing_kyc[field]:
                    old_filepath = os.path.join(kyc_upload_dir, existing_kyc[field])
                    try:
                        if os.path.exists(old_filepath):
                            os.remove(old_filepath)
                    except Exception as e:
                        print(f"Warning: Failed to delete old {field}: {e}")
            
            # Update existing KYC
            kyc_collection.update_one(
                {"_id": existing_kyc["_id"]},
                {"$set": kyc_data}
            )
            kyc_id = existing_kyc["_id"]
        else:
            # Create new KYC submission
            result = kyc_collection.insert_one(kyc_data)
            kyc_id = result.inserted_id
        
        # ========== USER UPDATE PHASE ==========
        # Update user's KYC status
        users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {
                "kyc_status": "pending",
                "kyc_submitted_at": datetime.now(timezone.utc),
                "kyc_notification_dismissed": True
            }}
        )
        
        # Update session
        session["kyc_status"] = "pending"
        session["kyc_notification_dismissed"] = True
        
        # ========== NOTIFICATION PHASE ==========
        # Send email notification to admin (non-blocking)
        try:
            import threading
            email_thread = threading.Thread(
                target=send_kyc_notification_email,
                args=(email, username)
            )
            email_thread.daemon = True
            email_thread.start()
        except Exception as email_error:
            print(f"Email notification error: {email_error}")
            # Non-critical error, continue
        
        # ========== RESPONSE PHASE ==========
        return jsonify({
            "success": True, 
            "message": "KYC submitted successfully for review",
            "redirect_url": url_for("dashboard"),
            "kyc_id": str(kyc_id)
        })
        
    except Exception as e:
        print(f"Error in submit_kyc: {e}")
        return jsonify({
            "success": False, 
            "message": "Internal server error. Please try again later."
        }), 500

# Add this helper function for image compression
def compress_image(filepath, max_size_kb=1024):
    """Compress image if it's too large"""
    try:
        from PIL import Image
        import io
        
        # Check current size
        current_size_kb = os.path.getsize(filepath) / 1024
        if current_size_kb <= max_size_kb:
            return True
        
        # Open and compress image
        with Image.open(filepath) as img:
            # Convert to RGB if necessary
            if img.mode in ('RGBA', 'LA'):
                background = Image.new('RGB', img.size, (255, 255, 255))
                if img.mode == 'RGBA':
                    background.paste(img, mask=img.split()[-1])
                else:
                    background.paste(img, mask=img)
                img = background
            
            # Save with compression
            img.save(filepath, 'JPEG', optimize=True, quality=85)
            
        return True
        
    except ImportError:
        print("PIL/Pillow not installed, skipping compression")
        return False
    except Exception as e:
        print(f"Error compressing image: {e}")
        return False


# Helper function for KYC email notifications
def send_kyc_notification_email(user_email, username):
    """Send email to admin about new KYC submission - With timeout"""
    try:
        admin_emails = ["admin@bigwinners.com"]  # Add your admin emails
        
        # Check if email is configured
        if not app.config.get("MAIL_USERNAME") or not app.config.get("MAIL_PASSWORD"):
            print("Email not configured, skipping notification")
            return
        
        msg = Message(
            "New KYC Submission - Big Winners",
            recipients=admin_emails,
            sender=app.config["MAIL_DEFAULT_SENDER"]
        )
        
        msg.html = f"""
        <h3>New KYC Submission Received</h3>
        <p><strong>User:</strong> {username}</p>
        <p><strong>Email:</strong> {user_email}</p>
        <p><strong>Submitted At:</strong> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
        <p>Please review the KYC submission in the admin dashboard.</p>
        <a href="{url_for('admin_kyc_review', _external=True)}" 
           style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
           Review KYC Submissions
        </a>
        """
        
        # Send with timeout
        import socket
        socket.setdefaulttimeout(10)  # 10 second timeout
        
        mail.send(msg)
        print(f"KYC notification email sent for user: {username}")
    except socket.timeout:
        print("Email sending timeout - continuing without email")
    except Exception as e:
        print(f"Error sending KYC notification email: {e}")
        # Don't crash the app - just log the error

@app.route("/admin/kyc_details/<kyc_id>")
@admin_required
def kyc_details(kyc_id):
    """Get detailed KYC information for admin view"""
    try:
        kyc = kyc_collection.find_one({"_id": ObjectId(kyc_id)})
        if not kyc:
            return jsonify({"error": "KYC not found"}), 404
        
        # Convert ObjectId to string for JSON serialization
        kyc["_id"] = str(kyc["_id"])
        kyc["user_id"] = str(kyc["user_id"])
        
        # Convert dates to string
        if kyc.get("submitted_at"):
            kyc["submitted_at"] = kyc["submitted_at"].isoformat()
        if kyc.get("reviewed_at"):
            kyc["reviewed_at"] = kyc["reviewed_at"].isoformat()
        
        return jsonify(kyc)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/kyc_review")
@admin_required
def admin_kyc_review():
    """Admin page to review pending KYC submissions"""
    # Get KYC submissions
    pending_kyc = list(kyc_collection.find({"status": "pending"}).sort("submitted_at", -1))
    approved_kyc = list(kyc_collection.find({"status": "approved"}).sort("reviewed_at", -1).limit(20))
    rejected_kyc = list(kyc_collection.find({"status": "rejected"}).sort("reviewed_at", -1).limit(20))
    
    # Ensure consistent data format for all submissions
    all_kyc = pending_kyc + approved_kyc + rejected_kyc
    for kyc in all_kyc:
        # Ensure all required fields exist
        kyc.setdefault('front_id_filename', '')
        kyc.setdefault('back_id_filename', '')
        kyc.setdefault('face_image_filename', '')
        kyc.setdefault('front_id_data', '')
        kyc.setdefault('back_id_data', '')
        kyc.setdefault('face_image_data', '')
        kyc.setdefault('doc_type', '')
        kyc.setdefault('doc_number', '')
        kyc.setdefault('fullname', '')
        kyc.setdefault('notes', '')
        kyc.setdefault('reviewed_by', '')
        kyc.setdefault('reviewed_at', None)
    
    return render_template(
        "admin_kyc_review.html",
        pending_kyc=pending_kyc,
        approved_kyc=approved_kyc,
        rejected_kyc=rejected_kyc
    )


@app.route("/admin/approve_kyc/<kyc_id>", methods=["POST"])
@admin_required
def approve_kyc(kyc_id):
    """Approve a KYC submission"""
    try:
        kyc = kyc_collection.find_one({"_id": ObjectId(kyc_id)})
        if not kyc:
            flash("KYC submission not found", "danger")
            return redirect(url_for("admin_kyc_review"))
        
        # Update KYC status
        kyc_collection.update_one(
            {"_id": ObjectId(kyc_id)},
            {"$set": {
                "status": "approved",
                "reviewed_at": datetime.now(timezone.utc),
                "reviewed_by": session.get("user"),
                "notes": request.form.get("notes", "")
            }}
        )
        
        # Update user's KYC status
        users_collection.update_one(
            {"_id": ObjectId(kyc["user_id"])},
            {"$set": {"kyc_status": "verified"}}
        )
        
        # Send approval email to user
        try:
            send_kyc_approval_email(kyc["email"], kyc["username"])
        except:
            pass
        
        flash("KYC approved successfully", "success")
        return redirect(url_for("admin_kyc_review"))
        
    except Exception as e:
        flash(f"Error approving KYC: {str(e)}", "danger")
        return redirect(url_for("admin_kyc_review"))

@app.route("/admin/reject_kyc/<kyc_id>", methods=["POST"])
@admin_required
def reject_kyc(kyc_id):
    """Reject a KYC submission"""
    try:
        kyc = kyc_collection.find_one({"_id": ObjectId(kyc_id)})
        if not kyc:
            flash("KYC submission not found", "danger")
            return redirect(url_for("admin_kyc_review"))
        
        # Update KYC status
        kyc_collection.update_one(
            {"_id": ObjectId(kyc_id)},
            {"$set": {
                "status": "rejected",
                "reviewed_at": datetime.now(timezone.utc),
                "reviewed_by": session.get("user"),
                "notes": request.form.get("notes", "KYC rejected. Please ensure documents are clear and match your identity.")
            }}
        )
        
        # Update user's KYC status
        users_collection.update_one(
            {"_id": ObjectId(kyc["user_id"])},
            {"$set": {"kyc_status": "rejected"}}
        )
        
        # Update session if this is the current user
        if session.get("user_id") == kyc["user_id"]:
            session["kyc_status"] = "rejected"
        
        # Send rejection email to user
        try:
            send_kyc_rejection_email(kyc["email"], kyc["username"], request.form.get("notes", ""))
        except:
            pass
        
        flash("KYC rejected", "warning")
        return redirect(url_for("admin_kyc_review"))
        
    except Exception as e:
        flash(f"Error rejecting KYC: {str(e)}", "danger")
        return redirect(url_for("admin_kyc_review"))

def send_kyc_approval_email(user_email, username):
    """Send KYC approval email to user"""
    msg = Message(
        "KYC Verification Approved - Big Winners",
        recipients=[user_email],
        sender=app.config["MAIL_DEFAULT_SENDER"]
    )
    
    msg.html = f"""
    <h3>KYC Verification Approved!</h3>
    <p>Dear {username},</p>
    <p>We're pleased to inform you that your KYC verification has been approved.</p>
    <p>You now have full access to all features on Big Winners platform.</p>
    <p>Thank you for completing the verification process.</p>
    <p><strong>The Big Winners Team</strong></p>
    """
    
    mail.send(msg)

def send_kyc_rejection_email(user_email, username, notes):
    """Send KYC rejection email to user"""
    msg = Message(
        "KYC Verification Update - Big Winners",
        recipients=[user_email],
        sender=app.config["MAIL_DEFAULT_SENDER"]
    )
    
    msg.html = f"""
    <h3>KYC Verification Requires Attention</h3>
    <p>Dear {username},</p>
    <p>Your KYC verification submission requires additional attention.</p>
    <p><strong>Reason:</strong> {notes}</p>
    <p>Please login to your account and resubmit your KYC documents with the following in mind:</p>
    <ul>
        <li>Ensure all documents are clear and legible</li>
        <li>Make sure photos are well-lit</li>
        <li>Ensure the face photo matches the ID photo</li>
        <li>All information should be visible and not cropped</li>
    </ul>
    <a href="{url_for('kyc_verification', _external=True)}" 
       style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
       Resubmit KYC Documents
    </a>
    <p><strong>The Big Winners Team</strong></p>
    """
    
    mail.send(msg)

@app.route("/kyc_image/<path:filename>")
def kyc_image(filename):
    """Serve KYC images from the uploads/kyc_docs directory"""
    # Security check: ensure the path is within the kyc_docs directory
    if ".." in filename or filename.startswith("/"):
        abort(404)
    
    # Get the full path
    kyc_upload_dir = os.path.join(app.config["UPLOAD_FOLDER"], "kyc_docs")
    filepath = os.path.join(kyc_upload_dir, filename)
    
    # Check if file exists
    if not os.path.exists(filepath):
        abort(404)
    
    # Determine content type
    if filename.lower().endswith('.pdf'):
        mime_type = 'application/pdf'
    elif filename.lower().endswith('.png'):
        mime_type = 'image/png'
    else:
        mime_type = 'image/jpeg'
    
    return send_file(filepath, mimetype=mime_type)

crypto_payments_collection = db["crypto_payments"]

@app.route("/submit_crypto_payment", methods=["POST"])
def submit_crypto_payment():
    """Handle crypto payment submissions with screenshots"""
    if "user_email" not in session:
        return jsonify({"status": "error", "message": "Not logged in"}), 401

    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ["amount_usd", "plan", "country", "crypto_type", "wallet_address", "payment_screenshot"]
        for field in required_fields:
            if not data.get(field):
                return jsonify({"status": "error", "message": f"Missing {field}"}), 400

        # Validate crypto type
        valid_crypto_types = ["BTC", "USDT_ERC20", "USDT_TRC20"]
        if data["crypto_type"] not in valid_crypto_types:
            return jsonify({"status": "error", "message": "Invalid crypto type"}), 400

        # Generate filename for screenshot
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"crypto_payment_{session['user_id']}_{timestamp}.jpg"
        
        # Create crypto payments directory
        crypto_upload_dir = os.path.join(app.config["UPLOAD_FOLDER"], "crypto_payments")
        os.makedirs(crypto_upload_dir, exist_ok=True)
        
        # Process screenshot
        screenshot_data = data["payment_screenshot"]
        if screenshot_data.startswith('data:image'):
            screenshot_data = screenshot_data.split(',')[1] if ',' in screenshot_data else screenshot_data
        
        try:
            image_data = base64.b64decode(screenshot_data)
            filepath = os.path.join(crypto_upload_dir, filename)
            
            with open(filepath, 'wb') as f:
                f.write(image_data)
            
            # Compress if too large
            if os.path.getsize(filepath) > 2 * 1024 * 1024:
                compress_image(filepath)
                
        except Exception as e:
            print(f"Error processing screenshot: {e}")
            return jsonify({"status": "error", "message": "Invalid screenshot format"}), 400

        # Save payment record
        payment_data = {
            "user_id": session["user_id"],
            "username": session["user"],
            "email": session["user_email"],
            "plan": data["plan"],
            "country": data["country"],
            "amount_usd": float(data["amount_usd"]),
            "crypto_type": data["crypto_type"],
            "wallet_address": data["wallet_address"],
            "screenshot_filename": filename,
            "status": "pending",
            "created_at": datetime.now(timezone.utc),
            "approved_at": None,
            "admin_notes": ""
        }
        
        crypto_payments_collection.insert_one(payment_data)
        
        # Update user status
        users_collection.update_one(
            {"_id": ObjectId(session["user_id"])},
            {"$set": {"investment_status": "pending_crypto_payment"}}
        )
        
        # Update session
        session["investment_status"] = "pending_crypto_payment"
        
        # Send email notification to admin
        try:
            send_crypto_payment_notification(session["user_email"], session["user"], 
                                           data["crypto_type"], float(data["amount_usd"]))
        except Exception as e:
            print(f"Email notification error: {e}")
            # Non-critical error, continue
        
        return jsonify({
            "status": "success", 
            "message": "Crypto payment submitted for review. Redirecting to dashboard...",
            "redirect_url": url_for("dashboard")
        })
        
    except Exception as e:
        print(f"Error in submit_crypto_payment: {e}")
        return jsonify({
            "status": "error", 
            "message": "Internal server error. Please try again later."
        }), 500
def send_crypto_payment_notification(email, username, crypto_type, amount):
    """Send email notification for crypto payment"""
    try:
        # Skip email sending entirely on Render
        if os.environ.get("RENDER"):
            print("Skipping email sending on Render")
            return

        if not app.config.get("MAIL_USERNAME") or not app.config.get("MAIL_PASSWORD"):
            print("Mail credentials missing, skipping email")
            return

        admin_emails = ["admin@bigwinners.com"]

        msg = Message(
            f"New Crypto Payment - {crypto_type} - Big Winners",
            recipients=admin_emails,
            sender=app.config["MAIL_DEFAULT_SENDER"]
        )

        msg.html = f""" ... """

        mail.send(msg)
        print(f"Crypto payment notification sent for user: {username}")

    except Exception as e:
        print(f"Error sending crypto payment email: {e}")


@app.route("/admin/crypto_payments")
@admin_required
def admin_crypto_payments():
    """Admin page to review crypto payments"""
    pending_payments = list(crypto_payments_collection.find({"status": "pending"}).sort("created_at", -1))
    approved_payments = list(crypto_payments_collection.find({"status": "approved"}).sort("approved_at", -1).limit(20))
    
    return render_template("admin_crypto_payments.html",
                         pending_payments=pending_payments,
                         approved_payments=approved_payments)

@app.route("/admin/approve_crypto_payment/<payment_id>", methods=["POST"])
@admin_required
def approve_crypto_payment(payment_id):
    """Approve a crypto payment"""
    try:
        payment = crypto_payments_collection.find_one({"_id": ObjectId(payment_id)})
        if not payment:
            flash("Payment not found", "danger")
            return redirect(url_for("admin_crypto_payments"))
        
        # Update payment status
        crypto_payments_collection.update_one(
            {"_id": ObjectId(payment_id)},
            {"$set": {
                "status": "approved",
                "approved_at": datetime.now(timezone.utc),
                "approved_by": session.get("user"),
                "admin_notes": request.form.get("notes", "")
            }}
        )
        
        # Activate user investment
        users_collection.update_one(
            {"_id": ObjectId(payment["user_id"])},
            {"$set": {
                "investment_status": "active",
                "initial_investment": payment["amount_usd"],
                "investment_time": datetime.now(timezone.utc)
            }}
        )
        
        flash("Crypto payment approved and investment activated!", "success")
        return redirect(url_for("admin_crypto_payments"))
        
    except Exception as e:
        flash(f"Error approving payment: {str(e)}", "danger")
        return redirect(url_for("admin_crypto_payments"))

@app.route("/admin/reject_crypto_payment/<payment_id>", methods=["POST"])
@admin_required
def reject_crypto_payment(payment_id):
    """Reject a crypto payment"""
    try:
        crypto_payments_collection.update_one(
            {"_id": ObjectId(payment_id)},
            {"$set": {
                "status": "rejected",
                "admin_notes": request.form.get("notes", "Payment rejected. Please check the transaction and try again.")
            }}
        )
        
        flash("Crypto payment rejected", "warning")
        return redirect(url_for("admin_crypto_payments"))
    except Exception as e:
        flash(f"Error rejecting payment: {str(e)}", "danger")
        return redirect(url_for("admin_crypto_payments"))

@app.route("/crypto_image/<path:filename>")
def crypto_image(filename):
    """Serve crypto payment screenshots from the uploads/crypto_payments directory"""
    # Security check: ensure the path is within the crypto_payments directory
    if ".." in filename or filename.startswith("/"):
        abort(404)
    
    crypto_upload_dir = os.path.join(app.config["UPLOAD_FOLDER"], "crypto_payments")
    filepath = os.path.join(crypto_upload_dir, filename)
    
    # Check if file exists
    if not os.path.exists(filepath):
        abort(404)
    
    # Determine content type
    if filename.lower().endswith('.png'):
        mime_type = 'image/png'
    elif filename.lower().endswith('.gif'):
        mime_type = 'image/gif'
    elif filename.lower().endswith('.pdf'):
        mime_type = 'application/pdf'
    else:
        mime_type = 'image/jpeg'
    
    return send_file(filepath, mimetype=mime_type)

@app.route("/create_paypal_order", methods=["POST"])
def create_paypal_order():
    """Create a PayPal order for payment with proper merchant configuration"""
    if "user_email" not in session:
        return jsonify({"status": "error", "message": "Not logged in"}), 401
    
    try:
        data = request.get_json()
        amount_usd = float(data.get("amount_usd", 0))
        plan = data.get("plan", "unknown")
        country = data.get("country", "")
        
        if amount_usd <= 0:
            return jsonify({"status": "error", "message": "Invalid amount"}), 400
        
        # Generate unique order ID
        order_id = f"BW{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}{random.randint(1000, 9999)}"
        
        # Get merchant email from environment or use default
        merchant_email = os.getenv("PAYPAL_MERCHANT_EMAIL", "")
        
        # Create PayPal payment with payee information
        payment_data = {
            "intent": "sale",
            "payer": {
                "payment_method": "paypal"
            },
            "redirect_urls": {
                "return_url": url_for('paypal_success', _external=True),
                "cancel_url": url_for('paypal_cancel', _external=True)
            },
            "transactions": [{
                "amount": {
                    "total": str(round(amount_usd, 2)),
                    "currency": "USD"
                },
                "description": f"Big Winners Investment - {plan} Plan",
                "custom": json.dumps({
                    "user_id": session["user_id"],
                    "plan": plan,
                    "country": country,
                    "order_id": order_id
                }),
                "invoice_number": order_id,
                "item_list": {
                    "items": [{
                        "name": f"{plan.capitalize()} Plan Investment",
                        "sku": f"BW-{plan.upper()}",
                        "price": str(round(amount_usd, 2)),
                        "currency": "USD",
                        "quantity": 1
                    }]
                }
            }]
        }
        
        # Add payee information if merchant email is available
        if merchant_email:
            payment_data["transactions"][0]["payee"] = {
                "email": merchant_email
            }
        
        try:
            payment = paypalrestsdk.Payment(payment_data)
            
            if payment.create():
                # Save payment to database
                paypal_payments_collection.insert_one({
                    "user_id": session["user_id"],
                    "email": session["user_email"],
                    "username": session.get("user", ""),
                    "plan": plan,
                    "country": country,
                    "amount_usd": amount_usd,
                    "order_id": order_id,
                    "paypal_payment_id": payment.id,
                    "merchant_email": merchant_email,
                    "status": "created",
                    "created_at": datetime.now(timezone.utc),
                    "paypal_links": [link.to_dict() for link in payment.links]
                })
                
                # Find approval URL
                approval_url = None
                for link in payment.links:
                    if link.rel == "approval_url":
                        approval_url = link.href
                        break
                
                return jsonify({
                    "status": "success",
                    "payment_id": payment.id,
                    "approval_url": approval_url,
                    "order_id": order_id
                })
            else:
                print(f"PayPal payment creation error: {payment.error}")
                return jsonify({"status": "error", "message": f"Payment creation failed: {payment.error}"}), 400
                
        except Exception as paypal_error:
            print(f"PayPal SDK error: {paypal_error}")
            return jsonify({
                "status": "error", 
                "message": f"PayPal service error: {str(paypal_error)}"
            }), 503
        
    except Exception as e:
        print(f"Error creating PayPal order: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500
    
@app.route("/process_card_payment", methods=["POST"])
def process_card_payment():
    """Process card payment with PayPal - Fixed version with database recording"""
    if "user_email" not in session:
        return jsonify({"status": "error", "message": "Not logged in"}), 401
    
    try:
        data = request.get_json()
        
        # Debug: Print received data (remove in production)
        print(f"Card payment data received: {data}")
        
        # Get card details from the request
        card_details = {
            "type": data.get("card_type", "visa").lower(),
            "number": data.get("card_number", "").replace(" ", ""),
            "expire_month": data.get("expire_month", ""),
            "expire_year": data.get("expire_year", ""),
            "cvv2": data.get("cvv", ""),
            "first_name": data.get("first_name", ""),
            "last_name": data.get("last_name", "")
        }
        
        print(f"Card details: {card_details['type']}, Last 4: {card_details['number'][-4:] if card_details['number'] else 'N/A'}")
        
        # Validate card details
        validation_errors = []
        if not card_details["number"]:
            validation_errors.append("Card number is required")
        if len(card_details["number"]) not in [13, 14, 15, 16]:
            validation_errors.append("Invalid card number length")
        if not card_details["expire_month"] or not card_details["expire_year"]:
            validation_errors.append("Expiry date is required")
        if not card_details["cvv2"]:
            validation_errors.append("CVV is required")
        
        if validation_errors:
            return jsonify({
                "status": "error", 
                "message": "Invalid card details: " + ", ".join(validation_errors)
            }), 400
        
        amount_usd = float(data.get("amount_usd", 0))
        plan = data.get("plan", "unknown")
        email = data.get("email", session["user_email"])
        
        if amount_usd <= 0:
            return jsonify({"status": "error", "message": "Invalid amount"}), 400
        
        # Get merchant email
        merchant_email = os.getenv("PAYPAL_MERCHANT_EMAIL", "")
        
        if not merchant_email:
            print("ERROR: PAYPAL_MERCHANT_EMAIL not set in environment")
            return jsonify({
                "status": "error", 
                "message": "Payment processor configuration error. Please try another payment method or contact support."
            }), 400
        
        # Generate unique order ID
        order_id = f"BW_CARD_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}{random.randint(1000, 9999)}"
        
        print(f"Creating PayPal payment for ${amount_usd}, Order ID: {order_id}")
        
        # Save card payment record BEFORE processing (for tracking)
        card_payment_record = {
            "user_id": session["user_id"],
            "email": session["user_email"],
            "username": session.get("user", ""),
            "plan": plan,
            "amount_usd": amount_usd,
            "card_type": card_details["type"],
            "card_last4": card_details["number"][-4:] if len(card_details["number"]) >= 4 else "",
            "expiry_month": card_details["expire_month"],
            "expiry_year": card_details["expire_year"],
            "order_id": order_id,
            "payment_processor": "paypal",
            "merchant_email": merchant_email,
            "status": "processing",
            "created_at": datetime.now(timezone.utc),
            "ip_address": request.remote_addr,
            "user_agent": request.headers.get('User-Agent', '')
        }
        
        # Insert into card_payments collection
        card_payment_id = card_payments_collection.insert_one(card_payment_record).inserted_id
        print(f"Card payment record created: {card_payment_id}")
        
        # Create PayPal payment with card
        payment_data = {
            "intent": "sale",
            "payer": {
                "payment_method": "credit_card",
                "funding_instruments": [{
                    "credit_card": {
                        "type": card_details["type"],
                        "number": card_details["number"],
                        "expire_month": card_details["expire_month"],
                        "expire_year": card_details["expire_year"],
                        "cvv2": card_details["cvv2"],
                        "first_name": card_details["first_name"] or "Customer",
                        "last_name": card_details["last_name"] or "Customer",
                        "billing_address": {
                            "line1": "123 Main St",
                            "city": "San Jose",
                            "state": "CA",
                            "postal_code": "95131",
                            "country_code": "US"
                        }
                    }
                }]
            },
            "transactions": [{
                "amount": {
                    "total": str(round(amount_usd, 2)),
                    "currency": "USD"
                },
                "description": f"Big Winners {plan.capitalize()} Plan Investment",
                "invoice_number": order_id,
                "payee": {
                    "email": merchant_email
                }
            }]
        }
        
        print(f"Payment data prepared, merchant email: {merchant_email}")
        
        try:
            payment = paypalrestsdk.Payment(payment_data)
            
            if payment.create():
                print(f"PayPal payment created successfully: {payment.id}")
                
                # Update card payment record with PayPal ID
                card_payments_collection.update_one(
                    {"_id": card_payment_id},
                    {"$set": {
                        "paypal_payment_id": payment.id,
                        "status": "created"
                    }}
                )
                
                # Execute payment
                if payment.execute({"payer_id": payment.payer.payer_info.payer_id}):
                    print(f"Payment executed successfully: {payment.id}")
                    
                    # Get transaction details
                    transaction_id = ""
                    if payment.transactions and payment.transactions[0].related_resources:
                        transaction_id = payment.transactions[0].related_resources[0].sale.id
                    
                    # Update card payment record with success
                    card_payments_collection.update_one(
                        {"_id": card_payment_id},
                        {"$set": {
                            "status": "completed",
                            "transaction_id": transaction_id,
                            "completed_at": datetime.now(timezone.utc),
                            "paypal_response": payment.to_dict()
                        }}
                    )
                    
                    # Also save to paypal_payments_collection for backward compatibility
                    paypal_payments_collection.insert_one({
                        "user_id": session["user_id"],
                        "email": session["user_email"],
                        "username": session.get("user", ""),
                        "plan": plan,
                        "amount_usd": amount_usd,
                        "order_id": order_id,
                        "paypal_payment_id": payment.id,
                        "merchant_email": merchant_email,
                        "status": "completed",
                        "payment_type": "card",
                        "card_last4": card_details["number"][-4:],
                        "card_type": card_details["type"],
                        "created_at": datetime.now(timezone.utc),
                        "completed_at": datetime.now(timezone.utc),
                        "transaction_id": transaction_id
                    })
                    
                    # Update user investment
                    users_collection.update_one(
                        {"_id": ObjectId(session["user_id"])},
                        {"$set": {
                            "investment_status": "active",
                            "initial_investment": amount_usd,
                            "investment_time": datetime.now(timezone.utc)
                        }}
                    )
                    
                    # Update session
                    session.update({
                        "investment": f"${amount_usd:.2f} invested",
                        "total_investment": f"${amount_usd:.2f}",
                        "investment_status": "active"
                    })
                    
                    # Send confirmation email
                    try:
                        send_payment_confirmation_email(
                            email,
                            session["user"],
                            amount_usd,
                            plan,
                            transaction_id or order_id,
                            "card"
                        )
                    except Exception as email_error:
                        print(f"Email error (non-critical): {email_error}")
                    
                    return jsonify({
                        "status": "success",
                        "message": "Payment successful! Your investment is now active.",
                        "transaction_id": transaction_id,
                        "amount_usd": amount_usd,
                        "plan": plan,
                        "order_id": order_id,
                        "payment_id": str(card_payment_id)
                    })
                else:
                    print(f"Payment execution failed: {payment.error}")
                    
                    # Update card payment record with failure
                    card_payments_collection.update_one(
                        {"_id": card_payment_id},
                        {"$set": {
                            "status": "failed",
                            "error_message": str(payment.error),
                            "failed_at": datetime.now(timezone.utc)
                        }}
                    )
                    
                    return jsonify({
                        "status": "error", 
                        "message": f"Payment failed: {payment.error.get('message', 'Unknown error')}"
                    }), 400
            else:
                print(f"Payment creation failed: {payment.error}")
                
                # Update card payment record with creation failure
                card_payments_collection.update_one(
                    {"_id": card_payment_id},
                    {"$set": {
                        "status": "creation_failed",
                        "error_message": str(payment.error),
                        "failed_at": datetime.now(timezone.utc)
                    }}
                )
                
                return jsonify({
                    "status": "error", 
                    "message": f"Payment creation failed: {payment.error.get('message', 'Unknown error')}"
                }), 400
                
        except Exception as paypal_error:
            print(f"PayPal processing exception: {paypal_error}")
            
            # Update card payment record with exception
            card_payments_collection.update_one(
                {"_id": card_payment_id},
                {"$set": {
                    "status": "exception",
                    "error_message": str(paypal_error),
                    "failed_at": datetime.now(timezone.utc)
                }}
            )
            
            return jsonify({
                "status": "error", 
                "message": f"Payment processing error: {str(paypal_error)}"
            }), 400
            
    except Exception as e:
        print(f"General error in process_card_payment: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "status": "error", 
            "message": f"Payment processing error: {str(e)}"
        }), 500

@app.route("/check_paypal_config", methods=["GET"])
def check_paypal_config():
    """Check if PayPal is properly configured"""
    config_status = {
        "client_id_configured": bool(PAYPAL_CLIENT_ID),
        "client_secret_configured": bool(PAYPAL_CLIENT_SECRET),
        "mode": PAYPAL_MODE,
        "sdk_version": paypalrestsdk.__version__ if 'paypalrestsdk' in locals() else "Not loaded"
    }
    
    return jsonify(config_status)


@app.route("/paypal/success")
def paypal_success():
    """Handle successful PayPal payment return"""
    try:
        payment_id = request.args.get('paymentId')
        payer_id = request.args.get('PayerID')
        
        if not payment_id or not payer_id:
            flash("Payment information missing", "error")
            return redirect(url_for("dashboard"))
        
        # Execute the payment
        payment = paypalrestsdk.Payment.find(payment_id)
        
        if payment.execute({"payer_id": payer_id}):
            # Update payment status in database
            payment_data = paypal_payments_collection.find_one({"paypal_payment_id": payment_id})
            
            if payment_data:
                # Get transaction details
                transaction = payment.transactions[0]
                amount_usd = float(transaction.amount.total)
                
                # Update payment record
                paypal_payments_collection.update_one(
                    {"paypal_payment_id": payment_id},
                    {"$set": {
                        "status": "completed",
                        "payer_id": payer_id,
                        "completed_at": datetime.now(timezone.utc),
                        "transaction_details": transaction.to_dict()
                    }}
                )
                
                # Update user investment
                users_collection.update_one(
                    {"_id": ObjectId(payment_data["user_id"])},
                    {"$set": {
                        "investment_status": "active",
                        "initial_investment": amount_usd,
                        "investment_time": datetime.now(timezone.utc)
                    }}
                )
                
                # Update session if this is the current user
                if session.get("user_id") == payment_data["user_id"]:
                    session.update({
                        "investment": f"${amount_usd:.2f} invested",
                        "total_investment": f"${amount_usd:.2f}",
                        "investment_status": "active"
                    })
                
                flash("Payment successful! Your investment is now active.", "success")
                
                # Send confirmation email
                try:
                    send_payment_confirmation_email(
                        payment_data["email"],
                        payment_data["username"],
                        amount_usd,
                        payment_data["plan"]
                    )
                except Exception as email_error:
                    print(f"Email error: {email_error}")
                
            else:
                flash("Payment completed but record not found", "warning")
            
            return redirect(url_for("dashboard"))
        else:
            flash(f"Payment execution failed: {payment.error}", "error")
            return redirect(url_for("invest"))
            
    except Exception as e:
        print(f"Error in paypal_success: {e}")
        flash("Payment processing error", "error")
        return redirect(url_for("dashboard"))


@app.route("/paypal/cancel")
def paypal_cancel():
    """Handle cancelled PayPal payment"""
    flash("Payment was cancelled", "warning")
    return redirect(url_for("invest"))


@app.route("/paypal/webhook", methods=["POST"])
def paypal_webhook():
    """Handle PayPal webhook events"""
    try:
        # Get webhook event
        body = request.get_data(as_text=True)
        event_body = json.loads(body)
        
        # Verify webhook signature (simplified - in production use proper verification)
        event_type = event_body.get('event_type', '')
        resource = event_body.get('resource', {})
        
        if event_type == 'PAYMENT.SALE.COMPLETED':
            # Handle completed payment
            payment_id = resource.get('parent_payment')
            if payment_id:
                # Update payment status
                paypal_payments_collection.update_one(
                    {"paypal_payment_id": payment_id},
                    {"$set": {
                        "status": "webhook_confirmed",
                        "webhook_received_at": datetime.now(timezone.utc)
                    }}
                )
        
        return jsonify({"status": "success"}), 200
        
    except Exception as e:
        print(f"PayPal webhook error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

def send_payment_confirmation_email(email, username, amount, plan, reference, payment_method):
    """Send payment confirmation email for different payment methods"""
    try:
        payment_method_text = ""
        if payment_method == "international_card":
            payment_method_text = "International Card Payment"
        elif payment_method == "crypto":
            payment_method_text = "Cryptocurrency"
        elif payment_method == "manual":
            payment_method_text = "Bank Transfer"
        else:
            payment_method_text = "Payment"
        
        msg = Message(
            f"Payment Confirmation - {payment_method_text} - Big Winners",
            recipients=[email],
            sender=app.config["MAIL_DEFAULT_SENDER"]
        )
        
        msg.html = f"""
        <h3>Payment Confirmed!</h3>
        <p>Dear {username},</p>
        <p>Your {payment_method_text.lower()} of <strong>${amount:.2f} USD</strong> for the <strong>{plan.capitalize()} Plan</strong> has been successfully processed.</p>
        <p><strong>Reference:</strong> {reference}</p>
        <p>Your investment is now active and will start earning returns immediately.</p>
        <p>You can track your investment progress in your dashboard.</p>
        <p><strong>Thank you for investing with Big Winners!</strong></p>
        <p><em>The Big Winners Team</em></p>
        """
        
        mail.send(msg)
        print(f"Payment confirmation email sent to {email}")
    except Exception as e:
        print(f"Error sending payment confirmation email: {e}")


@app.route("/check_paypal_payment_status/<payment_id>", methods=["GET"])
def check_paypal_payment_status(payment_id):
    """Check the status of a PayPal payment"""
    if "user_email" not in session:
        return jsonify({"status": "error", "message": "Not logged in"}), 401
    
    try:
        # Check in our database
        payment = paypal_payments_collection.find_one({
            "paypal_payment_id": payment_id,
            "user_id": session["user_id"]
        })
        
        if not payment:
            return jsonify({"status": "error", "message": "Payment not found"}), 404
        
        return jsonify({
            "status": "success",
            "payment_status": payment.get("status", "unknown"),
            "amount_usd": payment.get("amount_usd", 0),
            "order_id": payment.get("order_id", "")
        })
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
@app.route("/create_paypal_card_order", methods=["POST"])
def create_paypal_card_order():
    """Create a PayPal order specifically for card payments"""
    if "user_email" not in session:
        return jsonify({"status": "error", "message": "Not logged in"}), 401
    
    try:
        data = request.get_json()
        amount_usd = float(data.get("amount_usd", 0))
        plan = data.get("plan", "unknown")
        country = data.get("country", "")
        
        if amount_usd <= 0:
            return jsonify({"status": "error", "message": "Invalid amount"}), 400
        
        # Generate unique order ID
        order_id = f"BW_CARD_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}{random.randint(1000, 9999)}"
        
        # Create PayPal payment for card processing
        payment = paypalrestsdk.Payment({
            "intent": "sale",
            "payer": {
                "payment_method": "credit_card",
                "funding_instruments": [{
                    "credit_card": {
                        "type": "visa",  # This will be overridden by actual card data
                        "number": "4111111111111111",  # Placeholder - will be replaced by JS
                        "expire_month": "11",
                        "expire_year": "2028",
                        "cvv2": "123",
                        "first_name": "John",
                        "last_name": "Doe"
                    }
                }]
            },
            "transactions": [{
                "amount": {
                    "total": str(round(amount_usd, 2)),
                    "currency": "USD"
                },
                "description": f"Big Winners Investment - {plan} Plan - Card Payment",
                "custom": json.dumps({
                    "user_id": session["user_id"],
                    "plan": plan,
                    "country": country,
                    "order_id": order_id,
                    "payment_type": "card"
                }),
                "invoice_number": order_id,
                "item_list": {
                    "items": [{
                        "name": f"{plan.capitalize()} Plan Investment",
                        "sku": f"BW-{plan.upper()}-CARD",
                        "price": str(round(amount_usd, 2)),
                        "currency": "USD",
                        "quantity": 1
                    }]
                }
            }]
        })
        
        if payment.create():
            # Save payment to database
            paypal_payments_collection.insert_one({
                "user_id": session["user_id"],
                "email": session["user_email"],
                "username": session.get("user", ""),
                "plan": plan,
                "country": country,
                "amount_usd": amount_usd,
                "order_id": order_id,
                "paypal_payment_id": payment.id,
                "status": "created",
                "payment_type": "card",
                "created_at": datetime.now(timezone.utc)
            })
            
            return jsonify({
                "status": "success",
                "payment_id": payment.id,
                "order_id": order_id
            })
        else:
            return jsonify({"status": "error", "message": payment.error}), 400
        
    except Exception as e:
        print(f"Error creating PayPal card order: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/create_paystack_international_charge", methods=["POST"])
def create_paystack_international_charge():
    """Create a Paystack charge for international card payments in USD"""
    if "user_email" not in session:
        return jsonify({"status": "error", "message": "Not logged in"}), 401
    
    try:
        data = request.get_json()
        email = session["user_email"]
        amount_usd = float(data.get("amount_usd", 0))
        plan = data.get("plan", "unknown")
        country = data.get("country", "")
        
        if amount_usd <= 0:
            return jsonify({"status": "error", "message": "Invalid amount"}), 400
        
        # For international payments, we use USD directly
        # Paystack Kenya accepts USD for international payments
        amount_in_cents = int(amount_usd * 100)  # Paystack expects amount in cents for USD
        
        # Generate unique reference
        reference = f"BW_INT_{str(uuid.uuid4())[:8].upper()}_{datetime.now(timezone.utc).strftime('%Y%m%d')}"
        
        # Create Paystack charge with USD currency
        headers = {
            "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "email": email,
            "amount": amount_in_cents,  # Amount in cents
            "currency": "USD",  # USD for international payments
            "reference": reference,
            "metadata": {
                "plan": plan,
                "amount_usd": amount_usd,
                "country": country,
                "user_id": session.get("user_id"),
                "payment_type": "international_card",
                "payment_method": "card"
            },
            "channels": ["card"],  # Only card payments
            "callback_url": url_for('paystack_international_callback', _external=True),
            "cancel_url": url_for('invest', _external=True)
        }
        
        response = requests.post(
            "https://api.paystack.co/transaction/initialize",
            headers=headers,
            json=payload
        )
        response_data = response.json()
        
        if response_data.get("status"):
            # Save to card_payments collection
            card_payment_record = {
                "user_id": session["user_id"],
                "email": email,
                "username": session.get("user", ""),
                "plan": plan,
                "country": country,
                "amount_usd": amount_usd,
                "amount_charged": amount_usd,  # USD
                "currency": "USD",
                "reference": reference,
                "paystack_reference": response_data["data"]["reference"],
                "access_code": response_data["data"]["access_code"],
                "payment_processor": "paystack_international",
                "status": "initiated",
                "payment_type": "international_card",
                "created_at": datetime.now(timezone.utc),
                "ip_address": request.remote_addr
            }
            
            # Save to card_payments collection
            card_payment_id = card_payments_collection.insert_one(card_payment_record).inserted_id
            
            # Also save to paystack_international_payments for backward compatibility
            db["paystack_international_payments"].insert_one({
                **card_payment_record,
                "_id": card_payment_id  # Use same ID for reference
            })
            
            return jsonify({
                "status": "success",
                "authorization_url": response_data["data"]["authorization_url"],
                "reference": reference,
                "access_code": response_data["data"]["access_code"],
                "payment_id": str(card_payment_id)
            })
        
        return jsonify({
            "status": "error", 
            "message": response_data.get("message", "Payment initialization failed"),
            "details": response_data
        }), 400
        
    except Exception as e:
        print(f"Error creating Paystack international charge: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/paystack_international_callback", methods=["GET"])
def paystack_international_callback():
    """Handle Paystack international payment callback"""
    reference = request.args.get('reference')
    
    if not reference:
        flash("Payment reference missing!", "error")
        return redirect(url_for("dashboard"))
    
    try:
        # Verify payment with Paystack
        headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"}
        response = requests.get(
            f"https://api.paystack.co/transaction/verify/{reference}",
            headers=headers
        )
        data = response.json()
        
        if data["status"] and data["data"]["status"] == "success":
            # Get payment record
            payment = db["paystack_international_payments"].find_one({"reference": reference})
            
            if not payment:
                # Try to find by Paystack reference
                payment = db["paystack_international_payments"].find_one({"paystack_reference": reference})
            
            if not payment:
                flash("Payment record not found!", "error")
                return redirect(url_for("dashboard"))
            
            # Update card_payments collection
            card_payments_collection.update_one(
                {"reference": reference},
                {"$set": {
                    "status": "completed",
                    "verified_at": datetime.now(timezone.utc),
                    "paystack_data": data["data"],
                    "transaction_id": data["data"].get("id", ""),
                    "gateway_response": data["data"].get("gateway_response", ""),
                    "card_details": data["data"].get("authorization", {})
                }}
            )
            
            # Update paystack_international_payments collection
            db["paystack_international_payments"].update_one(
                {"_id": payment["_id"]},
                {"$set": {
                    "status": "completed",
                    "verified_at": datetime.now(timezone.utc),
                    "paystack_data": data["data"],
                    "transaction_id": data["data"].get("id", ""),
                    "gateway_response": data["data"].get("gateway_response", "")
                }}
            )
            
            # Activate user investment
            users_collection.update_one(
                {"_id": ObjectId(payment["user_id"])},
                {"$set": {
                    "investment_status": "active",
                    "initial_investment": payment["amount_usd"],
                    "investment_time": datetime.now(timezone.utc),
                    "investment_plan": payment["plan"]
                }}
            )
            
            # Update session if current user
            if session.get("user_id") == payment["user_id"]:
                session.update({
                    "investment": f"${payment['amount_usd']:.2f} invested",
                    "total_investment": f"${payment['amount_usd']:.2f}",
                    "investment_status": "active"
                })
            
            # Send confirmation email
            try:
                send_payment_confirmation_email(
                    payment["email"],
                    payment["username"],
                    payment["amount_usd"],
                    payment["plan"],
                    reference,
                    "international_card"
                )
            except Exception as email_error:
                print(f"Email error: {email_error}")
            
            flash("Card payment successful! Your investment is now active.", "success")
            return redirect(url_for("dashboard"))
        
        flash("Payment verification failed or was not successful!", "error")
        return redirect(url_for("invest"))
        
    except Exception as e:
        flash(f"Payment processing error: {str(e)}", "error")
        return redirect(url_for("dashboard"))

@app.route("/admin/card_payments_count", methods=["GET"])
@admin_required
def card_payments_count():
    """Get count of card payments"""
    try:
        total_payments = card_payments_collection.count_documents({})
        pending_payments = card_payments_collection.count_documents({"status": "pending"})
        
        return jsonify({
            "success": True,
            "total_payments": total_payments,
            "pending_payments": pending_payments
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route("/admin/pending_reviews_count", methods=["GET"])
@admin_required
def pending_reviews_count():
    """Get count of pending reviews"""
    try:
        count = pending_reviews_collection.count_documents({"status": "pending"})
        return jsonify({"success": True, "count": count})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route("/admin/card_payments")
@admin_required
def admin_card_payments():
    """Admin page to view all card payments"""
    # Get all card payments sorted by date
    card_payments = list(card_payments_collection.find().sort("created_at", -1))
    
    # Get stats
    total_payments = len(card_payments)
    total_amount = sum(p.get("amount_usd", 0) for p in card_payments)
    successful_payments = len([p for p in card_payments if p.get("status") == "completed"])
    failed_payments = len([p for p in card_payments if p.get("status") in ["failed", "creation_failed", "exception"]])
    
    return render_template("admin_card_payments.html",
                         card_payments=card_payments,
                         total_payments=total_payments,
                         total_amount=total_amount,
                         successful_payments=successful_payments,
                         failed_payments=failed_payments)

@app.route("/admin/card_payment_details/<payment_id>", methods=["GET"])
@admin_required
def card_payment_details(payment_id):
    """Get detailed card payment information"""
    try:
        payment = card_payments_collection.find_one({"_id": ObjectId(payment_id)})
        if not payment:
            return jsonify({"error": "Payment not found"}), 404
        
        # Convert ObjectId to string for JSON
        payment["_id"] = str(payment["_id"])
        payment["user_id"] = str(payment["user_id"])
        
        # Convert dates to string
        for date_field in ["created_at", "completed_at", "failed_at", "verified_at"]:
            if payment.get(date_field):
                payment[date_field] = payment[date_field].isoformat()
        
        return jsonify(payment)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/check_paystack_international_payment/<reference>", methods=["GET"])
def check_paystack_international_payment(reference):
    """Check status of Paystack international payment"""
    if "user_email" not in session:
        return jsonify({"status": "error", "message": "Not logged in"}), 401
    
    try:
        # Check in database first
        payment = db["paystack_international_payments"].find_one({
            "reference": reference,
            "user_id": session["user_id"]
        })
        
        if not payment:
            return jsonify({"status": "error", "message": "Payment not found"}), 404
        
        # Verify with Paystack if pending
        if payment["status"] in ["initiated", "pending"]:
            headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"}
            response = requests.get(
                f"https://api.paystack.co/transaction/verify/{payment['paystack_reference']}",
                headers=headers
            )
            verify_data = response.json()
            
            if verify_data["status"] and verify_data["data"]["status"] == "success":
                # Update payment status
                db["paystack_international_payments"].update_one(
                    {"_id": payment["_id"]},
                    {"$set": {
                        "status": "completed",
                        "verified_at": datetime.now(timezone.utc),
                        "paystack_data": verify_data["data"]
                    }}
                )
                
                # Activate investment
                users_collection.update_one(
                    {"_id": ObjectId(payment["user_id"])},
                    {"$set": {
                        "investment_status": "active",
                        "initial_investment": payment["amount_usd"],
                        "investment_time": datetime.now(timezone.utc)
                    }}
                )
                
                return jsonify({
                    "status": "completed",
                    "message": "Payment completed successfully"
                })
        
        return jsonify({
            "status": payment["status"],
            "message": f"Payment is {payment['status']}",
            "data": {
                "amount_usd": payment["amount_usd"],
                "currency": payment["currency"],
                "plan": payment["plan"],
                "created_at": payment["created_at"].isoformat() if payment.get("created_at") else None
            }
        })
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, port=5050)
