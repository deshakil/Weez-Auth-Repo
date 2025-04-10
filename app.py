from flask import Flask, request, jsonify, session, send_file
from flask_cors import CORS
import os
import jwt
from datetime import datetime, timedelta, timezone
import hashlib
import uuid
import json
import tempfile
import random
import string
from azure.storage.blob import BlobServiceClient, ContentSettings
from io import BytesIO
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

app = Flask(__name__)
CORS(app)

# Initialize Auth Dictionaries Container


# Azure Blob Storage configuration
AZURE_STORAGE_CONNECTION_STRING = os.getenv('AZURE_STORAGE_CONNECTION_STRING_1')
CONTAINER_NAME = "weez-users-info"
DEFAULT_PROFILE_PIC_URL = "https://i.pinimg.com/736x/23/a6/1f/23a61f584822b8c7dbaebdca7c96da3e.jpg"

# SendGrid configuration
SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY')
if not SENDGRID_API_KEY:
    raise ValueError("SENDGRID_API_KEY environment variable is not set")

# Initialize the BlobServiceClient
blob_service_client = BlobServiceClient.from_connection_string(AZURE_STORAGE_CONNECTION_STRING)
container_client = blob_service_client.get_container_client(CONTAINER_NAME)
try:
    if not container_client.exists():
        container_client.create_container()
except Exception as e:
    print(f"Error initializing container: {str(e)}")

AUTH_CONTAINER_NAME = "auth-dictionaries"
auth_container_client = blob_service_client.get_container_client(AUTH_CONTAINER_NAME)
try:
    if not auth_container_client.exists():
        auth_container_client.create_container()
except Exception as e:
    print(f"Error initializing auth container: {str(e)}")

# In-memory storage (replace with a database in production)
users_db = {}
active_tokens = {}
otps = {}
unverified_users = {}
incomplete_profiles = {}

def generate_otp(length=6):
    """Generate a random OTP of specified length."""
    return ''.join(random.choices(string.digits, k=length))

def send_email(to_email, subject, body):
    """Send an email using SendGrid."""
    try:
        message = Mail(
            from_email='support@em3196.weez.online',
            to_emails=to_email,
            subject=subject,
            html_content=body
        )
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        print(f"Email sent to {to_email} - Status: {response.status_code}")
        return response.status_code == 202  # 202 is SendGrid's success status
    except Exception as e:
        print(f"Email failed to {to_email}: {str(e)}")
        return False

def send_otp_email(email, otp, purpose="verification", user_name=None):
    """Send OTP email with purpose-specific messaging."""
    subject = "Weez OTP Verification Code"
    greeting = f"Dear {user_name}," if user_name else "Dear Weez User,"
    purpose_display = {
        "verification": "account verification",
        "login": "login attempt",
        "password_reset": "password reset",
        "email_change": "email change"
    }.get(purpose, "verification")
    body = f"""
    <html>
    <body>
        <p>{greeting}</p>
        <p>Welcome to Weez! To ensure the security of your account, please verify your email using the One-Time Password (OTP) below:</p>
        <h3>Your OTP: {otp}</h3>
        <p>This OTP is valid for 10 minutes and can only be used once.</p>
        <p><strong>Purpose:</strong> {purpose_display}</p>
        <p><strong>Important Security Guidelines:</strong></p>
        <ul>
            <li>Do not share this OTP with anyone, including Weez support staff.</li>
            <li>Do not enter your OTP on any unofficial websites or third-party apps.</li>
            <li>If you didn't request this OTP, please ignore this email or contact our support team immediately.</li>
        </ul>
        <p>If you have any questions, feel free to reach out to us at <a href="mailto:weatweez@gmail.com">weatweez@gmail.com</a>.</p>
        <p>Best regards,<br>The Weez Team</p>
    </body>
    </html>
    """
    return send_email(email, subject, body)


def load_auth_data(blob_name):
    """Load authentication data from blob storage"""
    try:
        blob_client = auth_container_client.get_blob_client(blob_name)
        if blob_client.exists():
            data = blob_client.download_blob().readall().decode('utf-8')
            return json.loads(data)
        return {}
    except Exception as e:
        print(f"Error loading {blob_name}: {str(e)}")
        return {}

def save_auth_data(blob_name, data):
    """Save authentication data to blob storage"""
    try:
        blob_client = auth_container_client.get_blob_client(blob_name)
        blob_client.upload_blob(
            json.dumps(data),
            overwrite=True,
            content_settings=ContentSettings(content_type='application/json')
        )
    except Exception as e:
        print(f"Error saving {blob_name}: {str(e)}")

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    # Load existing data
    users_db = load_auth_data('users_db.json')
    unverified_users = load_auth_data('unverified_users.json')
    
    if username in users_db:
        return jsonify({'error': 'Email already registered'}), 409
    if username in unverified_users:
        return jsonify({'error': 'Email already registered but not verified'}), 409

    # Update dictionaries
    unverified_users[username] = { }
    otps = load_auth_data('otps.json')
    otps[username] = { }
    
    # Save updated data
    save_auth_data('unverified_users.json', unverified_users)
    save_auth_data('otps.json', otps)
    
    # Rest of the registration logic

@app.route('/api/verify-email', methods=['POST'])
def verify_email():
    # Load data
    unverified_users = load_auth_data('unverified_users.json')
    otps = load_auth_data('otps.json')
    
    # Check OTP expiration
    expiry_time = datetime.fromisoformat(otps[username]['expires']).replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > expiry_time:
        # Update and save data
        del otps[username]
        save_auth_data('otps.json', otps)
        return jsonify({'error': 'OTP expired'}), 401
        
    # Update dictionaries
    incomplete_profiles = load_auth_data('incomplete_profiles.json')
    incomplete_profiles[username] = unverified_users[username]
    del unverified_users[username]
    del otps[username]
    
    # Save updated data
    save_auth_data('incomplete_profiles.json', incomplete_profiles)
    save_auth_data('unverified_users.json', unverified_users)
    save_auth_data('otps.json', otps)
    
@app.route('/api/complete-profile', methods=['POST'])
def complete_profile():
    data = request.get_json()
    if not data or not data.get('username'):
        return jsonify({'error': 'Email is required'}), 400

    username = data['username']
    if username not in incomplete_profiles:
        return jsonify({'error': 'Invalid email or email already verified'}), 404

    required_fields = ['profession', 'gender', 'age', 'bio']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'error': f'{field.capitalize()} is required'}), 400

    user_data = incomplete_profiles[username]
    user_info = {
        'full_name': user_data['full_name'],
        'email': user_data['email'],
        'profession': data['profession'],
        'gender': data['gender'],
        'bio': data['bio'],
        'age': data['age'],
        'created_at': user_data['created_at'],
        'email_verified': True
    }
    users_db[username] = user_data

    try:
        blob_client = blob_service_client.get_blob_client(
            container=CONTAINER_NAME,
            blob=f"{username}/userInfo.json"
        )
        blob_client.upload_blob(
            json.dumps(user_info),
            overwrite=True,
            content_settings=ContentSettings(content_type='application/json')
        )
        del incomplete_profiles[username]
        return jsonify({'message': 'Profile completed successfully. You can now log in.'}), 200
    except Exception as e:
        print(f"Error creating user info file: {str(e)}")
        return jsonify({'error': 'Error creating user profile'}), 500

@app.route('/api/resend-otp', methods=['POST'])
def resend_otp():
    data = request.get_json()
    if not data or not data.get('username'):
        return jsonify({'error': 'Email is required'}), 400

    username = data['username']
    if username in unverified_users:
        user_email = unverified_users[username]['email']
        purpose = "verification"
    elif username in otps and otps[username].get('for_password_reset'):
        user_email = users_db[username]['email']
        purpose = "password_reset"
    elif username in otps and otps[username].get('for_email_change'):
        user_email = otps[username]['new_email']
        purpose = "email_change"
    elif username in otps and otps[username].get('for_current_email_verification'):
        user_email = users_db[username]['email']
        purpose = "email_change"
    elif username in otps and otps[username].get('for_login'):
        user_email = users_db[username]['email']
        purpose = "login"
    else:
        return jsonify({'error': 'Invalid email or no pending verification'}), 404

    otp = generate_otp()
    otp_expiry = datetime.now(timezone.utc) + timedelta(minutes=10)
    current_otp_data = otps.get(username, {})
    otps[username] = {'otp': otp, 'expires': otp_expiry}
    for key in current_otp_data:
        if key not in ['otp', 'expires']:
            otps[username][key] = current_otp_data[key]

    if not send_otp_email(user_email, otp, purpose):
        return jsonify({'error': 'Failed to send verification email'}), 500

    print(f"OTP for {user_email}: {otp}")  # Debugging
    return jsonify({'message': 'OTP sent successfully'}), 200

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Email and password are required'}), 400

    email = data['email']
    password = data['password']
    username = email

    if username not in users_db:
        return jsonify({'error': 'Email not registered or invalid credentials'}), 401
    if username in incomplete_profiles:
        return jsonify({'error': 'Profile incomplete. Please complete your profile.'}), 401
    if username in unverified_users:
        return jsonify({'error': 'Email not verified. Please verify your email.'}), 401

    password_hash = hashlib.sha256(password.encode()).hexdigest()
    if users_db[username]['password_hash'] != password_hash:
        return jsonify({'error': 'Invalid email or password'}), 401

    otp = generate_otp()
    otp_expiry = datetime.now(timezone.utc) + timedelta(minutes=10)
    otps[username] = {
        'otp': otp,
        'expires': otp_expiry,
        'for_login': True
    }

    if not send_otp_email(email, otp, "login"):
        return jsonify({'error': 'Failed to send login verification email'}), 500

    print(f"OTP for {email}: {otp}")  # Debugging
    return jsonify({
        'message': 'Login verification code sent to your email',
        'username': username
    }), 200

@app.route('/api/verify-login', methods=['POST'])
def verify_login():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('otp'):
        return jsonify({'error': 'Email and OTP are required'}), 400

    username = data['username']
    otp = data['otp']

    if username not in users_db:
        return jsonify({'error': 'Invalid email'}), 404
    if username not in otps or not otps[username].get('for_login'):
        return jsonify({'error': 'No login verification request found'}), 404
    if datetime.now(timezone.utc) > otps[username]['expires']:
        del otps[username]
        return jsonify({'error': 'Verification code expired. Please try logging in again.'}), 401
    if otps[username]['otp'] != otp:
        return jsonify({'error': 'Invalid verification code'}), 401

    del otps[username]
    token = jwt.encode({
        'sub': username,
        'iat': datetime.now(timezone.utc),
        'exp': datetime.now(timezone.utc) + timedelta(hours=24)
    }, app.secret_key, algorithm='HS256')
    token_id = str(uuid.uuid4())
    active_tokens[token_id] = {
        'username': username,
        'expires': (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
    }
    return jsonify({
        'message': 'Login successful',
        'token': token,
        'token_id': token_id
    }), 200

@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    if not data or not data.get('email'):
        return jsonify({'error': 'Email is required'}), 400

    email = data['email']
    username = email

    if username not in users_db:
        return jsonify({'message': 'If the email exists, a reset code has been sent.'}), 200

    otp = generate_otp()
    otp_expiry = datetime.now(timezone.utc) + timedelta(minutes=10)
    otps[username] = {
        'otp': otp,
        'expires': otp_expiry,
        'for_password_reset': True
    }

    if not send_otp_email(email, otp, "password_reset"):
        return jsonify({'error': 'Failed to send password reset email'}), 500

    print(f"OTP for {email}: {otp}")  # Debugging
    return jsonify({
        'message': 'Password reset code sent to your email',
        'username': username
    }), 200

@app.route('/api/request-password-reset', methods=['POST'])
def request_password_reset():
    data = request.get_json()
    if not data or not data.get('username'):
        return jsonify({'error': 'Email is required'}), 400

    username = data.get('username').lower().strip()
    print(f"Password reset requested for: {username}")

    if username not in users_db:
        print(f"User {username} not found in database")
        return jsonify({'message': 'If the email exists, a reset code has been sent'}), 200

    otp = generate_otp()
    otps[username] = {
        'otp': otp,
        'expires': datetime.now(timezone.utc) + timedelta(minutes=15),
        'for_password_reset': True
    }

    user_name = users_db[username].get('full_name', None)
    if not send_otp_email(username, otp, "password_reset", user_name):
        print(f"Failed to send OTP email to {username}")
        return jsonify({'error': 'Failed to send reset code'}), 500

    print(f"OTP for {username}: {otp}")  # Debugging
    return jsonify({'message': 'Reset code sent to your email'}), 200

@app.route('/api/verify-reset-otp', methods=['POST'])
def verify_reset_otp():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('otp'):
        return jsonify({'error': 'Email and OTP are required'}), 400

    username = data.get('username').lower().strip()
    otp = data.get('otp')

    print(f"Verifying OTP for {username}: {otp}")
    if username not in otps or not otps[username].get('for_password_reset'):
        return jsonify({'error': 'Invalid or expired reset code'}), 401
    if datetime.now(timezone.utc) > otps[username]['expires']:
        del otps[username]
        return jsonify({'error': 'Reset code expired. Please request a new one.'}), 401
    if otps[username]['otp'] != otp:
        return jsonify({'error': 'Invalid reset code'}), 401

    return jsonify({'message': 'OTP verified successfully'}), 200

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('otp') or not data.get('new_password'):
        return jsonify({'error': 'Email, OTP, and new password are required'}), 400

    username = data.get('username').lower().strip()
    otp = data.get('otp')
    new_password = data.get('new_password')

    if username not in users_db:
        return jsonify({'error': 'Invalid email'}), 404
    if username not in otps or not otps[username].get('for_password_reset'):
        return jsonify({'error': 'No valid password reset request found'}), 404
    if datetime.now(timezone.utc) > otps[username]['expires']:
        del otps[username]
        return jsonify({'error': 'Reset code expired. Please request a new one.'}), 401
    if otps[username]['otp'] != otp:
        return jsonify({'error': 'Invalid reset code'}), 401

    if len(new_password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400

    try:
        new_password_hash = hashlib.sha256(new_password.encode()).hexdigest()
        users_db[username]['password_hash'] = new_password_hash
        blob_client = blob_service_client.get_blob_client(
            container=CONTAINER_NAME,
            blob=f"{username}/userInfo.json"
        )
        user_info_blob = blob_client.download_blob()
        user_info = json.loads(user_info_blob.readall().decode('utf-8'))
        user_info['last_password_change'] = datetime.now().isoformat()
        blob_client.upload_blob(
            json.dumps(user_info),
            overwrite=True,
            content_settings=ContentSettings(content_type='application/json')
        )
        del otps[username]
        for token_id in list(active_tokens.keys()):
            if active_tokens[token_id]['username'] == username:
                del active_tokens[token_id]
        return jsonify({'message': 'Password reset successfully'}), 200
    except Exception as e:
        print(f"Error resetting password: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'No token provided'}), 401

    token_id = request.get_json().get('token_id')
    if token_id and token_id in active_tokens:
        del active_tokens[token_id]
        return jsonify({'message': 'Logout successful'}), 200
    return jsonify({'error': 'Invalid token'}), 401

@app.route('/api/validate-token', methods=['GET'])
def validate_token():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'No token provided'}), 401

    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])
        return jsonify({
            'valid': True,
            'username': payload['sub']
        }), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401

def authenticate_request():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return None, ('No token provided', 401)

    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])
        username = payload['sub']
        return username, None
    except jwt.ExpiredSignatureError:
        return None, ('Token expired', 401)
    except jwt.InvalidTokenError:
        return None, ('Invalid token', 401)

@app.route('/api/user-profile', methods=['GET'])
def get_user_profile():
    username, error = authenticate_request()
    if error:
        return jsonify({'error': error[0]}), error[1]

    try:
        blob_client = blob_service_client.get_blob_client(
            container=CONTAINER_NAME,
            blob=f"{username}/userInfo.json"
        )
        user_info_blob = blob_client.download_blob()
        user_info = json.loads(user_info_blob.readall().decode('utf-8'))
        user_info['username'] = username
        has_profile_pic = blob_service_client.get_blob_client(
            container=CONTAINER_NAME,
            blob=f"{username}/profilePic.png"
        ).exists()
        user_info['has_profile_pic'] = has_profile_pic
        return jsonify(user_info), 200
    except Exception as e:
        return jsonify({'error': f'Error retrieving user profile: {str(e)}'}), 500

@app.route('/api/user-profile', methods=['PUT'])
def update_user_profile():
    username, error = authenticate_request()
    if error:
        return jsonify({'error': error[0]}), error[1]

    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    try:
        blob_client = blob_service_client.get_blob_client(
            container=CONTAINER_NAME,
            blob=f"{username}/userInfo.json"
        )
        user_info_blob = blob_client.download_blob()
        user_info = json.loads(user_info_blob.readall().decode('utf-8'))
        allowed_fields = ['full_name', 'profession', 'gender', 'bio', 'age']
        for field in allowed_fields:
            if field in data:
                user_info[field] = data[field]
        blob_client.upload_blob(
            json.dumps(user_info),
            overwrite=True,
            content_settings=ContentSettings(content_type='application/json')
        )
        return jsonify({'message': 'Profile updated successfully'}), 200
    except Exception as e:
        return jsonify({'error': f'Error updating user profile: {str(e)}'}), 500

@app.route('/api/profile-picture', methods=['POST'])
def upload_profile_picture():
    username, error = authenticate_request()
    if error:
        return jsonify({'error': error[0]}), error[1]

    if 'profile_pic' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['profile_pic']
    if file.filename == '' or not file.content_type.startswith('image/'):
        return jsonify({'error': 'Invalid file'}), 400

    try:
        blob_client = blob_service_client.get_blob_client(
            container=CONTAINER_NAME,
            blob=f"{username}/profilePic.png"
        )
        blob_client.upload_blob(
            file.read(),
            overwrite=True,
            content_settings=ContentSettings(content_type='image/png')
        )
        return jsonify({'message': 'Profile picture uploaded successfully'}), 200
    except Exception as e:
        return jsonify({'error': f'Error uploading profile picture: {str(e)}'}), 500

@app.route('/api/profile-picture', methods=['GET'])
def get_profile_picture():
    username, error = authenticate_request()
    if error:
        return jsonify({'error': error[0]}), error[1]

    target_username = request.args.get('username', username)
    try:
        blob_client = blob_service_client.get_blob_client(
            container=CONTAINER_NAME,
            blob=f"{target_username}/profilePic.png"
        )
        if not blob_client.exists():
            return jsonify({'error': 'Profile picture not found'}), 404
        blob_data = blob_client.download_blob()
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.png')
        temp_file.write(blob_data.readall())
        temp_file.close()
        return send_file(temp_file.name, mimetype='image/png', as_attachment=False)
    except Exception as e:
        return jsonify({'error': f'Error retrieving profile picture: {str(e)}'}), 500

@app.route('/api/change-email', methods=['POST'])
def change_email():
    username, error = authenticate_request()
    if error:
        return jsonify({'error': error[0]}), error[1]

    data = request.get_json()
    if not data or not data.get('new_email'):
        return jsonify({'error': 'New email is required'}), 400

    new_email = data['new_email']
    if new_email in users_db:
        return jsonify({'error': 'Email already registered'}), 409

    otp = generate_otp()
    otp_expiry = datetime.now(timezone.utc) + timedelta(minutes=10)
    otps[username] = {
        'otp': otp,
        'expires': otp_expiry,
        'new_email': new_email,
        'for_current_email_verification': True
    }

    if not send_otp_email(username, otp, "email_change"):
        return jsonify({'error': 'Failed to send verification email'}), 500

    print(f"OTP for {username}: {otp}")  # Debugging
    return jsonify({'message': 'Verification code sent to your current email'}), 200

@app.route('/api/verify-current-email', methods=['POST'])
def verify_current_email():
    username, error = authenticate_request()
    if error:
        return jsonify({'error': error[0]}), error[1]

    data = request.get_json()
    if not data or not data.get('otp'):
        return jsonify({'error': 'OTP is required'}), 400

    otp = data['otp']
    if username not in otps or not otps[username].get('for_current_email_verification'):
        return jsonify({'error': 'No email change request found'}), 404
    if datetime.now(timezone.utc) > otps[username]['expires']:
        del otps[username]
        return jsonify({'error': 'Verification code expired. Please request a new one.'}), 401
    if otps[username]['otp'] != otp:
        return jsonify({'error': 'Invalid verification code'}), 401

    new_email = otps[username]['new_email']
    new_otp = generate_otp()
    new_otp_expiry = datetime.now(timezone.utc) + timedelta(minutes=10)
    otps[username] = {
        'otp': new_otp,
        'expires': new_otp_expiry,
        'new_email': new_email,
        'for_email_change': True
    }

    if not send_otp_email(new_email, new_otp, "email_change"):
        return jsonify({'error': 'Failed to send verification email to new address'}), 500

    print(f"OTP for {new_email}: {new_otp}")  # Debugging
    return jsonify({'message': 'Verification code sent to new email'}), 200

@app.route('/api/verify-email-change', methods=['POST'])
def verify_email_change():
    username, error = authenticate_request()
    if error:
        return jsonify({'error': error[0]}), error[1]

    data = request.get_json()
    if not data or not data.get('otp'):
        return jsonify({'error': 'OTP is required'}), 400

    otp = data['otp']
    if username not in otps or not otps[username].get('for_email_change'):
        return jsonify({'error': 'No email change request found'}), 404
    if datetime.now(timezone.utc) > otps[username]['expires']:
        del otps[username]
        return jsonify({'error': 'Verification code expired. Please request a new one.'}), 401
    if otps[username]['otp'] != otp:
        return jsonify({'error': 'Invalid verification code'}), 401

    new_email = otps[username]['new_email']
    try:
        blob_client = blob_service_client.get_blob_client(
            container=CONTAINER_NAME,
            blob=f"{username}/userInfo.json"
        )
        user_info_blob = blob_client.download_blob()
        user_info = json.loads(user_info_blob.readall().decode('utf-8'))
        new_user_data = users_db[username].copy()
        new_user_data['email'] = new_email
        users_db[new_email] = new_user_data
        user_info['email'] = new_email
        new_blob_client = blob_service_client.get_blob_client(
            container=CONTAINER_NAME,
            blob=f"{new_email}/userInfo.json"
        )
        new_blob_client.upload_blob(
            json.dumps(user_info),
            overwrite=True,
            content_settings=ContentSettings(content_type='application/json')
        )
        try:
            profile_pic_blob = blob_service_client.get_blob_client(
                container=CONTAINER_NAME,
                blob=f"{username}/profilePic.png"
            )
            if profile_pic_blob.exists():
                pic_data = profile_pic_blob.download_blob().readall()
                new_pic_blob = blob_service_client.get_blob_client(
                    container=CONTAINER_NAME,
                    blob=f"{new_email}/profilePic.png"
                )
                new_pic_blob.upload_blob(
                    pic_data,
                    overwrite=True,
                    content_settings=ContentSettings(content_type='image/png')
                )
        except Exception as e:
            print(f"Error copying profile picture: {str(e)}")
        try:
            blob_client.delete_blob()
            profile_pic_blob = blob_service_client.get_blob_client(
                container=CONTAINER_NAME,
                blob=f"{username}/profilePic.png"
            )
            if profile_pic_blob.exists():
                profile_pic_blob.delete_blob()
        except Exception as e:
            print(f"Error deleting old user data: {str(e)}")
        del users_db[username]
        del otps[username]
        for token_id in list(active_tokens.keys()):
            if active_tokens[token_id]['username'] == username:
                del active_tokens[token_id]
        token = jwt.encode({
            'sub': new_email,
            'iat': datetime.now(timezone.utc),
            'exp': datetime.now(timezone.utc) + timedelta(hours=24)
        }, app.secret_key, algorithm='HS256')
        token_id = str(uuid.uuid4())
        active_tokens[token_id] = {
            'username': new_email,
            'expires': (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
        }
        return jsonify({
            'message': 'Email changed successfully',
            'new_username': new_email,
            'token': token,
            'token_id': token_id
        }), 200
    except Exception as e:
        return jsonify({'error': f'Error changing email: {str(e)}'}), 500

@app.route('/api/change-password', methods=['POST'])
def change_password():
    username, error = authenticate_request()
    if error:
        return jsonify({'error': error[0]}), error[1]

    data = request.get_json()
    if not data or not data.get('current_password') or not data.get('new_password'):
        return jsonify({'error': 'Current password and new password are required'}), 400

    current_password = data['current_password']
    new_password = data['new_password']
    current_password_hash = hashlib.sha256(current_password.encode()).hexdigest()
    if users_db[username]['password_hash'] != current_password_hash:
        return jsonify({'error': 'Current password is incorrect'}), 401

    new_password_hash = hashlib.sha256(new_password.encode()).hexdigest()
    users_db[username]['password_hash'] = new_password_hash
    try:
        blob_client = blob_service_client.get_blob_client(
            container=CONTAINER_NAME,
            blob=f"{username}/userInfo.json"
        )
        user_info_blob = blob_client.download_blob()
        user_info = json.loads(user_info_blob.readall().decode('utf-8'))
        user_info['last_password_change'] = datetime.now().isoformat()
        blob_client.upload_blob(
            json.dumps(user_info),
            overwrite=True,
            content_settings=ContentSettings(content_type='application/json')
        )
        current_token_id = request.get_json().get('token_id')
        for token_id in list(active_tokens.keys()):
            if active_tokens[token_id]['username'] == username and token_id != current_token_id:
                del active_tokens[token_id]
        return jsonify({'message': 'Password changed successfully'}), 200
    except Exception as e:
        return jsonify({'error': f'Error updating password: {str(e)}'}), 500

@app.route('/api/delete-account', methods=['POST'])
def delete_account():
    username, error = authenticate_request()
    if error:
        return jsonify({'error': error[0]}), error[1]

    data = request.get_json()
    if not data or not data.get('password'):
        return jsonify({'error': 'Password is required to delete your account'}), 400

    password = data['password']
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    if users_db[username]['password_hash'] != password_hash:
        return jsonify({'error': 'Password is incorrect'}), 401

    try:
        blob_list = blob_service_client.get_container_client(CONTAINER_NAME).list_blobs(name_starts_with=f"{username}/")
        for blob in blob_list:
            blob_service_client.get_blob_client(container=CONTAINER_NAME, blob=blob.name).delete_blob()
        del users_db[username]
        for token_id in list(active_tokens.keys()):
            if active_tokens[token_id]['username'] == username:
                del active_tokens[token_id]
        return jsonify({'message': 'Account deleted successfully'}), 200
    except Exception as e:
        return jsonify({'error': f'Error deleting account: {str(e)}'}), 500

@app.route('/api/users', methods=['GET'])
def get_users():
    username, error = authenticate_request()
    if error:
        return jsonify({'error': error[0]}), error[1]

    try:
        users = []
        user_blobs = blob_service_client.get_container_client(CONTAINER_NAME).list_blobs()
        user_folders = set(blob.name.split('/')[0] for blob in user_blobs if '/' in blob.name)
        for user_folder in user_folders:
            try:
                blob_client = blob_service_client.get_blob_client(
                    container=CONTAINER_NAME,
                    blob=f"{user_folder}/userInfo.json"
                )
                user_info_blob = blob_client.download_blob()
                user_info = json.loads(user_info_blob.readall().decode('utf-8'))
                has_profile_pic = blob_service_client.get_blob_client(
                    container=CONTAINER_NAME,
                    blob=f"{user_folder}/profilePic.png"
                ).exists()
                users.append({
                    'username': user_folder,
                    'full_name': user_info.get('full_name', ''),
                    'profession': user_info.get('profession', ''),
                    'has_profile_pic': has_profile_pic
                })
            except Exception as e:
                print(f"Error getting user info for {user_folder}: {str(e)}")
        return jsonify(users), 200
    except Exception as e:
        return jsonify({'error': f'Error retrieving users: {str(e)}'}), 500

@app.route('/api/user-profile/<email>', methods=['GET'])
def get_user_profile_grok(email):
    if not email or '@' not in email:
        return jsonify({"error": "Invalid email provided"}), 400

    try:
        blob_client = container_client.get_blob_client(f"{email}/userInfo.json")
        user_info_data = blob_client.download_blob().readall().decode('utf-8')
        user_info = json.loads(user_info_data)
        profile_pic_url = DEFAULT_PROFILE_PIC_URL
        blob_client = container_client.get_blob_client(f"{email}/profilePic.png")
        try:
            blob_client.get_blob_properties()
            sas_token = blob_client.generate_shared_access_signature(
                permission="read",
                expiry=datetime.utcnow() + timedelta(hours=1)
            )
            profile_pic_url = f"{blob_client.url}?{sas_token}"
        except Exception:
            pass
        response = {
            "full_name": user_info.get("full_name", ""),
            "email": user_info.get("email", email),
            "profession": user_info.get("profession", ""),
            "gender": user_info.get("gender", ""),
            "bio": user_info.get("bio", ""),
            "age": user_info.get("age", 0),
            "created_at": user_info.get("created_at", ""),
            "email_verified": user_info.get("email_verified", False),
            "profile_picture": profile_pic_url
        }
        return jsonify(response), 200
    except Exception as e:
        return jsonify({"error": "Error Fetching User Details", "details": str(e)}), 500

@app.route('/api/user-profile/<email>', methods=['PUT'])
def update_user_profile_grok(email):
    try:
        data = request.get_json()
        blob_client = container_client.get_blob_client(f"{email}/userInfo.json")
        current_data = json.loads(blob_client.download_blob().readall().decode('utf-8'))
        current_data.update({
            "full_name": data.get("full_name", current_data["full_name"]),
            "profession": data.get("profession", current_data["profession"]),
            "gender": data.get("gender", current_data["gender"]),
            "bio": data.get("bio", current_data["bio"])
        })
        blob_client.upload_blob(json.dumps(current_data), overwrite=True)
        return jsonify({"message": "Profile updated successfully"}), 200
    except Exception as e:
        return jsonify({"error": "Failed to update profile", "details": str(e)}), 500

@app.route('/api/upload-profile-pic/<username>', methods=['POST'])
def upload_profile_pic_grok(username):
    try:
        if 'profilePic' not in request.files:
            return jsonify({"error": "No file provided"}), 400
        file = request.files['profilePic']
        blob_client = container_client.get_blob_client(f"{username}/profilePic.png")
        blob_client.upload_blob(file, overwrite=True)
        sas_token = blob_client.generate_shared_access_signature(
            permission="read",
            expiry=datetime.utcnow() + timedelta(hours=1)
        )
        profile_pic_url = f"{blob_client.url}?{sas_token}"
        return jsonify({"profile_picture_url": profile_pic_url}), 200
    except Exception as e:
        return jsonify({"error": "Failed to upload profile picture", "details": str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        container_client.exists()
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat()
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

if not app.secret_key:
    app.secret_key = os.getenv('SECRET_KEY', os.urandom(24))

def cleanup_expired_data():
    current_time = datetime.now(timezone.utc)
    
    # Clean OTPs
    otps = load_auth_data('otps.json')
    for username in list(otps.keys()):
        expiry = datetime.fromisoformat(otps[username]['expires']).replace(tzinfo=timezone.utc)
        if current_time > expiry:
            del otps[username]
    save_auth_data('otps.json', otps)
    
    # Clean active tokens
    active_tokens = load_auth_data('active_tokens.json')
    for token_id in list(active_tokens.keys()):
        expiry = datetime.fromisoformat(active_tokens[token_id]['expires']).replace(tzinfo=timezone.utc)
        if current_time > expiry:
            del active_tokens[token_id]
    save_auth_data('active_tokens.json', active_tokens)

@app.before_request
def before_request():
    cleanup_expired_data()

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug)
