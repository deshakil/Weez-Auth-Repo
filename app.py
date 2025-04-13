from flask import Flask, request, jsonify, send_file
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
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

app = Flask(__name__)
CORS(app)
app.secret_key = os.getenv('SECRET_KEY', os.urandom(24))

# Azure Blob Storage configuration
AZURE_STORAGE_CONNECTION_STRING = os.getenv('AZURE_STORAGE_CONNECTION_STRING_1')
CONTAINER_NAME = "weez-users-info"
AUTH_CONTAINER_NAME = "auth-dictionaries"
DEFAULT_PROFILE_PIC_URL = "https://i.pinimg.com/736x/23/a6/1f/23a61f584822b8c7dbaebdca7c96da3e.jpg"

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


# Ensure containers exist
for client, name in [(container_client, CONTAINER_NAME), (auth_container_client, AUTH_CONTAINER_NAME)]:
    if not client.exists():
        client.create_container()

# Helper functions
def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))

def load_auth_data(blob_name):
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
    try:
        blob_client = auth_container_client.get_blob_client(blob_name)
        blob_client.upload_blob(
            json.dumps(data),
            overwrite=True,
            content_settings=ContentSettings(content_type='application/json'))
        return True
    except Exception as e:
        print(f"Error saving {blob_name}: {str(e)}")
        return False

def send_email(to_email, subject, body):
    try:
        message = Mail(
            from_email='support@em3196.weez.online',
            to_emails=to_email,
            subject=subject,
            html_content=body
        )
        sg = SendGridAPIClient(os.getenv('SENDGRID_API_KEY'))
        response = sg.send(message)
        return response.status_code == 202
    except Exception as e:
        print(f"Email failed to {to_email}: {str(e)}")
        return False

def send_otp_email(email, otp, purpose="verification", user_name=None):
    subject = "Weez OTP Verification Code"
    purpose_display = {
        "verification": "account verification",
        "login": "login attempt",
        "password_reset": "password reset",
        "email_change": "email change"
    }.get(purpose, "verification")
    
    body = f"""
    <html>
    <body>
        <p>Dear {user_name or 'User'},</p>
        <p>Your Weez verification code is: <strong>{otp}</strong></p>
        <p>This code will expire in 10 minutes.</p>
        <p>Purpose: {purpose_display}</p>
        <p>If you didn't request this, please ignore this email.</p>
    </body>
    </html>
    """
    return send_email(email, subject, body)

# Authentication endpoints
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email', '').lower().strip()
    password = data.get('password', '')
    full_name = data.get('full_name', '')

    if not email or '@' not in email:
        return jsonify({'error': 'Invalid email'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400

    users_db = load_auth_data('users_db.json')
    unverified_users = load_auth_data('unverified_users.json')

    if email in users_db or email in unverified_users:
        return jsonify({'error': 'Email already registered'}), 409

    password_hash = hashlib.sha256(password.encode()).hexdigest()
    unverified_users[email] = {
        'email': email,
        'password_hash': password_hash,
        'full_name': full_name,
        'created_at': datetime.now(timezone.utc).isoformat()
    }

    otp = generate_otp()
    otps = load_auth_data('otps.json')
    otps[email] = {
        'otp': otp,
        'expires': (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
        'purpose': 'verification'
    }

    if not all([
        save_auth_data('unverified_users.json', unverified_users),
        save_auth_data('otps.json', otps)
    ]):
        return jsonify({'error': 'Failed to save registration data'}), 500

    if not send_otp_email(email, otp, "verification", full_name):
        return jsonify({'error': 'Failed to send verification email'}), 500

    return jsonify({'message': 'OTP sent successfully'}), 200

@app.route('/api/verify-email', methods=['POST'])
def verify_email():
    data = request.get_json()
    email = data.get('email', '').lower().strip()
    otp = data.get('otp', '')

    unverified_users = load_auth_data('unverified_users.json')
    otps = load_auth_data('otps.json')

    if email not in unverified_users:
        return jsonify({'error': 'No pending verification for this email'}), 400

    stored_otp = otps.get(email, {})
    if not stored_otp or stored_otp.get('otp') != otp:
        return jsonify({'error': 'Invalid OTP'}), 401

    expiry_time = datetime.fromisoformat(stored_otp['expires']).replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > expiry_time:
        del otps[email]
        save_auth_data('otps.json', otps)
        return jsonify({'error': 'OTP expired'}), 401

    # Move to incomplete profiles
    incomplete_profiles = load_auth_data('incomplete_profiles.json')
    incomplete_profiles[email] = unverified_users[email]
    del unverified_users[email]
    del otps[email]

    if not all([
        save_auth_data('unverified_users.json', unverified_users),
        save_auth_data('otps.json', otps),
        save_auth_data('incomplete_profiles.json', incomplete_profiles)
    ]):
        return jsonify({'error': 'Failed to complete verification'}), 500

    return jsonify({'message': 'Email verified. Please complete your profile.'}), 200

@app.route('/api/complete-profile', methods=['POST'])
def complete_profile():
    data = request.get_json()
    email = data.get('email', '').lower().strip()

    incomplete_profiles = load_auth_data('incomplete_profiles.json')
    if email not in incomplete_profiles:
        return jsonify({'error': 'No incomplete profile found'}), 404

    user_data = incomplete_profiles[email]
    required_fields = ['profession', 'gender', 'age', 'bio']
    if any(field not in data for field in required_fields):
        return jsonify({'error': 'All profile fields are required'}), 400

    # Create user directory in main container
    user_info = {
        **user_data,
        'profession': data['profession'],
        'gender': data['gender'],
        'age': data['age'],
        'bio': data['bio'],
        'email_verified': True,
        'created_at': datetime.now(timezone.utc).isoformat()
    }

    try:
        # Save user info to main container
        blob_client = container_client.get_blob_client(f"{email}/userInfo.json")
        blob_client.upload_blob(
            json.dumps(user_info),
            overwrite=True,
            content_settings=ContentSettings(content_type='application/json')
        )  # FIXED: Added missing closing parenthesis
        
        # Update users database
        users_db = load_auth_data('users_db.json')
        users_db[email] = {
            'password_hash': user_data['password_hash'],
            'full_name': user_data['full_name']
        }
        
        # Clean up temporary data
        del incomplete_profiles[email]
        
        if not all([
            save_auth_data('users_db.json', users_db),
            save_auth_data('incomplete_profiles.json', incomplete_profiles)
        ]):
            return jsonify({'error': 'Failed to save profile data'}), 500

        return jsonify({'message': 'Profile completed successfully'}), 200
    except Exception as e:
        return jsonify({'error': f'Error completing profile: {str(e)}'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email', '').lower().strip()
    password = data.get('password', '')

    # Check if user exists in blob container instead of users_db
    try:
        blob_client = container_client.get_blob_client(f"{email}/userInfo.json")
        if not blob_client.exists():
            return jsonify({'error': 'Invalid credentials'}), 401
        
        user_info = json.loads(blob_client.download_blob().readall())
        
        # Verify password if password_hash exists in user_info
        if 'password_hash' in user_info:
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            if user_info['password_hash'] != password_hash:
                return jsonify({'error': 'Invalid credentials'}), 401
        else:
            # For users who may have registered through other means (e.g., Google)
            return jsonify({'error': 'Password login not enabled for this account'}), 401

        # Generate login OTP
        otp = generate_otp()
        otps = load_auth_data('otps.json')
        otps[email] = {
            'otp': otp,
            'expires': (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
            'purpose': 'login'
        }

        if not save_auth_data('otps.json', otps):
            return jsonify({'error': 'Failed to generate OTP'}), 500

        user_name = user_info.get('name', '') or user_info.get('full_name', '')
        if not send_otp_email(email, otp, "login", user_name):
            return jsonify({'error': 'Failed to send OTP'}), 500

        return jsonify({'message': 'OTP sent to email', 'email': email}), 200
    
    except Exception as e:
        print(f"Login error for {email}: {str(e)}")
        return jsonify({'error': 'Invalid credentials'}), 401
        
@app.route('/api/verify-login', methods=['POST'])
def verify_login():
    data = request.get_json()
    email = data.get('email', '').lower().strip()
    otp = data.get('otp', '')

    otps = load_auth_data('otps.json')
    stored_otp = otps.get(email, {})
    
    if not stored_otp or stored_otp.get('purpose') != 'login':
        return jsonify({'error': 'Invalid login attempt'}), 401

    if stored_otp['otp'] != otp:
        return jsonify({'error': 'Invalid OTP'}), 401

    expiry_time = datetime.fromisoformat(stored_otp['expires']).replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > expiry_time:
        del otps[email]
        save_auth_data('otps.json', otps)
        return jsonify({'error': 'OTP expired'}), 401

    # Generate JWT token
    token_payload = {
        'sub': email,
        'iat': datetime.now(timezone.utc),
        'exp': datetime.now(timezone.utc) + timedelta(hours=24)
    }
    token = jwt.encode(token_payload, app.secret_key, algorithm='HS256')
    
    # Store active token
    active_tokens = load_auth_data('active_tokens.json')
    token_id = str(uuid.uuid4())
    active_tokens[token_id] = {
        'email': email,
        'expires': token_payload['exp'].isoformat()
    }
    save_auth_data('active_tokens.json', active_tokens)

    # Cleanup OTP
    del otps[email]
    save_auth_data('otps.json', otps)

    return jsonify({
        'message': 'Login successful',
        'token': token,
        'token_id': token_id
    }), 200

@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    email = request.json.get('email', '').lower().strip()
    
    # Check if user exists in blob container instead of users_db
    try:
        blob_client = container_client.get_blob_client(f"{email}/userInfo.json")
        if not blob_client.exists():
            # Don't reveal that the email doesn't exist, but don't send OTP either
            return jsonify({'message': 'If email exists, reset code will be sent'}), 200
        
        # User exists, proceed with OTP
        user_info = json.loads(blob_client.download_blob().readall())
        user_name = user_info.get('name', '') or user_info.get('full_name', '')
        
        otp = generate_otp()
        otps = load_auth_data('otps.json')
        otps[email] = {
            'otp': otp,
            'expires': (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat(),
            'purpose': 'password_reset'
        }
        
        if not save_auth_data('otps.json', otps):
            return jsonify({'error': 'Failed to process request'}), 500

        if not send_otp_email(email, otp, "password_reset", user_name):
            return jsonify({'error': 'Failed to send reset code'}), 500

        return jsonify({'message': 'Reset code sent to email'}), 200
    
    except Exception as e:
        # Log the error but don't reveal it to the user
        print(f"Error in forgot_password for {email}: {str(e)}")
        # Return success message even if there was an error to prevent email enumeration
        return jsonify({'message': 'If email exists, reset code will be sent'}), 200

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email = data.get('email', '').lower().strip()
    otp = data.get('otp', '')
    new_password = data.get('new_password', '')

    otps = load_auth_data('otps.json')
    stored_otp = otps.get(email, {})
    
    if not stored_otp or stored_otp.get('purpose') != 'password_reset':
        return jsonify({'error': 'Invalid reset attempt'}), 401

    if stored_otp['otp'] != otp:
        return jsonify({'error': 'Invalid OTP'}), 401

    expiry_time = datetime.fromisoformat(stored_otp['expires']).replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > expiry_time:
        del otps[email]
        save_auth_data('otps.json', otps)
        return jsonify({'error': 'OTP expired'}), 401

    if len(new_password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400

    # Update password in blob storage
    try:
        # Get the user info from blob storage
        blob_client = container_client.get_blob_client(f"{email}/userInfo.json")
        user_info = json.loads(blob_client.download_blob().readall())
        
        # Update password hash and record the change time
        user_info['password_hash'] = hashlib.sha256(new_password.encode()).hexdigest()
        user_info['last_password_change'] = datetime.now(timezone.utc).isoformat()
        
        # Upload updated user info
        blob_client.upload_blob(
            json.dumps(user_info),
            overwrite=True,
            content_settings=ContentSettings(content_type='application/json')
        )
        
        # Cleanup OTP
        del otps[email]
        save_auth_data('otps.json', otps)
        
        return jsonify({'message': 'Password reset successfully'}), 200
    
    except Exception as e:
        return jsonify({'error': f'Failed to update password: {str(e)}'}), 500
        
# Profile endpoints
@app.route('/api/user-profile', methods=['GET'])
def get_user_profile():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        token = auth_header.split(' ')[1]
        payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])
        email = payload['sub']
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401

    try:
        blob_client = container_client.get_blob_client(f"{email}/userInfo.json")
        user_info = json.loads(blob_client.download_blob().readall())
        
        # Check for profile picture
        pic_client = container_client.get_blob_client(f"{email}/profilePic.png")
        user_info['has_profile_pic'] = pic_client.exists()
        
        return jsonify(user_info), 200
    except Exception as e:
        return jsonify({'error': f'Profile not found: {str(e)}'}), 404

@app.route('/api/profile-picture', methods=['POST'])
def upload_profile_picture():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        token = auth_header.split(' ')[1]
        payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])
        email = payload['sub']
    except:
        return jsonify({'error': 'Invalid token'}), 401

    if 'profile_pic' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['profile_pic']
    if not file.filename.lower().endswith(('.png', '.jpg', '.jpeg')):
        return jsonify({'error': 'Invalid file type'}), 400

    try:
        blob_client = container_client.get_blob_client(f"{email}/profilePic.png")
        blob_client.upload_blob(
            file.read(),
            overwrite=True,
            content_settings=ContentSettings(content_type='image/png')
        )  # FIXED: Added missing closing parenthesis
        return jsonify({'message': 'Profile picture updated'}), 200
    except Exception as e:
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500

# Additional endpoints (health check, etc.)
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'auth_container': auth_container_client.exists(),
        'main_container': container_client.exists()
    }), 200

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug)
