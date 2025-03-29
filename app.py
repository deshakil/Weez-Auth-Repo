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
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from azure.storage.blob import BlobServiceClient, ContentSettings
from io import BytesIO

app = Flask(__name__)  # Use environment variable in production
CORS(app)  # Enable Cross-Origin Resource Sharing

# Azure Blob Storage configuration
AZURE_STORAGE_CONNECTION_STRING = os.getenv('AZURE_STORAGE_CONNECTION_STRING_1')
CONTAINER_NAME = "weez-users-info"
DEFAULT_PROFILE_PIC_URL = "https://i.pinimg.com/736x/23/a6/1f/23a61f584822b8c7dbaebdca7c96da3e.jpg"

# Email configuration for OTP
EMAIL_HOST = os.getenv('EMAIL_HOST')
EMAIL_PORT = 587
EMAIL_USER = os.getenv('EMAIL_USER')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')
EMAIL_FROM = os.getenv('EMAIL_SENDER')

# Initialize the BlobServiceClient
blob_service_client = BlobServiceClient.from_connection_string(AZURE_STORAGE_CONNECTION_STRING)
container_client = blob_service_client.get_container_client(CONTAINER_NAME)
# Create container if it doesn't exist
try:
    container_client = blob_service_client.get_container_client(CONTAINER_NAME)
    if not container_client.exists():
        container_client.create_container()
except Exception as e:
    print(f"Error initializing container: {str(e)}")

# In a real application, you'd use a database instead of these dictionaries
users_db = {}
# Store active tokens
active_tokens = {}
# Store OTPs
otps = {}
# Store unverified users
unverified_users = {}
# Store users with incomplete profiles
incomplete_profiles = {}


def generate_otp(length=6):
    """Generate a random OTP of specified length."""
    return ''.join(random.choices(string.digits, k=length))


def send_email(to_email, subject, body):
    """Send an email with the provided subject and body."""
    try:
        message = MIMEMultipart()
        message['From'] = EMAIL_FROM
        message['To'] = to_email
        message['Subject'] = subject

        message.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASSWORD)
        server.send_message(message)
        server.quit()
        return True
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        return False


def send_otp_email(email, otp, purpose="verification", user_name=None):
    """Send OTP verification email."""
    subject = "Weez OTP Verification Code"

    # Use a generic greeting if no name is provided
    greeting = f"Dear {user_name}," if user_name else "Dear Weez User,"

    # Map purpose to more user-friendly descriptions
    purpose_display = {
        "verification": "account verification",
        "login": "login attempt",
        "password_reset": "password reset",
        "email_change": "email change"
    }.get(purpose, "verification")

    body = f"""
    {greeting}

    Welcome to Weez! To ensure the security of your account, please verify your email using the One-Time Password (OTP) below:

    Your OTP: {otp}

    This OTP is valid for 10 minutes and can only be used once.

    Important Security Guidelines:
    • Do not share this OTP with anyone, including Weez support staff.
    • Do not enter your OTP on any unofficial websites or third-party apps.
    • If you didn't request this OTP for {purpose_display}, please ignore this email or contact our support team immediately.

    If you have any questions, feel free to reach out to us at weatweez@gmail.com.

    Best regards,
    The Weez Team
    """

    return send_email(email, subject, body)


@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()

    if not data or not data.get('fullName') or not data.get('password') or not data.get('email'):
        return jsonify({'error': 'Full name, password, and email are required'}), 400

    full_name = data['fullName']
    password = data['password']
    email = data['email']

    # Use email as username
    username = email

    # Check if email is already registered
    if username in users_db:
        return jsonify({'error': 'Email already registered'}), 409

    if username in unverified_users:
        return jsonify({'error': 'Email already registered but not verified'}), 409

    # Hash the password before storing
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    # Generate OTP for email verification
    otp = generate_otp()
    otp_expiry = datetime.now(timezone.utc) + timedelta(minutes=10)

    # Store user in unverified users
    unverified_users[username] = {
        'password_hash': password_hash,
        'email': email,
        'full_name': full_name,
        'created_at': datetime.now().isoformat()
    }

    # Store OTP
    otps[username] = {
        'otp': otp,
        'expires': otp_expiry
    }

    # Send OTP via email
    if not send_otp_email(email, otp, "verification"):
        return jsonify({'error': 'Failed to send verification email'}), 500

    return jsonify({
        'message': 'Registration initiated. Please verify your email with the OTP sent.',
        'username': username
    }), 201


@app.route('/api/verify-email', methods=['POST'])
def verify_email():
    data = request.get_json()

    if not data or not data.get('username') or not data.get('otp'):
        return jsonify({'error': 'Email and OTP are required'}), 400

    username = data['username']
    otp = data['otp']

    if username not in unverified_users:
        return jsonify({'error': 'Invalid email'}), 404

    if username not in otps:
        return jsonify({'error': 'No OTP found for this user'}), 404

    if datetime.now(timezone.utc) > otps[username]['expires']:
        del otps[username]
        return jsonify({'error': 'OTP expired. Please request a new one.'}), 401

    if otps[username]['otp'] != otp:
        return jsonify({'error': 'Invalid OTP'}), 401

    # Move from unverified to incomplete profiles
    incomplete_profiles[username] = unverified_users[username]
    del unverified_users[username]
    del otps[username]

    # Return success and indicate that profile completion is needed
    return jsonify({
        'message': 'Email verified successfully. Please complete your profile.',
        'username': username
    }), 200


@app.route('/api/complete-profile', methods=['POST'])
def complete_profile():
    data = request.get_json()

    if not data or not data.get('username'):
        return jsonify({'error': 'Email is required'}), 400

    username = data['username']

    if username not in incomplete_profiles:
        return jsonify({'error': 'Invalid email or email already verified'}), 404

    # Required profile fields
    required_fields = ['profession', 'gender', 'age', 'bio']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'error': f'{field.capitalize()} is required'}), 400

    # Get user data from incomplete profiles
    user_data = incomplete_profiles[username]

    # Create complete user info
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

    # Move to verified users
    users_db[username] = user_data

    try:
        # Upload info.json to Azure Blob Storage
        blob_client = blob_service_client.get_blob_client(
            container=CONTAINER_NAME,
            blob=f"{username}/userInfo.json"
        )

        blob_client.upload_blob(
            json.dumps(user_info),
            overwrite=True,
            content_settings=ContentSettings(content_type='application/json')
        )

        # Remove from incomplete profiles
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

    # Generate new OTP
    otp = generate_otp()
    otp_expiry = datetime.now(timezone.utc) + timedelta(minutes=10)

    # Update OTP
    current_otp_data = otps.get(username, {})
    otps[username] = {
        'otp': otp,
        'expires': otp_expiry
    }

    # Preserve purpose flags
    for key in current_otp_data:
        if key not in ['otp', 'expires']:
            otps[username][key] = current_otp_data[key]

    # Send OTP via email
    if not send_otp_email(user_email, otp, purpose):
        return jsonify({'error': 'Failed to send verification email'}), 500

    return jsonify({'message': 'OTP sent successfully'}), 200


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Email and password are required'}), 400

    email = data['email']
    password = data['password']

    # Use email as username
    username = email

    if username not in users_db:
        return jsonify({'error': 'Email not registered or invalid credentials'}), 401

    # Check if user is in incomplete profiles
    if username in incomplete_profiles:
        return jsonify({'error': 'Profile incomplete. Please complete your profile.'}), 401

    # Check if user is in unverified users
    if username in unverified_users:
        return jsonify({'error': 'Email not verified. Please verify your email.'}), 401

    password_hash = hashlib.sha256(password.encode()).hexdigest()

    if users_db[username]['password_hash'] != password_hash:
        return jsonify({'error': 'Invalid email or password'}), 401

    # Generate OTP for login verification
    otp = generate_otp()
    otp_expiry = datetime.now(timezone.utc) + timedelta(minutes=10)

    # Store OTP
    otps[username] = {
        'otp': otp,
        'expires': otp_expiry,
        'for_login': True
    }

    # Send OTP via email
    if not send_otp_email(email, otp, "login"):
        return jsonify({'error': 'Failed to send login verification email'}), 500

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

    # Remove OTP
    del otps[username]

    # Generate JWT token
    token = jwt.encode({
        'sub': username,
        'iat': datetime.now(timezone.utc),
        'exp': datetime.now(timezone.utc) + timedelta(hours=24)
    }, app.secret_key, algorithm='HS256')

    # Store token in active tokens
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
        # Don't reveal that email doesn't exist for security reasons
        return jsonify({'message': 'If the email exists, a reset code has been sent.'}), 200

    # Generate OTP for password reset
    otp = generate_otp()
    otp_expiry = datetime.now(timezone.utc) + timedelta(minutes=10)

    # Store OTP
    otps[username] = {
        'otp': otp,
        'expires': otp_expiry,
        'for_password_reset': True
    }

    # Send OTP via email
    if not send_otp_email(email, otp, "password_reset"):
        return jsonify({'error': 'Failed to send password reset email'}), 500

    return jsonify({
        'message': 'Password reset code sent to your email',
        'username': username
    }), 200


# Endpoint to request a password reset and generate OTP
# Endpoint to request a password reset and generate OTP
@app.route('/api/request-password-reset', methods=['POST'])
def request_password_reset():
    data = request.get_json()
    
    if not data or not data.get('username'):
        return jsonify({'error': 'Email is required'}), 400
    
    username = data.get('username').lower().strip()
    
    # Log the request
    print(f"Password reset requested for: {username}")
    
    if username not in users_db:
        # For security, we don't reveal whether the email exists or not
        # But we log it for debugging
        print(f"User {username} not found in database")
        return jsonify({'message': 'If the email exists, a reset code has been sent'}), 200
    
    # Generate a 6-digit OTP
    otp = generate_otp()
    
    # Store the OTP with a 15-minute expiration and password reset flag
    otps[username] = {
        'otp': otp,
        'expires': datetime.now(timezone.utc) + timedelta(minutes=15),
        'for_password_reset': True
    }
    
    print(f"Generated OTP for {username}: {otp}")
    print(f"OTP expires at: {otps[username]['expires']}")
    
    # Get user's name from the database if available
    user_name = users_db[username].get('full_name', None)
    
    # Send the OTP email using your existing function
    if not send_otp_email(username, otp, "password_reset", user_name):
        print(f"Failed to send OTP email to {username}")
        return jsonify({'error': 'Failed to send reset code'}), 500
    
    # Include debug_otp only in development environments
    response_data = {
        'message': 'Reset code sent to your email'
    }
    
    # Conditionally add debug_otp if in development environment
    # You can add a check like: if app.config['ENV'] == 'development':
    response_data['debug_otp'] = otp  # Remove this in production!
    
    return jsonify(response_data), 200
# Endpoint to verify OTP
@app.route('/api/verify-reset-otp', methods=['POST'])
def verify_reset_otp():
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('otp'):
        return jsonify({'error': 'Email and OTP are required'}), 400
    
    username = data.get('username').lower().strip()
    otp = data.get('otp')
    
    print(f"Verifying OTP for {username}: {otp}")
    print(f"Current OTPs dictionary: {otps}")
    
    # Check if there's a valid OTP for this username
    if username not in otps:
        print(f"No OTP found for {username}")
        return jsonify({'error': 'Invalid or expired reset code'}), 401
    
    if not otps[username].get('for_password_reset'):
        print(f"OTP for {username} is not for password reset")
        return jsonify({'error': 'Invalid reset code type'}), 401
    
    # Check if OTP is expired
    if datetime.now(timezone.utc) > otps[username]['expires']:
        print(f"OTP for {username} is expired")
        del otps[username]
        return jsonify({'error': 'Reset code expired. Please request a new one.'}), 401
    
    # Check if OTP matches
    if otps[username]['otp'] != otp:
        print(f"OTP mismatch for {username}. Expected: {otps[username]['otp']}, Got: {otp}")
        return jsonify({'error': 'Invalid reset code'}), 401
    
    # OTP is valid
    return jsonify({'message': 'OTP verified successfully'}), 200


# Endpoint to reset password with OTP
@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    
    # Validate input
    if not data or not data.get('username') or not data.get('otp') or not data.get('new_password'):
        return jsonify({'error': 'Email, OTP, and new password are required'}), 400
    
    username = data.get('username').lower().strip()
    otp = data.get('otp')
    new_password = data.get('new_password')
    
    print(f"Reset password attempt for {username}")
    print(f"Current OTPs dictionary: {otps}")
    
    # Validate username exists
    if username not in users_db:
        print(f"User {username} not found in database")
        return jsonify({'error': 'Invalid email'}), 404
    
    # Validate OTP exists and is for password reset
    if username not in otps:
        print(f"No OTP found for {username}")
        return jsonify({'error': 'No valid password reset request found'}), 404
    
    if not otps[username].get('for_password_reset'):
        print(f"OTP for {username} is not for password reset")
        return jsonify({'error': 'Invalid reset request type'}), 401
    
    # Check if OTP is expired
    if datetime.now(timezone.utc) > otps[username]['expires']:
        print(f"OTP for {username} is expired")
        del otps[username]
        return jsonify({'error': 'Reset code expired. Please request a new one.'}), 401
    
    # Validate OTP matches
    if otps[username]['otp'] != otp:
        print(f"OTP mismatch for {username}. Expected: {otps[username]['otp']}, Got: {otp}")
        return jsonify({'error': 'Invalid reset code'}), 401
    
    # Validate password meets requirements
    if len(new_password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    
    try:
        # Update password
        new_password_hash = hashlib.sha256(new_password.encode()).hexdigest()
        users_db[username]['password_hash'] = new_password_hash
        
        print(f"Password updated for {username}")
        
        # Update userInfo.json with last password change timestamp
        try:
            blob_client = blob_service_client.get_blob_client(
                container=CONTAINER_NAME,
                blob=f"{username}/userInfo.json"
            )
            user_info_blob = blob_client.download_blob()
            user_info = json.loads(user_info_blob.readall().decode('utf-8'))
            
            # Update the last password change timestamp
            user_info['last_password_change'] = datetime.now().isoformat()
            
            # Upload updated userInfo.json
            blob_client.upload_blob(
                json.dumps(user_info),
                overwrite=True,
                content_settings=ContentSettings(content_type='application/json')
            )
            print(f"Updated userInfo.json for {username}")
        except Exception as e:
            print(f"Error updating user info file: {str(e)}")
            # Continue anyway, as the password is updated in memory
        
        # Remove OTP
        del otps[username]
        print(f"Removed OTP for {username}")
        
        # Invalidate all tokens for this user
        token_count = 0
        for token_id in list(active_tokens.keys()):
            if active_tokens[token_id]['username'] == username:
                del active_tokens[token_id]
                token_count += 1
        print(f"Invalidated {token_count} tokens for {username}")
        
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


# Helper function to authenticate requests
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
        # Get userInfo.json from Azure Blob Storage
        blob_client = blob_service_client.get_blob_client(
            container=CONTAINER_NAME,
            blob=f"{username}/userInfo.json"
        )

        user_info_blob = blob_client.download_blob()
        user_info = json.loads(user_info_blob.readall().decode('utf-8'))

        # Add username to response (which is the email)
        user_info['username'] = username

        # Check if profile picture exists
        has_profile_pic = False
        try:
            profile_pic_blob = blob_service_client.get_blob_client(
                container=CONTAINER_NAME,
                blob=f"{username}/profilePic.png"
            )
            has_profile_pic = profile_pic_blob.exists()
        except Exception:
            pass

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
        # Get current userInfo.json
        blob_client = blob_service_client.get_blob_client(
            container=CONTAINER_NAME,
            blob=f"{username}/userInfo.json"
        )

        user_info_blob = blob_client.download_blob()
        user_info = json.loads(user_info_blob.readall().decode('utf-8'))

        # Update fields (only the ones provided)
        allowed_fields = ['full_name', 'profession', 'gender', 'bio', 'age']
        for field in allowed_fields:
            if field in data:
                user_info[field] = data[field]

        # Upload updated userInfo.json
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

    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    # Check if the file is an image
    if not file.content_type.startswith('image/'):
        return jsonify({'error': 'File must be an image'}), 400

    try:
        # Upload profile picture to Azure Blob Storage
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

    # Get username from query param if provided (to get another user's profile picture)
    target_username = request.args.get('username', username)

    try:
        # Get profile picture from Azure Blob Storage
        blob_client = blob_service_client.get_blob_client(
            container=CONTAINER_NAME,
            blob=f"{target_username}/profilePic.png"
        )

        # Check if blob exists
        if not blob_client.exists():
            return jsonify({'error': 'Profile picture not found'}), 404

        # Download blob
        blob_data = blob_client.download_blob()

        # Create a temporary file
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.png')
        temp_file.write(blob_data.readall())
        temp_file.close()

        # Send the file
        return send_file(temp_file.name, mimetype='image/png', as_attachment=False)
    except Exception as e:
        return jsonify({'error': f'Error retrieving profile picture: {str(e)}'}), 500


@app.route('/api/change-email', methods=['POST'])
def change_email():
    # This route is kept for compatibility, but in this model
    # changing email means changing the username too
    username, error = authenticate_request()
    if error:
        return jsonify({'error': error[0]}), error[1]

    data = request.get_json()
    if not data or not data.get('new_email'):
        return jsonify({'error': 'New email is required'}), 400

    new_email = data['new_email']

    # Check if email is already registered
    if new_email in users_db:
        return jsonify({'error': 'Email already registered'}), 409

    # First verify current email
    # Generate OTP for current email verification
    otp = generate_otp()
    otp_expiry = datetime.now(timezone.utc) + timedelta(minutes=10)

    # Store OTP
    otps[username] = {
        'otp': otp,
        'expires': otp_expiry,
        'new_email': new_email,
        'for_current_email_verification': True
    }

    # Send OTP to current email
    if not send_otp_email(username, otp, "email_change"):
        return jsonify({'error': 'Failed to send verification email'}), 500

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

    # Now send OTP to new email
    new_otp = generate_otp()
    new_otp_expiry = datetime.now(timezone.utc) + timedelta(minutes=10)

    # Update OTP data
    otps[username] = {
        'otp': new_otp,
        'expires': new_otp_expiry,
        'new_email': new_email,
        'for_email_change': True
    }

    # Send OTP to new email
    if not send_otp_email(new_email, new_otp, "email_change"):
        return jsonify({'error': 'Failed to send verification email to new address'}), 500

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
        # Get current userInfo.json
        blob_client = blob_service_client.get_blob_client(
            container=CONTAINER_NAME,
            blob=f"{username}/userInfo.json"
        )

        user_info_blob = blob_client.download_blob()
        user_info = json.loads(user_info_blob.readall().decode('utf-8'))

        # Create a copy of the user's data
        new_user_data = users_db[username].copy()

        # Update email in the copy
        new_user_data['email'] = new_email

        # Add the new user with new email as username
        users_db[new_email] = new_user_data

        # Update email in userInfo
        user_info['email'] = new_email

        # Upload userInfo to the new location (new email as username)
        new_blob_client = blob_service_client.get_blob_client(
            container=CONTAINER_NAME,
            blob=f"{new_email}/userInfo.json"
        )

        new_blob_client.upload_blob(
            json.dumps(user_info),
            overwrite=True,
            content_settings=ContentSettings(content_type='application/json')
        )

        # Copy profile picture if it exists
        try:
            profile_pic_blob = blob_service_client.get_blob_client(
                container=CONTAINER_NAME,
                blob=f"{username}/profilePic.png"
            )

            if profile_pic_blob.exists():
                # Download existing profile picture
                pic_data = profile_pic_blob.download_blob().readall()

                # Upload to new location
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

        # Remove old user data
        del users_db[username]

        # Remove old user files (optional, can be kept for backup)
        # Delete only if the copy
        # Remove old user files (optional, can be kept for backup)
        # Delete only if the copy was successful
        try:
            # Delete old user info
            blob_client.delete_blob()

            # Delete old profile picture if it exists
            try:
                profile_pic_blob = blob_service_client.get_blob_client(
                    container=CONTAINER_NAME,
                    blob=f"{username}/profilePic.png"
                )
                if profile_pic_blob.exists():
                    profile_pic_blob.delete_blob()
            except Exception as e:
                print(f"Error deleting old profile picture: {str(e)}")
        except Exception as e:
            print(f"Error deleting old user data: {str(e)}")

        # Delete OTP data
        del otps[username]

        # Invalidate all tokens for the old username
        for token_id in list(active_tokens.keys()):
            if active_tokens[token_id]['username'] == username:
                del active_tokens[token_id]

        # Generate new JWT token with new username
        token = jwt.encode({
            'sub': new_email,
            'iat': datetime.now(timezone.utc),
            'exp': datetime.now(timezone.utc) + timedelta(hours=24)
        }, app.secret_key, algorithm='HS256')

        # Store token in active tokens
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

    # Verify current password
    current_password_hash = hashlib.sha256(current_password.encode()).hexdigest()
    if users_db[username]['password_hash'] != current_password_hash:
        return jsonify({'error': 'Current password is incorrect'}), 401

    # Update password
    new_password_hash = hashlib.sha256(new_password.encode()).hexdigest()
    users_db[username]['password_hash'] = new_password_hash

    try:
        # Update userInfo.json with last password change timestamp
        blob_client = blob_service_client.get_blob_client(
            container=CONTAINER_NAME,
            blob=f"{username}/userInfo.json"
        )

        user_info_blob = blob_client.download_blob()
        user_info = json.loads(user_info_blob.readall().decode('utf-8'))

        # We don't want to store the password hash in the user info file
        # But we're updating the last modified time
        user_info['last_password_change'] = datetime.now().isoformat()

        # Upload updated userInfo.json
        blob_client.upload_blob(
            json.dumps(user_info),
            overwrite=True,
            content_settings=ContentSettings(content_type='application/json')
        )

        # Invalidate all tokens for this user except the current one
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

    # Verify password
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    if users_db[username]['password_hash'] != password_hash:
        return jsonify({'error': 'Password is incorrect'}), 401

    try:
        # Delete all user files from Azure Blob Storage
        blob_list = blob_service_client.get_container_client(CONTAINER_NAME).list_blobs(name_starts_with=f"{username}/")
        for blob in blob_list:
            blob_service_client.get_blob_client(container=CONTAINER_NAME, blob=blob.name).delete_blob()

        # Remove user from users_db
        del users_db[username]

        # Invalidate all tokens for this user
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
        # This would typically have pagination and filtering in a production app
        users = []
        user_blobs = blob_service_client.get_container_client(CONTAINER_NAME).list_blobs()

        # Get unique user folders by splitting blob names and taking the first part
        user_folders = set()
        for blob in user_blobs:
            parts = blob.name.split('/')
            if len(parts) > 1:
                user_folders.add(parts[0])

        # Get basic info for each user
        for user_folder in user_folders:
            try:
                blob_client = blob_service_client.get_blob_client(
                    container=CONTAINER_NAME,
                    blob=f"{user_folder}/userInfo.json"
                )

                user_info_blob = blob_client.download_blob()
                user_info = json.loads(user_info_blob.readall().decode('utf-8'))

                # Check if profile picture exists
                has_profile_pic = False
                try:
                    profile_pic_blob = blob_service_client.get_blob_client(
                        container=CONTAINER_NAME,
                        blob=f"{user_folder}/profilePic.png"
                    )
                    has_profile_pic = profile_pic_blob.exists()
                except Exception:
                    pass

                # Add minimal user info
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
    try:
        # Sanitize email to prevent path traversal
        if not email or '@' not in email:
            return jsonify({"error": "Invalid email provided"}), 400

        # Define blob paths
        user_info_blob_path = f"{email}/userInfo.json"
        profile_pic_blob_path = f"{email}/profilePic.png"

        # Fetch userInfo.js
        blob_client = container_client.get_blob_client(user_info_blob_path)
        try:
            user_info_data = blob_client.download_blob().readall().decode('utf-8')
            user_info = json.loads(user_info_data)
        except Exception as e:
            return jsonify({"error": f"User info not found for {email}", "details": str(e)}), 404

        # Fetch profile picture or use default
        profile_pic_url = DEFAULT_PROFILE_PIC_URL
        blob_client = container_client.get_blob_client(profile_pic_blob_path)
        try:
            # Check if profile picture exists
            blob_client.get_blob_properties()
            # Generate a SAS URL for the profile picture (with limited time access)
            sas_token = blob_client.generate_shared_access_signature(
                permission="read",
                expiry=datetime.utcnow() + timedelta(hours=1)  # 1-hour access
            )
            profile_pic_url = f"{blob_client.url}?{sas_token}"
        except Exception:
            # If profile pic doesn't exist, keep the default URL
            pass

        # Prepare response
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
        
        # Fetch existing data
        current_data = json.loads(blob_client.download_blob().readall().decode('utf-8'))
        
        # Update only editable fields
        current_data.update({
            "full_name": data.get("full_name", current_data["full_name"]),
            "profession": data.get("profession", current_data["profession"]),
            "gender": data.get("gender", current_data["gender"]),
            "bio": data.get("bio", current_data["bio"])
        })
        
        # Upload updated data
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
        
        # Upload the new profile picture
        blob_client.upload_blob(file, overwrite=True)
        
        # Generate SAS URL
        sas_token = blob_client.generate_shared_access_signature(
            permission="read",
            expiry=datetime.utcnow() + timedelta(hours=1)
        )
        profile_pic_url = f"{blob_client.url}?{sas_token}"
        
        return jsonify({"profile_picture_url": profile_pic_url}), 200
    except Exception as e:
        return jsonify({"error": "Failed to upload profile picture", "details": str(e)}), 50


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint for monitoring."""
    try:
        # Check Azure Blob Storage connection
        container_client = blob_service_client.get_container_client(CONTAINER_NAME)
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


# Generate a secret key for the app if not provided
if not app.secret_key:
    app.secret_key = os.getenv('SECRET_KEY', os.urandom(24))


# Remove expired OTPs and tokens periodically
def cleanup_expired_data():
    """Remove expired OTPs and tokens."""
    current_time = datetime.now(timezone.utc)

    # Clean up expired OTPs
    for username in list(otps.keys()):
        if current_time > otps[username]['expires']:
            del otps[username]

    # Clean up expired tokens
    for token_id in list(active_tokens.keys()):
        expires = datetime.fromisoformat(active_tokens[token_id]['expires'])
        if current_time > expires:
            del active_tokens[token_id]


# Call cleanup on each request
@app.before_request
def before_request():
    cleanup_expired_data()


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug)
