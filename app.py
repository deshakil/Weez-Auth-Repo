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

# Email configuration for OTP
EMAIL_HOST = os.getenv('EMAIL_HOST')
EMAIL_PORT = 587
EMAIL_USER = os.getenv('EMAIL_USER')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')
EMAIL_FROM = os.getenv('EMAIL_SENDER')

# Initialize the BlobServiceClient
blob_service_client = BlobServiceClient.from_connection_string(AZURE_STORAGE_CONNECTION_STRING)

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


def generate_username_from_email(email):
    """Generate a username from email that preserves more of the original email structure."""
    # Replace @ with . and remove any special characters
    username = email.replace('@', '.')
    username = ''.join(c for c in username if c.isalnum() or c == '.')
    
    # If username is too long, truncate it
    if len(username) > 20:
        username = username[:20]
    
    return username


@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()

    if not data or not data.get('fullName') or not data.get('password') or not data.get('email'):
        return jsonify({'error': 'Full name, password, and email are required'}), 400

    full_name = data['fullName']
    password = data['password']
    email = data['email']

    # Generate a username based on email (more similar to the full email)
    
    username = email
    
    # Check if username already exists and add numbers if needed
    counter = 1
    while username in users_db or username in unverified_users:
        username = f"{base_username}{counter}"
        counter += 1

    # Check if email is already registered
    for user_data in users_db.values():
        if user_data.get('email') == email:
            return jsonify({'error': 'Email already registered'}), 409

    for user_data in unverified_users.values():
        if user_data.get('email') == email:
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
        return jsonify({'error': 'Username and OTP are required'}), 400

    username = data['username']
    otp = data['otp']

    if username not in unverified_users:
        return jsonify({'error': 'Invalid username'}), 404

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
        return jsonify({'error': 'Username is required'}), 400

    username = data['username']

    if username not in incomplete_profiles:
        return jsonify({'error': 'Invalid username or email already verified'}), 404

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
        return jsonify({'error': 'Username is required'}), 400

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
        return jsonify({'error': 'Invalid username or no pending verification'}), 404

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

    # Find user by email
    username = None
    for user, user_data in users_db.items():
        if user_data.get('email') == email:
            username = user
            break

    if not username:
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
        return jsonify({'error': 'Username and OTP are required'}), 400

    username = data['username']
    otp = data['otp']

    if username not in users_db:
        return jsonify({'error': 'Invalid username'}), 404

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
    found_username = None

    # Find user by email
    for username, user_data in users_db.items():
        if user_data.get('email') == email:
            found_username = username
            break

    if not found_username:
        # Don't reveal that email doesn't exist for security reasons
        return jsonify({'message': 'If the email exists, a reset code has been sent.'}), 200

    # Generate OTP for password reset
    otp = generate_otp()
    otp_expiry = datetime.now(timezone.utc) + timedelta(minutes=10)

    # Store OTP
    otps[found_username] = {
        'otp': otp,
        'expires': otp_expiry,
        'for_password_reset': True
    }

    # Send OTP via email
    if not send_otp_email(email, otp, "password_reset"):
        return jsonify({'error': 'Failed to send password reset email'}), 500

    return jsonify({
        'message': 'Password reset code sent to your email',
        'username': found_username
    }), 200


@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()

    if not data or not data.get('username') or not data.get('otp') or not data.get('new_password'):
        return jsonify({'error': 'Username, OTP, and new password are required'}), 400

    username = data['username']
    otp = data['otp']
    new_password = data['new_password']

    if username not in users_db:
        return jsonify({'error': 'Invalid username'}), 404

    if username not in otps or not otps[username].get('for_password_reset'):
        return jsonify({'error': 'No valid password reset request found'}), 404

    if datetime.now(timezone.utc) > otps[username]['expires']:
        del otps[username]
        return jsonify({'error': 'Reset code expired. Please request a new one.'}), 401

    if otps[username]['otp'] != otp:
        return jsonify({'error': 'Invalid reset code'}), 401

    # Update password
    new_password_hash = hashlib.sha256(new_password.encode()).hexdigest()
    users_db[username]['password_hash'] = new_password_hash

    try:
        # Update userInfo.json with new password hash
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
    except Exception as e:
        print(f"Error updating user info: {str(e)}")
        # Continue anyway, as the password is updated in memory

    # Remove OTP
    del otps[username]

    # Invalidate all tokens for this user
    for token_id in list(active_tokens.keys()):
        if active_tokens[token_id]['username'] == username:
            del active_tokens[token_id]

    return jsonify({'message': 'Password reset successfully'}), 200


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

        # Add username to response
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
            blob=f"{username}/profilePic.png"  # Changed from profile.png to profilePic.png
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
            blob=f"{target_username}/profilePic.png"  # Changed from profile.png to profilePic.png
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
    username, error = authenticate_request()
    if error:
        return jsonify({'error': error[0]}), error[1]

    data = request.get_json()
    if not data or not data.get('new_email'):
        return jsonify({'error': 'New email is required'}), 400

    new_email = data['new_email']

    # Check if email is already registered
    for user, user_data in users_db.items():
        if user != username and user_data.get('email') == new_email:
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
    if not send_otp_email(users_db[username]['email'], otp, "email_change"):
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

    # Update email in users_db
    users_db[username]['email'] = new_email

    # Update email in userInfo.json
    try:
        # Get current userInfo.json
        blob_client = blob_service_client.get_blob_client(
            container=CONTAINER_NAME,
            blob=f"{username}/userInfo.json"
        )

        user_info_blob = blob_client.download_blob()
        user_info = json.loads(user_info_blob.readall().decode('utf-8'))

        # Update email
        user_info['email'] = new_email

        # Upload updated userInfo.json
        blob_client.upload_blob(
            json.dumps(user_info),
            overwrite=True,
            content_settings=ContentSettings(content_type='application/json')
        )

        # Remove OTP
        del otps[username]

        return jsonify({'message': 'Email changed successfully'}), 200
    except Exception as e:
        return jsonify({'error': f'Error updating email: {str(e)}'}), 500


if __name__ == '__main__':
    app.run(debug=True)
