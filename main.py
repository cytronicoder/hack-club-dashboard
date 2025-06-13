import os
import time
import json
import hashlib
import requests
import re
import html
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, redirect, flash, request, jsonify, url_for, abort, session, Response
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import string
import urllib.parse

try:
    from flask_session import Session
    session_available = True
except ImportError:
    session_available = False

# Input validation and sanitization utilities
class InputValidator:

    # Regex patterns for validation
    USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{3,30}$')
    EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    NAME_PATTERN = re.compile(r'^[a-zA-Z\s\'-]{1,50}$')
    URL_PATTERN = re.compile(r'^https?://[^\s<>"]{1,500}$')
    CLUB_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9\s\'-]{4,100}$')
    VERIFICATION_CODE_PATTERN = re.compile(r'^[0-9]{6}$')
    TIME_PATTERN = re.compile(r'^([01]?[0-9]|2[0-3]):[0-5][0-9]$')
    DATE_PATTERN = re.compile(r'^[0-9]{4}-[0-9]{2}-[0-9]{2}$')
    JOIN_CODE_PATTERN = re.compile(r'^[A-Z0-9]{8}$')

    @staticmethod
    def sanitize_text(text):
        """Sanitize text input to prevent XSS"""
        if not text:
            return text
        return html.escape(str(text).strip())

    @staticmethod
    def validate_username(username):
        """Validate username format"""
        if not username:
            return False, "Username is required"
        username = username.strip()
        if not InputValidator.USERNAME_PATTERN.match(username):
            return False, "Username must be 3-30 characters and contain only letters, numbers, hyphens, and underscores"
        return True, username

    @staticmethod
    def validate_email(email):
        """Validate email format"""
        if not email:
            return False, "Email is required"
        email = email.strip().lower()
        if not InputValidator.EMAIL_PATTERN.match(email):
            return False, "Invalid email format"
        return True, email

    @staticmethod
    def validate_name(name, field_name="Name"):
        """Validate name fields"""
        if not name:
            return False, f"{field_name} is required"
        name = name.strip()
        if not InputValidator.NAME_PATTERN.match(name):
            return False, f"{field_name} can only contain letters, spaces, hyphens, and apostrophes"
        return True, name

    @staticmethod
    def validate_url(url, field_name="URL"):
        """Validate URL format"""
        if not url:
            return False, f"{field_name} is required"
        url = url.strip()
        if not InputValidator.URL_PATTERN.match(url):
            return False, f"Invalid {field_name} format. Must be a valid HTTP/HTTPS URL"
        return True, url

    @staticmethod
    def validate_club_name(club_name):
        """Validate club name format"""
        if not club_name:
            return False, "Club name is required"
        club_name = club_name.strip()
        if not InputValidator.CLUB_NAME_PATTERN.match(club_name):
            return False, "Club name must be 4-100 characters and contain only letters, numbers, spaces, hyphens, and apostrophes"
        return True, club_name

    @staticmethod
    def validate_verification_code(code):
        """Validate verification code format"""
        if not code:
            return False, "Verification code is required"
        code = code.strip()
        if not InputValidator.VERIFICATION_CODE_PATTERN.match(code):
            return False, "Verification code must be 6 digits"
        return True, code

    @staticmethod
    def validate_date(date_str, field_name="Date"):
        """Validate date format"""
        if not date_str:
            return False, f"{field_name} is required"
        date_str = date_str.strip()
        if not InputValidator.DATE_PATTERN.match(date_str):
            return False, f"Invalid {field_name} format. Use YYYY-MM-DD"
        try:
            datetime.strptime(date_str, '%Y-%m-%d')
            return True, date_str
        except ValueError:
            return False, f"Invalid {field_name}"

    @staticmethod
    def validate_time(time_str, field_name="Time"):
        """Validate time format"""
        if not time_str:
            return False, f"{field_name} is required"
        time_str = time_str.strip()
        if not InputValidator.TIME_PATTERN.match(time_str):
            return False, f"Invalid {field_name} format. Use HH:MM"
        return True, time_str

    @staticmethod
    def validate_text_content(text, min_length=1, max_length=5000, field_name="Text"):
        """Validate text content"""
        if not text:
            return False, f"{field_name} is required"
        text = text.strip()
        if len(text) < min_length:
            return False, f"{field_name} must be at least {min_length} characters"
        if len(text) > max_length:
            return False, f"{field_name} must be no more than {max_length} characters"
        return True, InputValidator.sanitize_text(text)

    @staticmethod
    def validate_password(password):
        """Validate password strength"""
        if not password:
            return False, "Password is required"
        if len(password) < 6:
            return False, "Password must be at least 6 characters long"
        if len(password) > 128:
            return False, "Password must be no more than 128 characters long"
        return True, password

    @staticmethod
    def validate_join_code(join_code):
        """Validate join code format"""
        if not join_code:
            return False, "Join code is required"
        join_code = join_code.strip().upper()
        if not InputValidator.JOIN_CODE_PATTERN.match(join_code):
            return False, "Invalid join code format"
        return True, join_code

def get_database_url():
    url = os.getenv('DATABASE_URL')
    if url and url.startswith('postgres://'):
        url = url.replace('postgres://', 'postgresql://', 1)
    return url

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(16))
app.config['SQLALCHEMY_DATABASE_URI'] = get_database_url()
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configure logging for production
import logging
if os.getenv('FLASK_ENV') == 'production':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(name)s %(message)s',
        handlers=[
            logging.StreamHandler()
        ]
    )
    app.logger.setLevel(logging.INFO)
    app.logger.info('Flask app starting in production mode')
    app.logger.info(f'Database URL configured: {bool(get_database_url())}')
    app.logger.info(f'Environment variables loaded: SECRET_KEY={bool(os.getenv("SECRET_KEY"))}, DATABASE_URL={bool(os.getenv("DATABASE_URL"))}')

# Configure persistent sessions
if session_available:
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_FILE_DIR'] = os.path.join(os.getcwd(), 'flask_session')
    app.config['SESSION_PERMANENT'] = True
    app.config['SESSION_USE_SIGNER'] = True
    app.config['SESSION_KEY_PREFIX'] = 'hackclub_'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)

    # Create session directory if it doesn't exist
    os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)

    Session(app)

SLACK_CLIENT_ID = os.getenv('SLACK_CLIENT_ID')
SLACK_CLIENT_SECRET = os.getenv('SLACK_CLIENT_SECRET')
SLACK_SIGNING_SECRET = os.getenv('SLACK_SIGNING_SECRET')

db_available = True
db = None
login_manager = None
limiter = None

try:
    db = SQLAlchemy(app)
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    login_manager.session_protection = "strong"

    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=["5000 per hour", "500 per minute"],
        storage_uri="memory://",
        strategy="fixed-window"
    )
    
    if os.getenv('FLASK_ENV') == 'production':
        app.logger.info('Database and components initialized successfully')
except Exception as e:
    error_msg = f"Database initialization failed: {e}"
    print(error_msg)
    if os.getenv('FLASK_ENV') == 'production':
        app.logger.error(error_msg)
    db_available = False
    
    # Create a dummy limiter that does nothing when database is unavailable
    class DummyLimiter:
        def limit(self, *args, **kwargs):
            def decorator(f):
                return f
            return decorator
    
    limiter = DummyLimiter()

# Models - only define if database is available
if db_available and db is not None:
    class User(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(80), unique=True, nullable=False)
        email = db.Column(db.String(120), unique=True, nullable=False)
        password_hash = db.Column(db.String(255), nullable=False)
        first_name = db.Column(db.String(50))
        last_name = db.Column(db.String(50))
        birthday = db.Column(db.Date)
        created_at = db.Column(db.DateTime, default=datetime.utcnow)
        last_login = db.Column(db.DateTime)
        is_admin = db.Column(db.Boolean, default=False)
        is_suspended = db.Column(db.Boolean, default=False)
        hackatime_api_key = db.Column(db.String(255))
        slack_user_id = db.Column(db.String(255), unique=True)

        def set_password(self, password):
            self.password_hash = generate_password_hash(password)

        def check_password(self, password):
            return check_password_hash(self.password_hash, password)

        def is_authenticated(self):
            return True

        def is_active(self):
            return not self.is_suspended

        def is_anonymous(self):
            return False

        def get_id(self):
            return str(self.id)

    class Club(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        name = db.Column(db.String(100), nullable=False)
        description = db.Column(db.Text)
        location = db.Column(db.String(255))
        leader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
        join_code = db.Column(db.String(8), unique=True, nullable=False)
        created_at = db.Column(db.DateTime, default=datetime.utcnow)
        balance = db.Column(db.Numeric(10, 2), default=0.00)

        leader = db.relationship('User', backref='led_clubs')
        members = db.relationship('ClubMembership', back_populates='club', cascade='all, delete-orphan')

        def generate_join_code(self):
            self.join_code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))

    class ClubMembership(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
        club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
        role = db.Column(db.String(20), default='member')  # member, co-leader
        joined_at = db.Column(db.DateTime, default=datetime.utcnow)

        user = db.relationship('User', backref='club_memberships')
        club = db.relationship('Club', back_populates='members')

    class ClubPost(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
        user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
        content = db.Column(db.Text, nullable=False)
        created_at = db.Column(db.DateTime, default=datetime.utcnow)

        club = db.relationship('Club', backref='posts')
        user = db.relationship('User', backref='posts')

    class ClubAssignment(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
        title = db.Column(db.String(200), nullable=False)
        description = db.Column(db.Text, nullable=False)
        due_date = db.Column(db.DateTime)
        for_all_members = db.Column(db.Boolean, default=True)
        status = db.Column(db.String(20), default='active')
        created_at = db.Column(db.DateTime, default=datetime.utcnow)

        club = db.relationship('Club', backref='assignments')

    class ClubMeeting(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
        title = db.Column(db.String(200), nullable=False)
        description = db.Column(db.Text)
        meeting_date = db.Column(db.Date, nullable=False)
        start_time = db.Column(db.String(10), nullable=False)
        end_time = db.Column(db.String(10))
        location = db.Column(db.String(255))
        meeting_link = db.Column(db.String(500))
        created_at = db.Column(db.DateTime, default=datetime.utcnow)

        club = db.relationship('Club', backref='meetings')

    class ClubResource(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
        title = db.Column(db.String(200), nullable=False)
        url = db.Column(db.String(500), nullable=False)
        description = db.Column(db.Text)
        icon = db.Column(db.String(50), default='book')
        created_at = db.Column(db.DateTime, default=datetime.utcnow)

        club = db.relationship('Club', backref='resources')

    class ClubProject(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
        user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
        name = db.Column(db.String(200), nullable=False)
        description = db.Column(db.Text)
        url = db.Column(db.String(500))
        github_url = db.Column(db.String(500))
        featured = db.Column(db.Boolean, default=False)
        created_at = db.Column(db.DateTime, default=datetime.utcnow)
        updated_at = db.Column(db.DateTime, default=datetime.utcnow)

        club = db.relationship('Club', backref='projects')
        user = db.relationship('User', backref='projects')

    class APIKey(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        key = db.Column(db.String(64), unique=True, nullable=False)
        name = db.Column(db.String(200), nullable=False)
        description = db.Column(db.Text)
        user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
        created_at = db.Column(db.DateTime, default=datetime.utcnow)
        last_used_at = db.Column(db.DateTime)
        is_active = db.Column(db.Boolean, default=True)
        rate_limit = db.Column(db.Integer, default=1000)  # requests per hour
        scopes = db.Column(db.Text)  # JSON array of allowed scopes

        user = db.relationship('User', backref='api_keys')

        def generate_key(self):
            self.key = secrets.token_urlsafe(48)

    class OAuthApplication(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        client_id = db.Column(db.String(64), unique=True, nullable=False)
        client_secret = db.Column(db.String(128), nullable=False)
        name = db.Column(db.String(200), nullable=False)
        description = db.Column(db.Text)
        redirect_uris = db.Column(db.Text)  # JSON array of allowed redirect URIs
        user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
        created_at = db.Column(db.DateTime, default=datetime.utcnow)
        is_active = db.Column(db.Boolean, default=True)
        scopes = db.Column(db.Text)  # JSON array of allowed scopes

        user = db.relationship('User', backref='oauth_applications')

        def generate_credentials(self):
            self.client_id = secrets.token_urlsafe(32)
            self.client_secret = secrets.token_urlsafe(64)

    class OAuthToken(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        access_token = db.Column(db.String(128), unique=True, nullable=False)
        refresh_token = db.Column(db.String(128), unique=True)
        user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
        application_id = db.Column(db.Integer, db.ForeignKey('o_auth_application.id'), nullable=False)
        scopes = db.Column(db.Text)  # JSON array of granted scopes
        expires_at = db.Column(db.DateTime, nullable=False)
        created_at = db.Column(db.DateTime, default=datetime.utcnow)
        is_active = db.Column(db.Boolean, default=True)

        user = db.relationship('User')
        application = db.relationship('OAuthApplication')

        def generate_tokens(self):
            self.access_token = secrets.token_urlsafe(48)
            self.refresh_token = secrets.token_urlsafe(48)
            self.expires_at = datetime.utcnow() + timedelta(hours=1)

    class OAuthAuthorizationCode(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        code = db.Column(db.String(128), unique=True, nullable=False)
        user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
        application_id = db.Column(db.Integer, db.ForeignKey('o_auth_application.id'), nullable=False)
        redirect_uri = db.Column(db.String(500), nullable=False)
        scopes = db.Column(db.Text)  # JSON array of requested scopes
        state = db.Column(db.String(500))
        expires_at = db.Column(db.DateTime, nullable=False)
        used = db.Column(db.Boolean, default=False)
        created_at = db.Column(db.DateTime, default=datetime.utcnow)

        user = db.relationship('User')
        application = db.relationship('OAuthApplication')

        def generate_code(self):
            self.code = secrets.token_urlsafe(32)
            self.expires_at = datetime.utcnow() + timedelta(minutes=10)
else:
    # Define dummy classes when database is not available
    class User:
        pass
    class Club:
        pass
    class ClubMembership:
        pass
    class ClubPost:
        pass
    class ClubAssignment:
        pass
    class ClubMeeting:
        pass
    class ClubResource:
        pass
    class ClubProject:
        pass
    class APIKey:
        pass
    class OAuthApplication:
        pass
    class OAuthToken:
        pass
    class OAuthAuthorizationCode:
        pass

def load_user(user_id):
    if not db_available:
        return None
    return db.session.get(User, int(user_id))

if login_manager is not None:
    login_manager.user_loader(load_user)

# Airtable Service for Pizza Grants
class AirtableService:
    def __init__(self):
        self.api_token = os.environ.get('AIRTABLE_TOKEN')
        self.base_id = os.environ.get('AIRTABLE_BASE_ID', 'appSnnIu0BhjI3E1p')
        self.table_name = os.environ.get('AIRTABLE_TABLE_NAME', 'YSWS Project Submission')
        self.headers = {
            'Authorization': f'Bearer {self.api_token}',
            'Content-Type': 'application/json'
        }
        # URL encode the table name properly
        import urllib.parse
        encoded_table_name = urllib.parse.quote(self.table_name)
        self.base_url = f'https://api.airtable.com/v0/{self.base_id}/{encoded_table_name}'

    def log_pizza_grant(self, submission_data):
        if not self.api_token:
            print("No Airtable API token found")
            return None

        # Calculate age from birthday if provided
        age = None
        if submission_data.get('birthday'):
            try:
                birth_date = datetime.strptime(submission_data.get('birthday'), '%Y-%m-%d')
                today = datetime.now()
                age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
            except:
                age = None

        # Calculate grant amount based on hours
        hours = float(submission_data.get('project_hours', 0))
        if hours >= 2:
            grant_amount = 10
        elif hours >= 1:
            grant_amount = 5
        else:
            grant_amount = 0

        fields = {
            'Hackatime Project': submission_data.get('project_name', ''),
            'First Name': submission_data.get('first_name', ''),
            'Last Name': submission_data.get('last_name', ''),
            'GitHub Username': submission_data.get('username', ''),
            'Email': submission_data.get('email', ''),
            'Birthday': submission_data.get('birthday', ''),
            'Description': submission_data.get('project_description', ''),
            'Playable URL': submission_data.get('live_url', ''),
            'Code URL': submission_data.get('github_url', ''),
            'What are we doing well?': submission_data.get('doing_well', ''),
            'How can we improve?': submission_data.get('improve', ''),
            'Address (Line 1)': submission_data.get('address_1', ''),
            'Address (Line 2)': submission_data.get('address_2', ''),
            'City': submission_data.get('city', ''),
            'State / Province': submission_data.get('state', ''),
            'ZIP / Postal Code': submission_data.get('zip', ''),
            'Country': submission_data.get('country', ''),
            'Club Name': submission_data.get('club_name', 'Unknown Club'),
            'Leader Email': submission_data.get('leader_email', ''),
            'Hours': str(hours),
            'Grant Amount': f"${grant_amount}",
            'Status': 'Pending',
            'Screenshot': [{'url': submission_data.get('screenshot_url', '')}] if submission_data.get('screenshot_url') else [],
            'How did you hear about this?': 'Hack Club Spaces'
        }

        payload = {'records': [{'fields': fields}]}

        try:
            response = requests.post(self.base_url, headers=self.headers, json=payload)

            if response.status_code in [200, 201]:
                return response.json()
            else:
                print(f"Airtable error: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            print(f"Error logging to Airtable: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

airtable_service = AirtableService()

# Leader Verification Service with Email Verification
class LeaderVerificationService:
    def __init__(self):
        self.api_token = os.environ.get('AIRTABLE_TOKEN')
        self.base_id = os.environ.get('AIRTABLE_BASE_ID', 'appSnnIu0BhjI3E1p')
        self.table_name = 'Club Leaders & Emails'
        self.verification_table = 'Leader Verification'
        self.headers = {
            'Authorization': f'Bearer {self.api_token}',
            'Content-Type': 'application/json'
        }
        import urllib.parse
        encoded_table_name = urllib.parse.quote(self.table_name)
        encoded_verification_table = urllib.parse.quote(self.verification_table)
        self.base_url = f'https://api.airtable.com/v0/{self.base_id}/{encoded_table_name}'
        self.verification_url = f'https://api.airtable.com/v0/{self.base_id}/{encoded_verification_table}'

    def send_verification_email(self, email, club_name, user_name):
        if not self.api_token:
            return {'success': False, 'error': 'Verification service unavailable'}

        try:
            # Clean input club name first
            clean_input_club_name = str(club_name).strip().strip('"\'')
            print(f"DEBUG: Original club name: '{club_name}'")
            print(f"DEBUG: Cleaned input club name: '{clean_input_club_name}'")

            # First check if this is a valid leader
            params = {
                'filterByFormula': f'AND(SEARCH(LOWER("{email}"), LOWER({{Current Leaders\' Emails}})), SEARCH(LOWER("{clean_input_club_name[:4]}"), LOWER({{Venue}})))'
            }

            response = requests.get(self.base_url, headers=self.headers, params=params)

            if response.status_code != 200:
                return {'success': False, 'error': f'Verification failed: {response.status_code}'}

            data = response.json()
            records = data.get('records', [])

            leader_found = False
            verified_club_name = clean_input_club_name

            for record in records:
                fields = record.get('fields', {})
                venue = fields.get('Venue', '').lower()
                emails = fields.get("Current Leaders' Emails", '').lower()

                if (clean_input_club_name.lower()[:4] in venue and 
                    len(clean_input_club_name) >= 4 and 
                    email.lower() in emails):
                    leader_found = True
                    # Clean the venue name from Airtable response thoroughly
                    raw_venue = fields.get('Venue', clean_input_club_name)
                    verified_club_name = str(raw_venue).strip()
                    # Remove any quotes that might be in the data
                    import re
                    verified_club_name = re.sub(r'^["\']|["\']$', '', verified_club_name).strip()
                    # Remove any remaining escaped quotes
                    verified_club_name = verified_club_name.replace('\\"', '').replace("\\'", '').strip()
                    break

            if not leader_found:
                return {'success': False, 'error': 'No matching club and email combination found'}

            # Generate verification code
            verification_code = ''.join(secrets.choice(string.digits) for _ in range(6))

            # Store verification request in Airtable
            # Clean the verified club name - just strip whitespace, don't remove quotes aggressively
            final_club_name = str(verified_club_name).strip()
            print(f"DEBUG: Verified club name: '{verified_club_name}'")
            print(f"DEBUG: Final club name for Airtable: '{final_club_name}'")

            fields = {
                'Email': email,
                'Code': verification_code,
                'Club': final_club_name
            }

            payload = {'records': [{'fields': fields}]}
            print(f"DEBUG: Payload being sent to Airtable: {payload}")
            verification_response = requests.post(self.verification_url, headers=self.headers, json=payload)

            if verification_response.status_code in [200, 201]:
                return {
                    'success': True, 
                    'message': f'Verification code sent to {email}',
                    'club_name': verified_club_name
                }
            else:
                print(f"Airtable verification error: {verification_response.status_code} - {verification_response.text}")
                return {'success': False, 'error': 'Failed to send verification email'}

        except Exception as e:
            print(f"Error sending verification email: {str(e)}")
            return {'success': False, 'error': f'Verification error: {str(e)}'}

    def verify_code(self, email, code):
        if not self.api_token:
            return {'verified': False, 'error': 'Verification service unavailable'}

        try:
            # Search for verification with matching email and code
            params = {
                'filterByFormula': f'AND({{Email}} = "{email}", {{Code}} = "{code}")'
            }

            print(f"DEBUG: Verification lookup params: {params}")
            response = requests.get(self.verification_url, headers=self.headers, params=params)
            print(f"DEBUG: Verification lookup response: {response.status_code} - {response.text}")

            if response.status_code == 200:
                data = response.json()
                records = data.get('records', [])

                if records:
                    # Found matching verification record
                    record = records[0]
                    record_id = record['id']
                    fields = record.get('fields', {})

                    # Check if already verified
                    if fields.get('Status') == 'Verified':
                        return {'verified': False, 'error': 'Verification code already used'}

                    # Check if verification is not too old (e.g., within 1 hour)
                    if fields.get('Created'):
                        try:
                            created_time = datetime.fromisoformat(fields.get('Created', '').replace('Z', '+00:00'))
                            if datetime.utcnow() - created_time.replace(tzinfo=None) > timedelta(hours=1):
                                return {'verified': False, 'error': 'Verification code expired'}
                        except:
                            pass

                    # Update record status to verified (if Status field exists)
                    update_payload = {
                        'fields': {
                            'Status': 'Verified'
                        }
                    }

                    # Try to update, but don't fail if Status field doesn't exist
                    try:
                        update_response = requests.patch(
                            f'{self.verification_url}/{record_id}', 
                            headers=self.headers, 
                            json=update_payload
                        )
                        print(f"DEBUG: Update response: {update_response.status_code} - {update_response.text}")
                    except Exception as update_error:
                        print(f"DEBUG: Update failed (non-critical): {update_error}")

                    return {
                        'verified': True,
                        'club_name': fields.get('Club', ''),
                        'email': fields.get('Email', '')
                    }

                return {'verified': False, 'error': 'Invalid verification code or email'}
            else:
                print(f"Airtable verification lookup error: {response.status_code} - {response.text}")
                return {'verified': False, 'error': f'Verification check failed: {response.status_code}'}

        except Exception as e:
            print(f"Error verifying code: {str(e)}")
            import traceback
            traceback.print_exc()
            return {'verified': False, 'error': f'Verification error: {str(e)}'}

    def verify_leader(self, club_name, email):
        # Legacy method for backward compatibility
        if not self.api_token:
            return {'verified': False, 'error': 'Verification service unavailable'}

        try:
            params = {
                'filterByFormula': f'AND(SEARCH(LOWER("{email}"), LOWER({{Current Leaders\' Emails}})), SEARCH(LOWER("{club_name[:4]}"), LOWER({{Venue}})))'
            }

            response = requests.get(self.base_url, headers=self.headers, params=params)

            if response.status_code == 200:
                data = response.json()
                records = data.get('records', [])

                if records:
                    for record in records:
                        fields = record.get('fields', {})
                        venue = fields.get('Venue', '').lower()
                        emails = fields.get("Current Leaders' Emails", '').lower()

                        if (club_name.lower()[:4] in venue and 
                            len(club_name) >= 4 and 
                            email.lower() in emails):
                            return {
                                'verified': True, 
                                'club_name': fields.get('Venue', ''),
                                'leaders': fields.get('Current Leader(s)', '')
                            }

                return {'verified': False, 'error': 'No matching club and email combination found'}
            else:
                return {'verified': False, 'error': f'Verification failed: {response.status_code}'}

        except Exception as e:
            print(f"Error verifying leader: {str(e)}")
            return {'verified': False, 'error': f'Verification error: {str(e)}'}

leader_verification_service = LeaderVerificationService()

# Hackatime Service
class HackatimeService:
    def __init__(self):
        self.base_url = "https://hackatime.hackclub.com/api/v1"

    def get_user_stats(self, api_key):
        if not api_key:
            return None

        url = f"{self.base_url}/users/my/stats?features=projects"
        headers = {"Authorization": f"Bearer {api_key}"}

        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            print(f"Hackatime API error: {str(e)}")
            return None

    def get_user_projects(self, api_key):
        stats = self.get_user_stats(api_key)
        if not stats or 'data' not in stats:
            return []

        projects = stats['data'].get('projects', [])
        # Filter projects with activity and sort by total_seconds
        active_projects = [p for p in projects if p.get('total_seconds', 0) > 0]
        active_projects.sort(key=lambda x: x.get('total_seconds', 0), reverse=True)

        # Format the data
        for project in active_projects:
            # Convert seconds to a human-readable format
            total_seconds = project.get('total_seconds', 0)
            project['formatted_time'] = self.format_duration(total_seconds)

        return active_projects

    def format_duration(self, total_seconds):
        """Convert seconds to human-readable format (days, hours, minutes)"""
        if total_seconds < 60:
            return f"{total_seconds}s"

        minutes = total_seconds // 60
        hours = minutes // 60
        days = hours // 24

        remaining_hours = hours % 24
        remaining_minutes = minutes % 60

        parts = []
        if days > 0:
            parts.append(f"{days}d")
        if remaining_hours > 0:
            parts.append(f"{remaining_hours}h")
        if remaining_minutes > 0:
            parts.append(f"{remaining_minutes}m")

        return " ".join(parts) if parts else "0m"

hackatime_service = HackatimeService()

# Slack OAuth Service
class SlackOAuthService:
    def __init__(self):
        self.client_id = SLACK_CLIENT_ID
        self.client_secret = SLACK_CLIENT_SECRET
        self.base_url = "https://slack.com/api"

    def get_auth_url(self, redirect_uri):
        params = {
            'client_id': self.client_id,
            'scope': 'users:read,users:read.email,users.profile:read',
            'user_scope': 'identity.basic,identity.email,identity.avatar',
            'redirect_uri': redirect_uri,
            'state': secrets.token_urlsafe(32)
        }
        session['oauth_state'] = params['state']
        return f"https://slack.com/oauth/v2/authorize?{urllib.parse.urlencode(params)}"

    def exchange_code(self, code, redirect_uri):
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'redirect_uri': redirect_uri
        }

        try:
            response = requests.post('https://slack.com/api/oauth.v2.access', data=data)
            response_data = response.json()

            return response_data
        except Exception as e:
            print(f"Error during Slack OAuth token exchange: {str(e)}")
            return {'ok': False, 'error': f'Request failed: {str(e)}'}

    def get_user_info(self, access_token):
        headers = {'Authorization': f'Bearer {access_token}'}

        identity_url = f'{self.base_url}/users.identity'

        identity_response = requests.get(identity_url, headers=headers)

        if identity_response.status_code != 200:
            print(f"ERROR: Identity request failed with status {identity_response.status_code}")
            return None

        try:
            identity_data = identity_response.json()
        except Exception as e:
            print(f"ERROR: Failed to parse identity response as JSON: {e}")
            return None

        if not identity_data.get('ok'):
            print(f"ERROR: Identity response not ok: {identity_data.get('error', 'Unknown error')}")
            return None

        user_id = identity_data['user']['id']

        # Get detailed user profile
        profile_url = f'{self.base_url}/users.info'
        profile_params = {'user': user_id}

        profile_response = requests.get(profile_url, headers=headers, params=profile_params)

        if profile_response.status_code != 200:
            print(f"WARNING: Profile request failed with status {profile_response.status_code}, using identity data only")
            return identity_data

        try:
            profile_data = profile_response.json()
        except Exception as e:
            print(f"WARNING: Failed to parse profile response as JSON: {e}, using identity data only")
            return identity_data

        if profile_data.get('ok'):
            # Merge identity and profile data
            identity_data['user']['profile'] = profile_data['user']['profile']
        else:
            print(f"WARNING: Profile response not ok: {profile_data.get('error', 'Unknown error')}")

        return identity_data

slack_oauth_service = SlackOAuthService()

# Slack OAuth Routes
@app.route('/auth/slack')
@limiter.limit("100 per minute")
def slack_login():
    if not SLACK_CLIENT_ID or not SLACK_CLIENT_SECRET:
        flash('Slack OAuth is not configured', 'error')
        return redirect(url_for('login'))

    redirect_uri = url_for('slack_callback', _external=True, _scheme='https')
    auth_url = slack_oauth_service.get_auth_url(redirect_uri)
    return redirect(auth_url)

@app.route('/auth/slack/callback')
@limiter.limit("100 per minute")
def slack_callback():
    if not db_available:
        flash('Database is currently unavailable. Please try again later.', 'error')
        return redirect(url_for('login'))

    # Verify state parameter
    if request.args.get('state') != session.get('oauth_state'):
        flash('Invalid OAuth state parameter', 'error')
        return redirect(url_for('login'))

    code = request.args.get('code')
    if not code:
        error = request.args.get('error', 'Unknown error')
        flash(f'Slack authorization failed: {error}', 'error')
        return redirect(url_for('login'))

    # Exchange code for access token
    redirect_uri = url_for('slack_callback', _external=True, _scheme='https')
    token_data = slack_oauth_service.exchange_code(code, redirect_uri)

    if not token_data.get('ok'):
        error = token_data.get('error', 'Token exchange failed')
        flash(f'Slack authentication failed: {error}', 'error')
        return redirect(url_for('login'))

    # We need a user token, not a bot token, for user identity
    # The bot token is in 'access_token' but we need the user token from 'authed_user'
    user_token = None
    if 'authed_user' in token_data:
        user_token = token_data['authed_user'].get('access_token')

    if not user_token:
        user_token = token_data.get('access_token')

    if not user_token:
        flash('Failed to get user access token from Slack', 'error')
        return redirect(url_for('login'))

    access_token = user_token

    # Get user information
    user_info = slack_oauth_service.get_user_info(access_token)
    if not user_info or not user_info.get('ok'):
        # Fallback: use data from OAuth response if user info fails
        if 'authed_user' in token_data:
            slack_user_id = token_data['authed_user']['id']
            email = None
            name = f"user_{slack_user_id}"
            real_name = ""
            profile = {}

            # Create minimal user info structure
            user_info = {
                'ok': True,
                'user': {
                    'id': slack_user_id,
                    'name': name,
                    'real_name': real_name,
                    'profile': profile
                }
            }
        else:
            flash('Failed to retrieve user information from Slack', 'error')
            return redirect(url_for('login'))

    slack_user = user_info['user']
    slack_user_id = slack_user['id']
    email = slack_user.get('email')
    name = slack_user.get('name', '')
    real_name = slack_user.get('real_name', '')
    profile = slack_user.get('profile', {})

    # Try to find existing user by Slack ID or email
    user = None
    if slack_user_id:
        user = User.query.filter_by(slack_user_id=slack_user_id).first()

    if not user and email:
        user = User.query.filter_by(email=email).first()
        if user:
            # Link Slack account to existing user
            user.slack_user_id = slack_user_id
            db.session.commit()

    if user:
        # User exists, log them in
        login_user(user)
        session.permanent = True
        user.last_login = datetime.utcnow()
        db.session.commit()
        flash(f'Welcome back, {user.username}!', 'success')
        return redirect(url_for('dashboard'))
    else:
        # New user, store Slack data in session and show completion modal
        session['slack_signup_data'] = {
            'slack_user_id': slack_user_id,
            'email': email or '',
            'name': name,
            'real_name': real_name,
            'first_name': profile.get('first_name', ''),
            'last_name': profile.get('last_name', ''),
            'display_name': profile.get('display_name', ''),
            'image_url': profile.get('image_512', profile.get('image_192', ''))
        }
        return redirect(url_for('complete_slack_signup'))

@app.route('/complete-slack-signup', methods=['GET', 'POST'])
@limiter.limit("50 per minute")
def complete_slack_signup():
    if not db_available:
        flash('Database is currently unavailable. Please try again later.', 'error')
        return redirect(url_for('login'))

    slack_data = session.get('slack_signup_data')
    if not slack_data:
        flash('No Slack signup data found. Please try again.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        data = request.get_json()

        username = data.get('username', '').strip()
        first_name = data.get('first_name', '').strip()
        last_name = data.get('last_name', '').strip()
        birthday = data.get('birthday', '').strip()
        email = data.get('email', slack_data.get('email', '')).strip()
        is_leader = data.get('is_leader', False)
        leader_email = data.get('leader_email', '').strip() if data.get('leader_email') else None
        leader_club_name = data.get('leader_club_name', '').strip() if data.get('leader_club_name') else None

        # Validate username
        valid, username = InputValidator.validate_username(username)
        if not valid:
            return jsonify({'error': username}), 400

        # Validate email
        valid, email = InputValidator.validate_email(email)
        if not valid:
            return jsonify({'error': email}), 400

        # Validate first name
        valid, first_name = InputValidator.validate_name(first_name, "First name")
        if not valid:
            return jsonify({'error': first_name}), 400

        # Validate last name if provided
        if last_name:
            valid, last_name = InputValidator.validate_name(last_name, "Last name")
            if not valid:
                return jsonify({'error': last_name}), 400

        # Validate birthday if provided
        if birthday:
            valid, birthday = InputValidator.validate_date(birthday, "Birthday")
            if not valid:
                return jsonify({'error': birthday}), 400

            # Validate age (must be between 7 and 18)
            try:
                birth_date = datetime.strptime(birthday, '%Y-%m-%d').date()
                today = datetime.now().date()
                age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))

                if age < 7 or age > 18:
                    return jsonify({'error': 'You must be between 7 and 18 years old to create an account'}), 400
            except ValueError:
                return jsonify({'error': 'Invalid birthday format'}), 400

        # Check if username or email is already taken (case-insensitive)
        if User.query.filter(db.func.lower(User.username) == username.lower()).first():
            return jsonify({'error': 'Username already taken'}), 400

        if User.query.filter(db.func.lower(User.email) == email.lower()).first():
            return jsonify({'error': 'Email already registered'}), 400

        # Verify leader if they want to create a club
        if is_leader:
            # Validate leader email
            valid, leader_email = InputValidator.validate_email(leader_email)
            if not valid:
                return jsonify({'error': f'Leader {leader_email}'}), 400

            # Validate club name
            valid, leader_club_name = InputValidator.validate_club_name(leader_club_name)
            if not valid:
                return jsonify({'error': leader_club_name}), 400

            verification_code = data.get('verification_code', '').strip()
            valid, verification_code = InputValidator.validate_verification_code(verification_code)
            if not valid:
                return jsonify({'error': verification_code}), 400

            verification_result = leader_verification_service.verify_code(leader_email, verification_code)
            if not verification_result['verified']:
                return jsonify({'error': f'Leader verification failed: {verification_result["error"]}'}), 400

        try:
            # Create new user
            user = User(
                username=username,
                email=email,
                first_name=first_name,
                last_name=last_name,
                slack_user_id=slack_data['slack_user_id'],
                birthday=datetime.strptime(birthday, '%Y-%m-%d').date() if birthday else None
            )
            # Set a random password for Slack users (they won't use it)
            user.set_password(secrets.token_urlsafe(32))

            db.session.add(user)
            db.session.flush()

            # Create club if user wants to be a leader
            if is_leader:
                verified_club_name = verification_result['club_name']
                club = Club(
                    name=verified_club_name,
                    description="A verified Hack Club - update your club details in the dashboard",
                    leader_id=user.id
                )
                club.generate_join_code()
                db.session.add(club)

            db.session.commit()

            # Clear Slack signup data and log user in
            session.pop('slack_signup_data', None)
            login_user(user)
            session.permanent = True
            user.last_login = datetime.utcnow()
            db.session.commit()

            return jsonify({'success': True, 'message': 'Account created successfully!'})

        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Database error: {str(e)}'}), 500

    # GET request - show completion form
    return render_template('slack_signup_complete.html', slack_data=slack_data)

# Routes
@app.route('/')
def index():
    if db_available and current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("100 per minute")
def login():
    if not db_available:
        flash('Database is currently unavailable. Please try again later.', 'error')
        return render_template('login.html')

    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email_or_username = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        # Basic validation
        if not email_or_username:
            flash('Email or username is required', 'error')
            return render_template('login.html')

        if not password:
            flash('Password is required', 'error')
            return render_template('login.html')

        # Sanitize email/username input
        email_or_username = InputValidator.sanitize_text(email_or_username)

        try:
            # Try to find user by email or username (case-insensitive)
            user = User.query.filter(
                db.or_(
                    db.func.lower(User.email) == email_or_username.lower(),
                    db.func.lower(User.username) == email_or_username.lower()
                )
            ).first()

            if user and user.check_password(password):
                login_user(user)
                session.permanent = True
                user.last_login = datetime.utcnow()
                db.session.commit()
                flash(f'Welcome back, {user.username}!', 'success')
                return redirect(url_for('dashboard'))

            flash('Invalid email/username or password', 'error')
        except Exception as e:
            flash('Database error. Please try again later.', 'error')

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
@limiter.limit("50 per minute")
def signup():
    if not db_available:
        flash('Database is currently unavailable. Please try again later.', 'error')
        return render_template('signup.html')

    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # Get and validate input data
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        birthday = request.form.get('birthday', '').strip()
        is_leader = request.form.get('is_leader') == 'on'
        leader_email = request.form.get('leader_email', '').strip()
        leader_club_name = request.form.get('leader_club_name', '').strip()

        # Validate username
        valid, username = InputValidator.validate_username(username)
        if not valid:
            flash(username, 'error')
            return render_template('signup.html')

        # Validate email
        valid, email = InputValidator.validate_email(email)
        if not valid:
            flash(email, 'error')
            return render_template('signup.html')

        # Validate password
        valid, password_msg = InputValidator.validate_password(password)
        if not valid:
            flash(password_msg, 'error')
            return render_template('signup.html')

        # Validate names
        valid, first_name = InputValidator.validate_name(first_name, "First name")
        if not valid:
            flash(first_name, 'error')
            return render_template('signup.html')

        if last_name:
            valid, last_name = InputValidator.validate_name(last_name, "Last name")
            if not valid:
                flash(last_name, 'error')
                return render_template('signup.html')

        # Validate birthday
        if birthday:
            valid, birthday = InputValidator.validate_date(birthday, "Birthday")
            if not valid:
                flash(birthday, 'error')
                return render_template('signup.html')

            # Validate age (must be between 7 and 18)
            try:
                birth_date = datetime.strptime(birthday, '%Y-%m-%d').date()
                today = datetime.now().date()
                age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))

                if age < 7 or age > 18:
                    flash('You must be between 7 and 18 years old to create an account', 'error')
                    return render_template('signup.html')
            except ValueError:
                flash('Invalid birthday format', 'error')
                return render_template('signup.html')

        try:
            if User.query.filter(db.func.lower(User.email) == email.lower()).first():
                flash('Email already registered', 'error')
                return render_template('signup.html')

            if User.query.filter(db.func.lower(User.username) == username.lower()).first():
                flash('Username already taken', 'error')
                return render_template('signup.html')

            # Verify leader if they want to create a club
            if is_leader:
                # Validate leader email
                valid, leader_email = InputValidator.validate_email(leader_email)
                if not valid:
                    flash(f'Leader {leader_email}', 'error')
                    return render_template('signup.html')

                # Validate club name
                valid, leader_club_name = InputValidator.validate_club_name(leader_club_name)
                if not valid:
                    flash(leader_club_name, 'error')
                    return render_template('signup.html')

                verification_code = request.form.get('verification_code', '').strip()
                valid, verification_code = InputValidator.validate_verification_code(verification_code)
                if not valid:
                    flash(verification_code, 'error')
                    return render_template('signup.html')

                verification_result = leader_verification_service.verify_code(leader_email, verification_code)
                if not verification_result['verified']:
                    flash(f'Leader verification failed: {verification_result["error"]}', 'error')
                    return render_template('signup.html')

            user = User(
                username=username, 
                email=email, 
                first_name=first_name, 
                last_name=last_name if last_name else None, 
                birthday=datetime.strptime(birthday, '%Y-%m-%d').date() if birthday else None
            )
            user.set_password(password)
            db.session.add(user)
            db.session.flush()

            if is_leader:
                # Use verified club name from Airtable
                verified_club_name = verification_result['club_name']
                club = Club(
                    name=InputValidator.sanitize_text(verified_club_name),
                    description="A verified Hack Club - update your club details in the dashboard",
                    leader_id=user.id
                )
                club.generate_join_code()
                db.session.add(club)

            db.session.commit()
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash('Database error. Please try again later.', 'error')

    return render_template('signup.html')

def require_database(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not db_available:
            flash('Database is currently unavailable.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/logout')
@login_required
@require_database
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
@require_database
def dashboard():
    # Get user's club memberships
    memberships = ClubMembership.query.filter_by(user_id=current_user.id).all()
    led_clubs = Club.query.filter_by(leader_id=current_user.id).all()

    # If user only has one club (either as leader or member), redirect to it
    all_clubs = led_clubs + [m.club for m in memberships]
    if len(all_clubs) == 1:
        return redirect(url_for('club_dashboard', club_id=all_clubs[0].id))

    return render_template('dashboard.html', memberships=memberships, led_clubs=led_clubs)

@app.route('/club-dashboard')
@app.route('/club-dashboard/<int:club_id>')
@login_required
@require_database
def club_dashboard(club_id=None):
    if club_id:
        club = Club.query.get_or_404(club_id)
        # Check if user is leader or member
        is_leader = club.leader_id == current_user.id
        is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

        if not is_leader and not is_member:
            flash('You are not a member of this club', 'error')
            return redirect(url_for('dashboard'))
    else:
        # Try to find user's club
        club = Club.query.filter_by(leader_id=current_user.id).first()
        if not club:
            membership = ClubMembership.query.filter_by(user_id=current_user.id).first()
            if membership:
                club = membership.club

        if not club:
            flash('You are not a member of any club', 'error')
            return redirect(url_for('dashboard'))

    return render_template('club_dashboard.html', club=club)

@app.route('/join-club')
def join_club_redirect():
    join_code = request.args.get('code', '').strip()

    # Validate join code
    valid, join_code = InputValidator.validate_join_code(join_code)
    if not valid:
        flash('Invalid join code format', 'error')
        return redirect(url_for('dashboard'))

    if current_user.is_authenticated:
        club = Club.query.filter_by(join_code=join_code).first()
        if not club:
            flash('Invalid join code', 'error')
            return redirect(url_for('dashboard'))

        existing_membership = ClubMembership.query.filter_by(
            user_id=current_user.id, club_id=club.id).first()

        if existing_membership:
            flash(f"You are already a member of {club.name}", 'info')
            return redirect(url_for('club_dashboard', club_id=club.id))

        new_membership = ClubMembership(
            user_id=current_user.id,
            club_id=club.id,
            role='member'
        )
        db.session.add(new_membership)
        db.session.commit()

        flash(f"You have successfully joined {club.name}!", 'success')
        return redirect(url_for('club_dashboard', club_id=club.id))
    else:
        session['pending_join_code'] = join_code
        flash('Please log in or sign up to join the club', 'info')
        return redirect(url_for('login'))

# API Routes
@app.route('/api/clubs/<int:club_id>/join-code', methods=['POST'])
@login_required
@limiter.limit("200 per hour")
def generate_club_join_code(club_id):
    club = Club.query.get_or_404(club_id)

    if club.leader_id != current_user.id:
        membership = ClubMembership.query.filter_by(
            club_id=club_id, user_id=current_user.id, role='co-leader').first()
        if not membership:
            return jsonify({'error': 'Unauthorized'}), 403

    club.generate_join_code()
    db.session.commit()

    return jsonify({'join_code': club.join_code})

@app.route('/api/clubs/<int:club_id>/posts', methods=['GET', 'POST'])
@login_required
@limiter.limit("2000 per hour")
def club_posts(club_id):
    club = Club.query.get_or_404(club_id)

    # Check if user is member
    is_leader = club.leader_id == current_user.id
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

    if not is_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403

    if request.method == 'POST':
        data = request.get_json()
        content = data.get('content', '').strip()

        # Validate content
        valid, content = InputValidator.validate_text_content(content, min_length=1, max_length=2000, field_name="Post content")
        if not valid:
            return jsonify({'error': content}), 400

        post = ClubPost(
            club_id=club_id,
            user_id=current_user.id,
            content=content
        )
        db.session.add(post)
        db.session.commit()

        return jsonify({'message': 'Post created successfully'})

    # GET request
    posts = ClubPost.query.filter_by(club_id=club_id).order_by(ClubPost.created_at.desc()).all()
    posts_data = [{
        'id': post.id,
        'content': post.content,
        'created_at': post.created_at.isoformat(),
        'user': {
            'id': post.user.id,
            'username': post.user.username
        }
    } for post in posts]

    return jsonify({'posts': posts_data})

@app.route('/api/clubs/<int:club_id>/assignments', methods=['GET', 'POST'])
@login_required
@limiter.limit("500 per hour")
def club_assignments(club_id):
    club = Club.query.get_or_404(club_id)

    # Check if user is member
    is_leader = club.leader_id == current_user.id
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

    if not is_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403

    if request.method == 'POST':
        # Only leaders and co-leaders can create assignments
        membership = ClubMembership.query.filter_by(
            club_id=club_id, user_id=current_user.id, role='co-leader').first()
        if not is_leader and not membership:
            return jsonify({'error': 'Only leaders can create assignments'}), 403

        data = request.get_json()

        # Validate title
        title = data.get('title', '').strip()
        valid, title = InputValidator.validate_text_content(title, min_length=1, max_length=200, field_name="Assignment title")
        if not valid:
            return jsonify({'error': title}), 400

        # Validate description
        description = data.get('description', '').strip()
        valid, description = InputValidator.validate_text_content(description, min_length=1, max_length=5000, field_name="Assignment description")
        if not valid:
            return jsonify({'error': description}), 400

        # Validate due date if provided
        due_date = None
        if data.get('due_date'):
            try:
                due_date = datetime.fromisoformat(data.get('due_date'))
            except ValueError:
                return jsonify({'error': 'Invalid due date format'}), 400

        assignment = ClubAssignment(
            club_id=club_id,
            title=title,
            description=description,
            due_date=due_date,
            for_all_members=data.get('for_all_members', True)
        )
        db.session.add(assignment)
        db.session.commit()

        return jsonify({'message': 'Assignment created successfully'})

    # GET request
    assignments = ClubAssignment.query.filter_by(club_id=club_id).order_by(ClubAssignment.created_at.desc()).all()
    assignments_data = [{
        'id': assignment.id,
        'title': assignment.title,
        'description': assignment.description,
        'due_date': assignment.due_date.isoformat() if assignment.due_date else None,
        'for_all_members': assignment.for_all_members,
        'status': assignment.status,
        'created_at': assignment.created_at.isoformat()
    } for assignment in assignments]

    return jsonify({'assignments': assignments_data})

@app.route('/api/clubs/<int:club_id>/meetings', methods=['GET', 'POST'])
@login_required
@limiter.limit("500 per hour")
def club_meetings(club_id):
    club = Club.query.get_or_404(club_id)

    # Check if user is member
    is_leader = club.leader_id == current_user.id
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

    if not is_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403

    if request.method == 'POST':
        # Only leaders and co-leaders can create meetings
        membership = ClubMembership.query.filter_by(
            club_id=club_id, user_id=current_user.id, role='co-leader').first()
        if not is_leader and not membership:
            return jsonify({'error': 'Only leaders can create meetings'}), 403

        data = request.get_json()

        # Validate title
        title = data.get('title', '').strip()
        valid, title = InputValidator.validate_text_content(title, min_length=1, max_length=200, field_name="Meeting title")
        if not valid:
            return jsonify({'error': title}), 400

        # Validate description
        description = data.get('description', '').strip()
        if description:
            valid, description = InputValidator.validate_text_content(description, min_length=0, max_length=2000, field_name="Meeting description")
            if not valid:
                return jsonify({'error': description}), 400

        # Validate meeting date
        meeting_date_str = data.get('meeting_date', '').strip()
        valid, meeting_date_str = InputValidator.validate_date(meeting_date_str, "Meeting date")
        if not valid:
            return jsonify({'error': meeting_date_str}), 400

        # Validate start time
        start_time = data.get('start_time', '').strip()
        valid, start_time = InputValidator.validate_time(start_time, "Start time")
        if not valid:
            return jsonify({'error': start_time}), 400

        # Validate end time if provided
        end_time = data.get('end_time', '').strip()
        if end_time:
            valid, end_time = InputValidator.validate_time(end_time, "End time")
            if not valid:
                return jsonify({'error': end_time}), 400

        # Validate location if provided```python
        location = data.get('location', '').strip()
        if location:
            valid, location = InputValidator.validate_text_content(location, min_length=0, max_length=255, field_name="Location")
            if not valid:
                return jsonify({'error': location}), 400

        # Validate meeting link if provided
        meeting_link = data.get('meeting_link', '').strip()
        if meeting_link:
            valid, meeting_link = InputValidator.validate_url(meeting_link, "Meeting link")
            if not valid:
                return jsonify({'error': meeting_link}), 400

        try:
            meeting_date = datetime.strptime(meeting_date_str, '%Y-%m-%d').date()
        except ValueError:
            return jsonify({'error': 'Invalid meeting date'}), 400

        meeting = ClubMeeting(
            club_id=club_id,
            title=title,
            description=description,
            meeting_date=meeting_date,
            start_time=start_time,
            end_time=end_time if end_time else None,
            location=location if location else None,
            meeting_link=meeting_link if meeting_link else None
        )
        db.session.add(meeting)
        db.session.commit()

        return jsonify({'message': 'Meeting scheduled successfully'})

    # GET request
    meetings = ClubMeeting.query.filter_by(club_id=club_id).order_by(ClubMeeting.meeting_date.desc()).all()
    meetings_data = [{
        'id': meeting.id,
        'title': meeting.title,
        'description': meeting.description,
        'meeting_date': meeting.meeting_date.isoformat(),
        'start_time': meeting.start_time,
        'end_time': meeting.end_time,
        'location': meeting.location,
        'meeting_link': meeting.meeting_link,
        'created_at': meeting.created_at.isoformat()
    } for meeting in meetings]

    return jsonify({'meetings': meetings_data})

@app.route('/api/clubs/<int:club_id>/meetings/<int:meeting_id>', methods=['PUT', 'DELETE'])
@login_required
@limiter.limit("200 per hour")
def manage_meeting(club_id, meeting_id):
    club = Club.query.get_or_404(club_id)
    meeting = ClubMeeting.query.get_or_404(meeting_id)

    # Only leaders and co-leaders can manage meetings
    is_leader = club.leader_id == current_user.id
    membership = ClubMembership.query.filter_by(
        club_id=club_id, user_id=current_user.id, role='co-leader').first()

    if not is_leader and not membership:
        return jsonify({'error': 'Only leaders can manage meetings'}), 403

    if meeting.club_id != club_id:
        return jsonify({'error': 'Meeting not found'}), 404

    if request.method == 'DELETE':
        db.session.delete(meeting)
        db.session.commit()
        return jsonify({'message': 'Meeting deleted successfully'})

    elif request.method == 'PUT':
        data = request.get_json()
        meeting.title = data.get('title', meeting.title)
        meeting.description = data.get('description', meeting.description)
        if data.get('meeting_date'):
            meeting.meeting_date = datetime.strptime(data.get('meeting_date'), '%Y-%m-%d').date()
        meeting.start_time = data.get('start_time', meeting.start_time)
        meeting.end_time = data.get('end_time', meeting.end_time)
        meeting.location = data.get('location', meeting.location)
        meeting.meeting_link = data.get('meeting_link', meeting.meeting_link)
        db.session.commit()
        return jsonify({'message': 'Meeting updated successfully'})

@app.route('/api/clubs/<int:club_id>/resources', methods=['GET', 'POST'])
@login_required
@limiter.limit("500 per hour")
def club_resources(club_id):
    club = Club.query.get_or_404(club_id)

    # Check if user is member
    is_leader = club.leader_id == current_user.id
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

    if not is_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403

    if request.method == 'POST':
        # Only leaders and co-leaders can add resources
        membership = ClubMembership.query.filter_by(
            club_id=club_id, user_id=current_user.id, role='co-leader').first()
        if not is_leader and not membership:
            return jsonify({'error': 'Only leaders can add resources'}), 403

        data = request.get_json()

        resource = ClubResource(
            club_id=club_id,
            title=data.get('title'),
            url=data.get('url'),
            description=data.get('description'),
            icon=data.get('icon', 'book')
        )
        db.session.add(resource)
        db.session.commit()

        return jsonify({'message': 'Resource added successfully'})

    # GET request
    resources = ClubResource.query.filter_by(club_id=club_id).order_by(ClubResource.created_at.desc()).all()
    resources_data = [{
        'id': resource.id,
        'title': resource.title,
        'url': resource.url,
        'description': resource.description,
        'icon': resource.icon,
        'created_at': resource.created_at.isoformat()
    } for resource in resources]

    return jsonify({'resources': resources_data})

@app.route('/api/clubs/<int:club_id>/resources/<int:resource_id>', methods=['PUT', 'DELETE'])
@login_required
@limiter.limit("200 per hour")
def manage_resource(club_id, resource_id):
    club = Club.query.get_or_404(club_id)
    resource = ClubResource.query.get_or_404(resource_id)

    # Only leaders and co-leaders can manage resources
    is_leader = club.leader_id == current_user.id
    membership = ClubMembership.query.filter_by(
        club_id=club_id, user_id=current_user.id, role='co-leader').first()

    if not is_leader and not membership:
        return jsonify({'error': 'Only leaders can manage resources'}), 403

    if resource.club_id != club_id:
        return jsonify({'error': 'Resource not found'}), 404

    if request.method == 'DELETE':
        db.session.delete(resource)
        db.session.commit()
        return jsonify({'message': 'Resource deleted successfully'})

    elif request.method == 'PUT':
        data = request.get_json()
        resource.title = data.get('title', resource.title)
        resource.url = data.get('url', resource.url)
        resource.description = data.get('description', resource.description)
        resource.icon = data.get('icon', resource.icon)
        db.session.commit()
        return jsonify({'message': 'Resource updated successfully'})

@app.route('/api/clubs/<int:club_id>/projects', methods=['GET'])
@login_required
def club_projects(club_id):
    club = Club.query.get_or_404(club_id)

    # Check if user is member
    is_leader = club.leader_id == current_user.id
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

    if not is_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403

    # Get all members
    member_ids = [m.user_id for m in club.members] + [club.leader_id]

    # Mock projects data for now
    projects_data = [{
        'id': 1,
        'name': 'Sample Project',
        'description': 'A sample project for the club',
        'owner': {'username': current_user.username},
        'featured': False,
        'updated_at': datetime.utcnow().isoformat()
    }]

    return jsonify({'projects': projects_data})

@app.route('/api/clubs/<int:club_id>/pizza-grants', methods=['GET', 'POST'])
@login_required
@limiter.limit("100 per hour")
def pizza_grants(club_id):
    club = Club.query.get_or_404(club_id)

    # Check if user is member
    is_leader = club.leader_id == current_user.id
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

    if not is_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403

    if request.method == 'POST':
        try:
            data = request.get_json()

            # Get the member user if leader is submitting for someone else
            member_id = data.get('member_id')
            if member_id and str(member_id) != str(current_user.id):
                # Verify leader can submit for this member
                if not is_leader:
                    return jsonify({'error': 'Only leaders can submit for other members'}), 403
                member_user = User.query.get(member_id)
                if not member_user:
                    return jsonify({'error': 'Member not found'}), 404
                # Verify member is part of the club
                member_in_club = ClubMembership.query.filter_by(club_id=club_id, user_id=member_id).first()
                if not member_in_club and member_id != club.leader_id:
                    return jsonify({'error': 'Member is not part of this club'}), 403
            else:
                member_user = current_user

            # Validate required fields
            project_name = data.get('project_name', '').strip()
            valid, project_name = InputValidator.validate_text_content(project_name, min_length=1, max_length=200, field_name="Project name")
            if not valid:
                return jsonify({'error': project_name}), 400

            first_name = data.get('first_name', '').strip()
            valid, first_name = InputValidator.validate_name(first_name, "First name")
            if not valid:
                return jsonify({'error': first_name}), 400

            last_name = data.get('last_name', '').strip()
            valid, last_name = InputValidator.validate_name(last_name, "Last name")
            if not valid:
                return jsonify({'error': last_name}), 400

            email = data.get('email', '').strip()
            valid, email = InputValidator.validate_email(email)
            if not valid:
                return jsonify({'error': email}), 400

            project_description = data.get('project_description', '').strip()
            valid, project_description = InputValidator.validate_text_content(project_description, min_length=10, max_length=2000, field_name="Project description")
            if not valid:
                return jsonify({'error': project_description}), 400

            github_url = data.get('github_url', '').strip()
            valid, github_url = InputValidator.validate_url(github_url, "GitHub URL")
            if not valid:
                return jsonify({'error': github_url}), 400

            live_url = data.get('live_url', '').strip()
            valid, live_url = InputValidator.validate_url(live_url, "Live URL")
            if not valid:
                return jsonify({'error': live_url}), 400

            # Validate optional fields
            birthday = data.get('birthday', '').strip()
            if birthday:
                valid, birthday = InputValidator.validate_date(birthday, "Birthday")
                if not valid:
                    return jsonify({'error': birthday}), 400

            learning = data.get('learning', '').strip()
            if learning:
                valid, learning = InputValidator.validate_text_content(learning, min_length=1, max_length=1000, field_name="Learning")
                if not valid:
                    return jsonify({'error': learning}), 400

            doing_well = data.get('doing_well', '').strip()
            if doing_well:
                valid, doing_well = InputValidator.validate_text_content(doing_well, min_length=1, max_length=1000, field_name="What we're doing well")
                if not valid:
                    return jsonify({'error': doing_well}), 400

            improve = data.get('improve', '').strip()
            if improve:
                valid, improve = InputValidator.validate_text_content(improve, min_length=1, max_length=1000, field_name="How to improve")
                if not valid:
                    return jsonify({'error': improve}), 400

            # Validate project hours
            try:
                project_hours = float(data.get('project_hours', 0))
                if project_hours < 0 or project_hours > 1000:
                    return jsonify({'error': 'Project hours must be between 0 and 1000'}), 400
            except (ValueError, TypeError):
                return jsonify({'error': 'Invalid project hours'}), 400

            # Submit to Airtable with all required fields
            submission_data = {
                'project_name': project_name,
                'first_name': first_name,
                'last_name': last_name,
                'username': member_user.username,
                'email': email,
                'birthday': birthday,
                'project_description': project_description,
                'github_url': github_url,
                'live_url': live_url,
                'learning': learning,
                'doing_well': doing_well,
                'improve': improve,
                'address_1': InputValidator.sanitize_text(data.get('address_1', '')),
                'address_2': InputValidator.sanitize_text(data.get('address_2', '')),
                'city': InputValidator.sanitize_text(data.get('city', '')),
                'state': InputValidator.sanitize_text(data.get('state', '')),
                'zip': InputValidator.sanitize_text(data.get('zip', '')),
                'country': InputValidator.sanitize_text(data.get('country', '')),
                'club_name': club.name,
                'leader_email': club.leader.email,
                'project_hours': project_hours,
                'screenshot_url': InputValidator.sanitize_text(data.get('screenshot_url', ''))
            }

            result = airtable_service.log_pizza_grant(submission_data)

            if result:
                return jsonify({'message': 'Pizza grant submitted successfully!'})
            else:
                print("Failed to submit to Airtable")
                return jsonify({'error': 'Failed to submit pizza grant to Airtable'}), 500

        except Exception as e:
            print(f"Error in pizza grant submission: {str(e)}")
            import traceback
            traceback.print_exc()
            return jsonify({'error': f'Server error: {str(e)}'}), 500

    return jsonify({'grants': []})

@app.route('/api/hackatime/projects/<int:user_id>', methods=['GET'])
@login_required
def get_hackatime_projects(user_id):
    # Get the user whose projects we want to see
    target_user = User.query.get_or_404(user_id)

    # Check if the target user has a Hackatime API key
    if not target_user.hackatime_api_key:
        return jsonify({'error': 'User has not set up Hackatime integration'}), 400

    # Get projects using the Hackatime service
    projects = hackatime_service.get_user_projects(target_user.hackatime_api_key)

    if projects is None:
        return jsonify({'error': 'Failed to fetch Hackatime data'}), 500

    return jsonify({
        'projects': projects,
        'username': target_user.username
    })

@app.route('/account')
@login_required
def account():
    return render_template('account.html')

@app.route('/api/docs')
def api_docs():
    return render_template('api_docs.html')

@app.route('/api/user/<int:user_id>', methods=['GET'])
@login_required
def get_user_data(user_id):
    # Only allow getting data for current user or if current user is admin/leader
    if user_id != current_user.id and not current_user.is_admin:
        # Check if current user is a leader and the target user is in their club
        led_clubs = Club.query.filter_by(leader_id=current_user.id).all()
        is_member_of_led_club = False
        for club in led_clubs:
            if ClubMembership.query.filter_by(club_id=club.id, user_id=user_id).first():
                is_member_of_led_club = True
                break

        if not is_member_of_led_club:
            return jsonify({'error': 'Unauthorized'}), 403

    user = User.query.get_or_404(user_id)

    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'birthday': user.birthday.strftime('%Y-%m-%d') if user.birthday else None
    })

@app.route('/api/user/update', methods=['PUT'])
@login_required
@limiter.limit("100 per hour")
def update_user():
    data = request.get_json()

    username = data.get('username', '').strip() if data.get('username') else None
    email = data.get('email', '').strip() if data.get('email') else None
    first_name = data.get('first_name', '').strip() if data.get('first_name') else None
    last_name = data.get('last_name', '').strip() if data.get('last_name') else None
    birthday = data.get('birthday', '').strip() if data.get('birthday') else None
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    hackatime_api_key = data.get('hackatime_api_key', '').strip() if data.get('hackatime_api_key') else None

    # Validate username if provided
    if username:
        valid, username = InputValidator.validate_username(username)
        if not valid:
            return jsonify({'error': username}), 400

    # Validate email if provided
    if email:
        valid, email = InputValidator.validate_email(email)
        if not valid:
            return jsonify({'error': email}), 400

    # Validate first name if provided
    if first_name:
        valid, first_name = InputValidator.validate_name(first_name, "First name")
        if not valid:
            return jsonify({'error': first_name}), 400

    # Validate last name if provided
    if last_name:
        valid, last_name = InputValidator.validate_name(last_name, "Last name")
        if not valid:
            return jsonify({'error': last_name}), 400

    # Validate birthday if provided
    if birthday:
        valid, birthday = InputValidator.validate_date(birthday, "Birthday")
        if not valid:
            return jsonify({'error': birthday}), 400

    # Check if username is taken by another user (case-insensitive)
    if username and username.lower() != current_user.username.lower():
        existing_user = User.query.filter(db.func.lower(User.username) == username.lower()).first()
        if existing_user:
            return jsonify({'error': 'Username already taken'}), 400

    # Check if email is taken by another user (case-insensitive)
    if email and email.lower() != current_user.email.lower():
        existing_user = User.query.filter(db.func.lower(User.email) == email.lower()).first()
        if existing_user:
            return jsonify({'error': 'Email already registered'}), 400

    # Update user fields
    if username:
        current_user.username = username
    if email:
        current_user.email = email
    if first_name is not None:
        current_user.first_name = first_name if first_name else None
    if last_name is not None:
        current_user.last_name = last_name if last_name else None
    if birthday is not None:
        current_user.birthday = datetime.strptime(birthday, '%Y-%m-%d').date() if birthday else None
    if hackatime_api_key is not None:
        current_user.hackatime_api_key = InputValidator.sanitize_text(hackatime_api_key) if hackatime_api_key else None

    # Update password if provided
    if new_password:
        if not current_password:
            return jsonify({'error': 'Current password required to change password'}), 400

        valid, password_msg = InputValidator.validate_password(new_password)
        if not valid:
            return jsonify({'error': password_msg}), 400

        if not current_user.check_password(current_password):
            return jsonify({'error': 'Current password is incorrect'}), 400
        current_user.set_password(new_password)

    db.session.commit()
    return jsonify({'message': 'Account updated successfully'})

def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Admin access required', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def require_api_key(scopes=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not db_available:
                return jsonify({'error': 'Database unavailable'}), 503

            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return jsonify({'error': 'API key required'}), 401

            api_key = auth_header.replace('Bearer ', '')
            key_obj = APIKey.query.filter_by(key=api_key, is_active=True).first()
            
            if not key_obj:
                return jsonify({'error': 'Invalid API key'}), 401

            # Check scopes if required
            if scopes:
                key_scopes = json.loads(key_obj.scopes or '[]')
                if not all(scope in key_scopes for scope in scopes):
                    return jsonify({'error': 'Insufficient permissions'}), 403

            # Update last used timestamp
            key_obj.last_used_at = datetime.utcnow()
            db.session.commit()

            # Add key info to request context
            request.api_key = key_obj
            request.api_user = key_obj.user

            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_oauth_token(scopes=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not db_available:
                return jsonify({'error': 'Database unavailable'}), 503

            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return jsonify({'error': 'OAuth token required'}), 401

            token = auth_header.replace('Bearer ', '')
            token_obj = OAuthToken.query.filter_by(
                access_token=token, 
                is_active=True
            ).filter(OAuthToken.expires_at > datetime.utcnow()).first()
            
            if not token_obj:
                return jsonify({'error': 'Invalid or expired token'}), 401

            # Check scopes if required
            if scopes:
                token_scopes = json.loads(token_obj.scopes or '[]')
                if not all(scope in token_scopes for scope in scopes):
                    return jsonify({'error': 'Insufficient permissions'}), 403

            # Add token info to request context
            request.oauth_token = token_obj
            request.oauth_user = token_obj.user

            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_club_from_airtable(club_identifier):
    """Fallback to get club info from Airtable if not in database"""
    try:
        # Try to search by club name or identifier
        params = {
            'filterByFormula': f'SEARCH(LOWER("{club_identifier}"), LOWER({{Venue}}))'
        }
        
        response = requests.get(
            leader_verification_service.base_url, 
            headers=leader_verification_service.headers, 
            params=params
        )
        
        if response.status_code == 200:
            data = response.json()
            records = data.get('records', [])
            
            if records:
                record = records[0]
                fields = record.get('fields', {})
                
                return {
                    'id': f"airtable_{record['id']}",
                    'name': fields.get('Venue', ''),
                    'description': 'Hack Club from Airtable',
                    'location': fields.get('Venue', ''),
                    'leader': fields.get('Current Leader(s)', ''),
                    'leader_email': fields.get("Current Leaders' Emails", ''),
                    'member_count': 1,
                    'balance': 0.0,
                    'created_at': None,
                    'source': 'airtable'
                }
    except Exception as e:
        print(f"Error fetching from Airtable: {e}")
    
    return None

@app.route('/admin')
@login_required
@require_database
@require_admin
def admin_dashboard():
    # Get statistics
    total_users = User.query.count()
    total_clubs = Club.query.count()
    total_posts = ClubPost.query.count()
    total_assignments = ClubAssignment.query.count()

    # Get recent activity
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
    recent_clubs = Club.query.order_by(Club.created_at.desc()).limit(5).all()
    recent_posts = ClubPost.query.order_by(ClubPost.created_at.desc()).limit(10).all()

    return render_template('admin_dashboard.html',
                         total_users=total_users,
                         total_clubs=total_clubs,
                         total_posts=total_posts,
                         total_assignments=total_assignments,
                         recent_users=recent_users,
                         recent_clubs=recent_clubs,
                         recent_posts=recent_posts)

@app.route('/api/admin/users', methods=['GET'])
@login_required
@require_admin
@limiter.limit("500 per hour")
def admin_get_users():
    users = User.query.all()
    users_data = [{
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'is_admin': user.is_admin,
        'is_suspended': user.is_suspended,
        'created_at': user.created_at.isoformat() if user.created_at else None,
        'last_login': user.last_login.isoformat() if user.last_login else None,
        'clubs_led': len(user.led_clubs),
        'clubs_joined': len(user.club_memberships)
    } for user in users]

    return jsonify({'users': users_data})

@app.route('/api/admin/clubs', methods=['GET'])
@login_required
@require_admin
def admin_get_clubs():
    clubs = Club.query.all()
    clubs_data = [{
        'id': club.id,
        'name': club.name,
        'description': club.description,
        'location': club.location,
        'leader': club.leader.username,
        'leader_email': club.leader.email,
        'member_count': len(club.members) + 1,
        'balance': float(club.balance),
        'join_code': club.join_code,
        'created_at': club.created_at.isoformat() if club.created_at else None
    } for club in clubs]

    return jsonify({'clubs': clubs_data})

@app.route('/api/admin/users/<int:user_id>', methods=['PUT', 'DELETE'])
@login_required
@require_admin
def admin_manage_user(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'DELETE':
        # Don't allow deleting yourself
        if user.id == current_user.id:
            return jsonify({'error': 'Cannot delete your own account'}), 400

        # Delete user's clubs and memberships
        for club in user.led_clubs:
            db.session.delete(club)

        ClubMembership.query.filter_by(user_id=user.id).delete()
        ClubPost.query.filter_by(user_id=user.id).delete()

        db.session.delete(user)
        db.session.commit()

        return jsonify({'message': 'User deleted successfully'})

    elif request.method == 'PUT':
        data = request.get_json()

        # Don't allow removing admin from yourself
        if user.id == current_user.id and not data.get('is_admin', True):
            return jsonify({'error': 'Cannot remove admin from your own account'}), 400

        user.is_admin = data.get('is_admin', user.is_admin)
        user.is_suspended = data.get('is_suspended', user.is_suspended)

        if data.get('username'):
            user.username = data.get('username')
        if data.get('email'):
            user.email = data.get('email')

        db.session.commit()
        return jsonify({'message': 'User updated successfully'})

@app.route('/api/admin/clubs/<int:club_id>', methods=['PUT', 'DELETE'])
@login_required
@require_admin
def admin_manage_club(club_id):
    club = Club.query.get_or_404(club_id)

    if request.method == 'DELETE':
        db.session.delete(club)
        db.session.commit()
        return jsonify({'message': 'Club deleted successfully'})

    elif request.method == 'PUT':
        data = request.get_json()

        club.name = data.get('name', club.name)
        club.description = data.get('description', club.description)
        club.location = data.get('location', club.location)
        club.balance = data.get('balance', club.balance)

        db.session.commit()
        return jsonify({'message': 'Club updated successfully'})

@app.route('/api/admin/stats', methods=['GET'])
@login_required
@require_admin
def admin_get_stats():
    # Get user registration stats (last 30 days)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    recent_users = User.query.filter(User.created_at >= thirty_days_ago).count()

    # Get club creation stats (last 30 days)
    recent_clubs = Club.query.filter(Club.created_at >= thirty_days_ago).count()

    # Get activity stats
    active_users = User.query.filter(User.last_login >= thirty_days_ago).count()

    return jsonify({
        'recent_users': recent_users,
        'recent_clubs': recent_clubs,
        'active_users': active_users,
        'total_users': User.query.count(),
        'total_clubs': Club.query.count(),
        'total_posts': ClubPost.query.count(),
        'suspended_users': User.query.filter_by(is_suspended=True).count()
    })

@app.route('/api/admin/login-as-user/<int:user_id>', methods=['POST'])
@login_required
@require_admin
def admin_login_as_user(user_id):
    user = User.query.get_or_404(user_id)

    # Don't allow logging in as suspended users
    if user.is_suspended:
        return jsonify({'error': 'Cannot login as suspended user'}), 400

    # Log out current admin user and log in as the target user
    logout_user()
    login_user(user)
    user.last_login = datetime.utcnow()
    db.session.commit()

    return jsonify({'message': f'Successfully logged in as {user.username}'})

@app.route('/api/upload-screenshot', methods=['POST'])
@login_required
@limiter.limit("50 per hour")
def upload_screenshot():
    if 'screenshot' not in request.files:
        return jsonify({'success': False, 'error': 'No screenshot file provided'}), 400

    screenshot = request.files['screenshot']

    if screenshot.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400

    try:
        import tempfile
        import uuid
        from werkzeug.utils import secure_filename

        # Create temp directory if it doesn't exist
        temp_dir = os.path.join(tempfile.gettempdir(), 'hc_cdn_temp')
        os.makedirs(temp_dir, exist_ok=True)

        # Temp files will be cleaned up immediately after upload

        # Generate unique filename
        file_extension = os.path.splitext(secure_filename(screenshot.filename))[1]
        unique_filename = f"{uuid.uuid4()}{file_extension}"
        temp_file_path = os.path.join(temp_dir, unique_filename)

        # Save file temporarily
        screenshot.save(temp_file_path)
        file_size = os.path.getsize(temp_file_path)

        # Upload to Hack Club CDN using v3 API
        api_token = "beans"
        upload_url = "https://cdn.hackclub.com/api/v3/new"

        # First, we need to upload the file to a temporary public URL
        # Since we can't use the temp folder (not public), let's upload directly to CDN
        # For now, we'll use a different approach - convert to base64 and use a data URL

        # Read file content and convert to base64
        with open(temp_file_path, 'rb') as f:
            file_content = f.read()

        import base64
        file_base64 = base64.b64encode(file_content).decode('utf-8')
        data_url = f"data:{screenshot.content_type or 'image/png'};base64,{file_base64}"

        # Prepare the request for v3 API (expects array of URLs)
        payload = [data_url]

        headers = {
            'Authorization': f'Bearer {api_token}',
            'Content-Type': 'application/json'
        }

        response = requests.post(upload_url, json=payload, headers=headers)

        # Clean up temp file immediately after upload attempt
        try:
            os.remove(temp_file_path)
        except Exception as cleanup_error:
            print(f"Failed to cleanup temp file: {cleanup_error}")

        if response.status_code == 200:
            try:
                response_data = response.json()

                # v3 API returns an object with 'files' array
                if 'files' in response_data and len(response_data['files']) > 0:
                    file_info = response_data['files'][0]
                    cdn_url = file_info.get('deployedUrl')
                    if cdn_url:
                        return jsonify({'success': True, 'url': cdn_url})
                    else:
                        return jsonify({'success': False, 'error': 'No deployedUrl in CDN response'}), 500
                else:
                    return jsonify({'success': False, 'error': 'No files in CDN response'}), 500
            except Exception as json_error:
                return jsonify({'success': False, 'error': f'Invalid CDN response: {str(json_error)}'}), 500
        else:
            return jsonify({'success': False, 'error': f'CDN upload failed: {response.status_code} - {response.text}'}), 500

    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Screenshot upload error: {str(e)}")
        print(f"Full traceback: {error_details}")
        return jsonify({'success': False, 'error': f'Upload error: {str(e)}'}), 500

@app.route('/api/send-verification-email', methods=['POST'])
@login_required
@limiter.limit("5 per hour")
def send_verification_email():
    data = request.get_json()
    leader_email = data.get('leader_email')
    leader_club_name = data.get('leader_club_name')

    if not leader_email or not leader_club_name:
        return jsonify({'error': 'Leader email and club name are required'}), 400

    # Send verification email
    result = leader_verification_service.send_verification_email(
        leader_email, 
        leader_club_name, 
        current_user.username
    )

    if result['success']:
        return jsonify({
            'success': True,
            'message': result['message'],
            'club_name': result['club_name']
        })
    else:
        return jsonify({'error': result['error']}), 400

@app.route('/api/send-verification-email-signup', methods=['POST'])
@limiter.limit("5 per hour")
def send_verification_email_signup():
    data = request.get_json()
    leader_email = data.get('leader_email')
    leader_club_name = data.get('leader_club_name')

    if not leader_email or not leader_club_name:
        return jsonify({'error': 'Leader email and club name are required'}), 400

    # Send verification email - use a temporary username for signup
    result = leader_verification_service.send_verification_email(
        leader_email, 
        leader_club_name, 
        'New User (Signup)'
    )

    if result['success']:
        return jsonify({
            'success': True,
            'message': result['message'],
            'club_name': result['club_name']
        })
    else:
        return jsonify({'error': result['error']}), 400

@app.route('/api/verify-leader-code', methods=['POST'])
@login_required
@limiter.limit("10 per hour")
def verify_leader_code():
    data = request.get_json()
    leader_email = data.get('leader_email')
    verification_code = data.get('verification_code')

    if not leader_email or not verification_code:
        return jsonify({'error': 'Email and verification code are required'}), 400

    # Verify the code
    result = leader_verification_service.verify_code(leader_email, verification_code)

    if result['verified']:
        return jsonify({
            'verified': True,
            'club_name': result['club_name'],
            'email': result['email']
        })
    else:
        return jsonify({'error': result['error']}), 400

@app.route('/api/create-club', methods=['POST'])
@login_required
@limiter.limit("10 per hour")
def create_club():
    data = request.get_json()
    leader_email = data.get('leader_email')
    verification_code = data.get('verification_code')

    if not leader_email or not verification_code:
        return jsonify({'error': 'Leader email and verification code are required'}), 400

    # Check if user already leads a club
    existing_club = Club.query.filter_by(leader_id=current_user.id).first()
    if existing_club:
        return jsonify({'error': 'You already lead a club'}), 400

    # Verify the code first
    verification_result = leader_verification_service.verify_code(leader_email, verification_code)
    if not verification_result['verified']:
        return jsonify({'error': 'Invalid or expired verification code'}), 400

    try:
        # Create new club with verified name
        verified_club_name = verification_result['club_name']
        club = Club(
            name=verified_club_name,
            description="A verified Hack Club - update your club details in the dashboard",
            leader_id=current_user.id
        )
        club.generate_join_code()
        db.session.add(club)
        db.session.commit()

        return jsonify({'success': True, 'message': f'Club "{verified_club_name}" created successfully!'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to create club: {str(e)}'}), 500

@app.route('/api/admin/reset-password/<int:user_id>', methods=['POST'])
@login_required
@require_admin
def admin_reset_password(user_id):
    user = User.query.get_or_404(user_id)
    data = request.get_json()

    new_password = data.get('new_password')
    if not new_password:
        return jsonify({'error': 'New password is required'}), 400

    if len(new_password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters long'}), 400

    # Don't allow resetting your own password this way
    if user.id == current_user.id:
        return jsonify({'error': 'Cannot reset your own password via admin panel'}), 400

    user.set_password(new_password)
    db.session.commit()

    return jsonify({'message': f'Password reset successfully for {user.username}'})

@app.route('/api/admin/api-keys', methods=['GET', 'POST'])
@login_required
@require_admin
def admin_api_keys():
    if request.method == 'GET':
        keys = APIKey.query.all()
        keys_data = [{
            'id': key.id,
            'key': f"{key.key[:16]}...{key.key[-8:]}" if key.key else '',
            'name': key.name,
            'description': key.description,
            'user': key.user.username,
            'user_email': key.user.email,
            'scopes': json.loads(key.scopes or '[]'),
            'rate_limit': key.rate_limit,
            'is_active': key.is_active,
            'created_at': key.created_at.isoformat() if key.created_at else None,
            'last_used_at': key.last_used_at.isoformat() if key.last_used_at else None
        } for key in keys]
        
        return jsonify({'api_keys': keys_data})
    
    elif request.method == 'POST':
        data = request.get_json()
        
        name = data.get('name', '').strip()
        if not name:
            return jsonify({'error': 'API key name is required'}), 400
        
        description = data.get('description', '').strip()
        user_email = data.get('user_email', '').strip()
        scopes = data.get('scopes', [])
        rate_limit = int(data.get('rate_limit', 1000))
        
        # Find user by email
        user = User.query.filter_by(email=user_email).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Validate scopes
        valid_scopes = [
            'clubs:read', 'clubs:write', 'users:read', 'projects:read', 
            'assignments:read', 'meetings:read', 'analytics:read'
        ]
        
        invalid_scopes = [scope for scope in scopes if scope not in valid_scopes]
        if invalid_scopes:
            return jsonify({'error': f'Invalid scopes: {invalid_scopes}'}), 400
        
        # Create API key
        api_key = APIKey(
            name=name,
            description=description,
            user_id=user.id,
            scopes=json.dumps(scopes),
            rate_limit=rate_limit
        )
        api_key.generate_key()
        
        db.session.add(api_key)
        db.session.commit()
        
        return jsonify({
            'message': 'API key created successfully',
            'api_key': api_key.key,
            'id': api_key.id
        })

@app.route('/api/admin/api-keys/<int:key_id>', methods=['PUT', 'DELETE'])
@login_required
@require_admin
def admin_manage_api_key(key_id):
    api_key = APIKey.query.get_or_404(key_id)
    
    if request.method == 'DELETE':
        db.session.delete(api_key)
        db.session.commit()
        return jsonify({'message': 'API key deleted successfully'})
    
    elif request.method == 'PUT':
        data = request.get_json()
        
        api_key.name = data.get('name', api_key.name)
        api_key.description = data.get('description', api_key.description)
        api_key.is_active = data.get('is_active', api_key.is_active)
        api_key.rate_limit = int(data.get('rate_limit', api_key.rate_limit))
        
        if 'scopes' in data:
            api_key.scopes = json.dumps(data['scopes'])
        
        db.session.commit()
        return jsonify({'message': 'API key updated successfully'})

@app.route('/api/admin/oauth-applications', methods=['GET', 'POST'])
@login_required
@require_admin
def admin_oauth_applications():
    if request.method == 'GET':
        apps = OAuthApplication.query.all()
        apps_data = [{
            'id': app.id,
            'client_id': app.client_id,
            'name': app.name,
            'description': app.description,
            'user': app.user.username,
            'user_email': app.user.email,
            'redirect_uris': json.loads(app.redirect_uris or '[]'),
            'scopes': json.loads(app.scopes or '[]'),
            'is_active': app.is_active,
            'created_at': app.created_at.isoformat() if app.created_at else None
        } for app in apps]
        
        return jsonify({'oauth_applications': apps_data})
    
    elif request.method == 'POST':
        data = request.get_json()
        
        name = data.get('name', '').strip()
        if not name:
            return jsonify({'error': 'Application name is required'}), 400
        
        description = data.get('description', '').strip()
        user_email = data.get('user_email', '').strip()
        redirect_uris = data.get('redirect_uris', [])
        scopes = data.get('scopes', [])
        
        # Find user by email
        user = User.query.filter_by(email=user_email).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Validate redirect URIs
        for uri in redirect_uris:
            if not uri.startswith(('http://', 'https://')):
                return jsonify({'error': f'Invalid redirect URI: {uri}'}), 400
        
        # Create OAuth application
        app = OAuthApplication(
            name=name,
            description=description,
            user_id=user.id,
            redirect_uris=json.dumps(redirect_uris),
            scopes=json.dumps(scopes)
        )
        app.generate_credentials()
        
        db.session.add(app)
        db.session.commit()
        
        return jsonify({
            'message': 'OAuth application created successfully',
            'client_id': app.client_id,
            'client_secret': app.client_secret,
            'id': app.id
        })

@app.route('/api/admin/administrators', methods=['GET', 'POST'])
@login_required
@require_admin
def admin_manage_administrators():
    if request.method == 'GET':
        # Get all administrators
        admins = User.query.filter_by(is_admin=True).all()
        admins_data = [{
            'id': admin.id,
            'username': admin.username,
            'email': admin.email,
            'is_admin': admin.is_admin,
            'is_suspended': admin.is_suspended,
            'is_super_admin': admin.email == 'ethan@hackclub.com',
            'created_at': admin.created_at.isoformat() if admin.created_at else None,
            'last_login': admin.last_login.isoformat() if admin.last_login else None,
            'clubs_led': len(admin.led_clubs)
        } for admin in admins]

        return jsonify({'admins': admins_data})

    elif request.method == 'POST':
        # Add new administrator
        data = request.get_json()
        email = data.get('email')

        if not email:
            return jsonify({'error': 'Email is required'}), 400

        # Find user by email
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'error': 'User not found. They must create an account first.'}), 404

        if user.is_admin:
            return jsonify({'error': 'User is already an administrator'}), 400

        # Make user an admin
        user.is_admin = True
        db.session.commit()

        return jsonify({'message': f'Administrator privileges granted to {user.username}'})

@app.route('/api/admin/administrators/<int:admin_id>', methods=['DELETE'])
@login_required
@require_admin
def admin_remove_administrator(admin_id):
    admin = User.query.get_or_404(admin_id)

    # Don't allow removing your own admin privileges
    if admin.id == current_user.id:
        return jsonify({'error': 'Cannot remove your own administrator privileges'}), 400

    # Don't allow removing super admin
    if admin.email == 'ethan@hackclub.com':
        return jsonify({'error': 'Cannot remove super administrator privileges'}), 400

    if not admin.is_admin:
        return jsonify({'error': 'User is not an administrator'}), 400

    # Remove admin privileges
    admin.is_admin = False
    db.session.commit()

    return jsonify({'message': f'Administrator privileges removed from {admin.username}'})

@app.route('/api/debug/airtable-test', methods=['GET'])
@login_required
def test_airtable_connection():
    """Debug endpoint to test Airtable connection and get base info"""
    if not airtable_service.api_token:
        return jsonify({'error': 'No Airtable API token configured'}), 400

    # Test basic API access by getting base schema
    try:
        import urllib.parse
        base_url = f'https://api.airtable.com/v0/meta/bases/{airtable_service.base_id}/tables'

        response = requests.get(base_url, headers=airtable_service.headers)

        if response.status_code == 200:
            data = response.json()
            tables = data.get('tables', [])
            table_names = [table.get('name') for table in tables]

            # Find our table
            target_table = None
            for table in tables:
                if table.get('name') == airtable_service.table_name:
                    target_table = table
                    break

            result = {
                'base_id': airtable_service.base_id,
                'configured_table_name': airtable_service.table_name,
                'available_tables': table_names,
                'table_found': target_table is not None
            }

            if target_table:
                fields = target_table.get('fields', [])
                field_names = [field.get('name') for field in fields]
                result['table_fields'] = field_names

                # Check which of our payload fields match
                payload_fields = [
                    'Hackatime Project', 'First Name', 'Last Name', 'GitHub Username', 'Email',
                    'Age', 'Birthday', 'Description', 'Playable URL', 'What are we doing well?',
                    'How can we improve?', 'Screenshot', 'Address (Line 1)', 'Address (Line 2)',
                    'City', 'State / Province', 'ZIP / Postal Code', 'Country', 'Club Name',
                    'Leader Email', 'Hours', 'Grant Amount', 'Status', 'Decision Reason',
                    'How did you hear about this?'
                ]

                matching_fields = [field for field in payload_fields if field in field_names]
                missing_fields = [field for field in payload_fields if field not in field_names]

                result['matching_fields'] = matching_fields
                result['missing_fields'] = missing_fields

            return jsonify(result)
        else:
            return jsonify({
                'error': f'Failed to get base schema: {response.status_code}',
                'response': response.text
            }), response.status_code

    except Exception as e:
        return jsonify({'error': f'Error testing Airtable: {str(e)}'}), 500

# Developer API Endpoints
@app.route('/api/v1/clubs', methods=['GET'])
@require_api_key(['clubs:read'])
@limiter.limit("100 per hour")
def api_get_clubs():
    """Get all clubs with pagination"""
    page = int(request.args.get('page', 1))
    per_page = min(int(request.args.get('per_page', 20)), 100)
    search = request.args.get('search', '').strip()
    
    query = Club.query
    
    if search:
        query = query.filter(
            db.or_(
                Club.name.ilike(f'%{search}%'),
                Club.location.ilike(f'%{search}%')
            )
        )
    
    pagination = query.paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    clubs_data = [{
        'id': club.id,
        'name': club.name,
        'description': club.description,
        'location': club.location,
        'leader': {
            'id': club.leader.id,
            'username': club.leader.username,
            'email': club.leader.email
        },
        'member_count': len(club.members) + 1,
        'balance': float(club.balance),
        'created_at': club.created_at.isoformat() if club.created_at else None
    } for club in pagination.items]
    
    return jsonify({
        'clubs': clubs_data,
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': pagination.total,
            'pages': pagination.pages,
            'has_next': pagination.has_next,
            'has_prev': pagination.has_prev
        }
    })

@app.route('/api/v1/clubs/<club_identifier>', methods=['GET'])
@require_api_key(['clubs:read'])
@limiter.limit("200 per hour")
def api_get_club(club_identifier):
    """Get a specific club by ID or name, with Airtable fallback"""
    club = None
    
    # Try to find by ID first
    try:
        club_id = int(club_identifier)
        club = Club.query.get(club_id)
    except ValueError:
        # Not an ID, try by name
        club = Club.query.filter(Club.name.ilike(f'%{club_identifier}%')).first()
    
    if club:
        # Found in database
        return jsonify({
            'club': {
                'id': club.id,
                'name': club.name,
                'description': club.description,
                'location': club.location,
                'leader': {
                    'id': club.leader.id,
                    'username': club.leader.username,
                    'email': club.leader.email
                },
                'member_count': len(club.members) + 1,
                'balance': float(club.balance),
                'join_code': club.join_code,
                'created_at': club.created_at.isoformat() if club.created_at else None,
                'source': 'database'
            }
        })
    
    # Fallback to Airtable
    airtable_club = get_club_from_airtable(club_identifier)
    if airtable_club:
        return jsonify({'club': airtable_club})
    
    return jsonify({'error': 'Club not found'}), 404

@app.route('/api/v1/clubs/<int:club_id>/members', methods=['GET'])
@require_api_key(['clubs:read'])
@limiter.limit("200 per hour")
def api_get_club_members(club_id):
    """Get club members"""
    club = Club.query.get_or_404(club_id)
    
    members_data = []
    
    # Add leader
    members_data.append({
        'id': club.leader.id,
        'username': club.leader.username,
        'email': club.leader.email,
        'role': 'leader',
        'joined_at': club.created_at.isoformat() if club.created_at else None
    })
    
    # Add other members
    for membership in club.members:
        members_data.append({
            'id': membership.user.id,
            'username': membership.user.username,
            'email': membership.user.email,
            'role': membership.role,
            'joined_at': membership.joined_at.isoformat() if membership.joined_at else None
        })
    
    return jsonify({'members': members_data})

@app.route('/api/v1/clubs/<int:club_id>/projects', methods=['GET'])
@require_api_key(['projects:read'])
@limiter.limit("200 per hour")
def api_get_club_projects(club_id):
    """Get club projects"""
    club = Club.query.get_or_404(club_id)
    
    projects = ClubProject.query.filter_by(club_id=club_id).all()
    projects_data = [{
        'id': project.id,
        'name': project.name,
        'description': project.description,
        'url': project.url,
        'github_url': project.github_url,
        'featured': project.featured,
        'author': {
            'id': project.user.id,
            'username': project.user.username
        },
        'created_at': project.created_at.isoformat() if project.created_at else None,
        'updated_at': project.updated_at.isoformat() if project.updated_at else None
    } for project in projects]
    
    return jsonify({'projects': projects_data})

@app.route('/api/v1/clubs/<int:club_id>/assignments', methods=['GET'])
@require_api_key(['assignments:read'])
@limiter.limit("200 per hour")
def api_get_club_assignments(club_id):
    """Get club assignments"""
    club = Club.query.get_or_404(club_id)
    
    assignments = ClubAssignment.query.filter_by(club_id=club_id).all()
    assignments_data = [{
        'id': assignment.id,
        'title': assignment.title,
        'description': assignment.description,
        'due_date': assignment.due_date.isoformat() if assignment.due_date else None,
        'for_all_members': assignment.for_all_members,
        'status': assignment.status,
        'created_at': assignment.created_at.isoformat() if assignment.created_at else None
    } for assignment in assignments]
    
    return jsonify({'assignments': assignments_data})

@app.route('/api/v1/clubs/<int:club_id>/meetings', methods=['GET'])
@require_api_key(['meetings:read'])
@limiter.limit("200 per hour")
def api_get_club_meetings(club_id):
    """Get club meetings"""
    club = Club.query.get_or_404(club_id)
    
    meetings = ClubMeeting.query.filter_by(club_id=club_id).all()
    meetings_data = [{
        'id': meeting.id,
        'title': meeting.title,
        'description': meeting.description,
        'meeting_date': meeting.meeting_date.isoformat() if meeting.meeting_date else None,
        'start_time': meeting.start_time,
        'end_time': meeting.end_time,
        'location': meeting.location,
        'meeting_link': meeting.meeting_link,
        'created_at': meeting.created_at.isoformat() if meeting.created_at else None
    } for meeting in meetings]
    
    return jsonify({'meetings': meetings_data})

@app.route('/api/v1/users/<int:user_id>', methods=['GET'])
@require_api_key(['users:read'])
@limiter.limit("200 per hour")
def api_get_user(user_id):
    """Get user information"""
    user = User.query.get_or_404(user_id)
    
    return jsonify({
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'created_at': user.created_at.isoformat() if user.created_at else None,
            'clubs_led': len(user.led_clubs),
            'clubs_joined': len(user.club_memberships)
        }
    })

@app.route('/api/v1/analytics/overview', methods=['GET'])
@require_api_key(['analytics:read'])
@limiter.limit("100 per hour")
def api_get_analytics():
    """Get platform analytics"""
    total_users = User.query.count()
    total_clubs = Club.query.count()
    total_posts = ClubPost.query.count()
    total_assignments = ClubAssignment.query.count()
    total_meetings = ClubMeeting.query.count()
    total_projects = ClubProject.query.count()
    
    # Recent activity (last 30 days)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    recent_users = User.query.filter(User.created_at >= thirty_days_ago).count()
    recent_clubs = Club.query.filter(Club.created_at >= thirty_days_ago).count()
    active_users = User.query.filter(User.last_login >= thirty_days_ago).count()
    
    return jsonify({
        'analytics': {
            'totals': {
                'users': total_users,
                'clubs': total_clubs,
                'posts': total_posts,
                'assignments': total_assignments,
                'meetings': total_meetings,
                'projects': total_projects
            },
            'recent': {
                'new_users_30d': recent_users,
                'new_clubs_30d': recent_clubs,
                'active_users_30d': active_users
            }
        }
    })

# OAuth Endpoints
@app.route('/oauth/authorize')
@login_required
@limiter.limit("20 per minute")
def oauth_authorize():
    """OAuth authorization endpoint"""
    client_id = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')
    response_type = request.args.get('response_type', 'code')
    scope = request.args.get('scope', '')
    state = request.args.get('state', '')
    
    if response_type != 'code':
        return jsonify({'error': 'unsupported_response_type'}), 400
    
    # Find OAuth application
    app = OAuthApplication.query.filter_by(client_id=client_id, is_active=True).first()
    if not app:
        return jsonify({'error': 'invalid_client'}), 400
    
    # Validate redirect URI
    allowed_uris = json.loads(app.redirect_uris or '[]')
    if redirect_uri not in allowed_uris:
        return jsonify({'error': 'invalid_redirect_uri'}), 400
    
    # Parse scopes
    requested_scopes = scope.split(' ') if scope else []
    app_scopes = json.loads(app.scopes or '[]')
    
    invalid_scopes = [s for s in requested_scopes if s not in app_scopes]
    if invalid_scopes:
        return f"Invalid scopes: {invalid_scopes}", 400
    
    # For now, auto-approve (in production, show approval page)
    # Generate authorization code
    auth_code = OAuthAuthorizationCode(
        user_id=current_user.id,
        application_id=app.id,
        redirect_uri=redirect_uri,
        scopes=json.dumps(requested_scopes),
        state=state
    )
    auth_code.generate_code()
    
    db.session.add(auth_code)
    db.session.commit()
    
    # Redirect with authorization code
    redirect_url = f"{redirect_uri}?code={auth_code.code}"
    if state:
        redirect_url += f"&state={state}"
    
    return redirect(redirect_url)

@app.route('/oauth/token', methods=['POST'])
@limiter.limit("60 per minute")
def oauth_token():
    """OAuth token endpoint"""
    grant_type = request.form.get('grant_type')
    client_id = request.form.get('client_id')
    client_secret = request.form.get('client_secret')
    
    # Find OAuth application
    app = OAuthApplication.query.filter_by(
        client_id=client_id, 
        client_secret=client_secret,
        is_active=True
    ).first()
    
    if not app:
        return jsonify({'error': 'invalid_client'}), 401
    
    if grant_type == 'authorization_code':
        code = request.form.get('code')
        redirect_uri = request.form.get('redirect_uri')
        
        # Find authorization code
        auth_code = OAuthAuthorizationCode.query.filter_by(
            code=code,
            application_id=app.id,
            redirect_uri=redirect_uri,
            used=False
        ).filter(OAuthAuthorizationCode.expires_at > datetime.utcnow()).first()
        
        if not auth_code:
            return jsonify({'error': 'invalid_grant'}), 400
        
        # Mark code as used
        auth_code.used = True
        
        # Create access token
        token = OAuthToken(
            user_id=auth_code.user_id,
            application_id=app.id,
            scopes=auth_code.scopes
        )
        token.generate_tokens()
        
        db.session.add(token)
        db.session.commit()
        
        return jsonify({
            'access_token': token.access_token,
            'token_type': 'Bearer',
            'expires_in': 3600,
            'refresh_token': token.refresh_token,
            'scope': ' '.join(json.loads(token.scopes or '[]'))
        })
    
    elif grant_type == 'refresh_token':
        refresh_token = request.form.get('refresh_token')
        
        # Find refresh token
        token = OAuthToken.query.filter_by(
            refresh_token=refresh_token,
            application_id=app.id,
            is_active=True
        ).first()
        
        if not token:
            return jsonify({'error': 'invalid_grant'}), 400
        
        # Generate new tokens
        token.generate_tokens()
        db.session.commit()
        
        return jsonify({
            'access_token': token.access_token,
            'token_type': 'Bearer',
            'expires_in': 3600,
            'refresh_token': token.refresh_token,
            'scope': ' '.join(json.loads(token.scopes or '[]'))
        })
    
    return jsonify({'error': 'unsupported_grant_type'}), 400

@app.route('/oauth/user', methods=['GET'])
@require_oauth_token()
@limiter.limit("200 per hour")
def oauth_user():
    """Get authenticated user info via OAuth"""
    user = request.oauth_user
    
    return jsonify({
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name
        }
    })

if __name__ == '__main__':

    if db_available:
        try:
            with app.app_context():
                db.create_all()
                
                if os.getenv('FLASK_ENV') == 'production':
                    app.logger.info('Database tables created successfully')

                # Create super admin if doesn't exist
                super_admin = User.query.filter_by(email='ethan@hackclub.com').first()
                if not super_admin:
                    super_admin = User(
                        username='ethan',
                        email='ethan@hackclub.com',
                        is_admin=True
                    )
                    super_admin.set_password('hackclub2024')  # Default password
                    db.session.add(super_admin)
                    db.session.commit()
                    if os.getenv('FLASK_ENV') == 'production':
                        app.logger.info('Super admin account created')
                else:
                    # Ensure admin status
                    super_admin.is_admin = True
                    db.session.commit()
                    if os.getenv('FLASK_ENV') == 'production':
                        app.logger.info('Super admin account verified')

        except Exception as e:
            error_msg = f"Database connection failed: {e}"
            print(error_msg)
            if os.getenv('FLASK_ENV') == 'production':
                app.logger.error(error_msg)
            print("Starting app without database functionality...")
            db_available = False
    else:
        msg = "Starting app without database functionality..."
        print(msg)
        if os.getenv('FLASK_ENV') == 'production':
            app.logger.warning(msg)

    app.run(host='0.0.0.0', port=5000, debug=True)