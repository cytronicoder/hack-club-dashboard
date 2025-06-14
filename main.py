import os
import time
import json
import hashlib
import requests
import logging
import re
import html
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, render_template, redirect, flash, request, jsonify, url_for, abort, session, Response
import psycopg2
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import string
import urllib.parse

# Setup logger
logger = logging.getLogger(__name__)

def get_database_url():
    url = os.getenv('DATABASE_URL')
    if url and url.startswith('postgres://'):
        url = url.replace('postgres://', 'postgresql://', 1)
    return url

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = get_database_url()
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Input validation and sanitization functions
def sanitize_string(value, max_length=None, allow_html=False):
    """Sanitize string input to prevent XSS and injection attacks"""
    if not value:
        return value

    # Convert to string if not already
    value = str(value).strip()

    # Limit length if specified
    if max_length and len(value) > max_length:
        value = value[:max_length]

    # Remove or escape HTML/script tags
    if not allow_html:
        # Remove script tags completely
        value = re.sub(r'<script[^>]*>.*?</script>', '', value, flags=re.IGNORECASE | re.DOTALL)
        # Remove other potentially dangerous tags
        value = re.sub(r'<(script|iframe|object|embed|form|input|button|link|style)[^>]*>', '', value, flags=re.IGNORECASE)
        # Escape remaining HTML
        value = html.escape(value)

    # Remove null bytes and other control characters
    value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)

    return value

def validate_username(username):
    """Validate username format"""
    if not username:
        return False, "Username is required"

    username = username.strip()
    if len(username) < 3:
        return False, "Username must be at least 3 characters long"
    if len(username) > 30:
        return False, "Username must be less than 30 characters"

    # Only allow alphanumeric characters, underscores, and hyphens
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        return False, "Username can only contain letters, numbers, underscores, and hyphens"

    return True, username

def validate_email(email):
    """Validate email format"""
    if not email:
        return False, "Email is required"

    email = email.strip().lower()
    if len(email) > 120:
        return False, "Email is too long"

    # Basic email validation
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        return False, "Invalid email format"

    return True, email

def validate_name(name, field_name="Name"):
    """Validate first/last name"""
    if not name:
        return True, ""  # Names are optional

    name = name.strip()
    if len(name) > 50:
        return False, f"{field_name} must be less than 50 characters"

    # Only allow letters, spaces, hyphens, and apostrophes
    if not re.match(r"^[a-zA-Z\s'-]+$", name):
        return False, f"{field_name} can only contain letters, spaces, hyphens, and apostrophes"

    return True, name

# Session configuration for multiple servers
app.config['SESSION_COOKIE_SECURE'] = True if os.getenv('FLASK_ENV') == 'production' else False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_DOMAIN'] = None
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
app.config['SESSION_TYPE'] = 'filesystem'

SLACK_CLIENT_ID = os.getenv('SLACK_CLIENT_ID')
SLACK_CLIENT_SECRET = os.getenv('SLACK_CLIENT_SECRET')
SLACK_SIGNING_SECRET = os.getenv('SLACK_SIGNING_SECRET')

# Initialize database
db = SQLAlchemy(app)

# Initialize rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["1000 per hour"],
    storage_uri="memory://",
    strategy="fixed-window"
)

# Simple User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    birthday = db.Column(db.Date)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    hackatime_api_key = db.Column(db.String(255))
    slack_user_id = db.Column(db.String(255), unique=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class APIKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False, index=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_used_at = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    rate_limit = db.Column(db.Integer, default=1000)  # requests per hour
    scopes = db.Column(db.Text)  # JSON array of allowed scopes

    user = db.relationship('User', backref=db.backref('api_keys', cascade='all, delete-orphan'))

    def generate_key(self):
        self.key = secrets.token_urlsafe(48)

    def get_scopes(self):
        try:
            return json.loads(self.scopes) if self.scopes else []
        except:
            return []

    def set_scopes(self, scopes_list):
        self.scopes = json.dumps(scopes_list)

class OAuthApplication(db.Model):
    __tablename__ = 'o_auth_application'
    
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    client_secret = db.Column(db.String(128), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    redirect_uris = db.Column(db.Text)  # JSON array of allowed redirect URIs
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    is_active = db.Column(db.Boolean, default=True)
    scopes = db.Column(db.Text)  # JSON array of allowed scopes
    
    # Relationships
    tokens = db.relationship(
        'OAuthToken',
        primaryjoin='OAuthApplication.id == OAuthToken.application_id',
        back_populates='application',
        cascade='all, delete-orphan'
    )
    authorization_codes = db.relationship(
        'OAuthAuthorizationCode',
        primaryjoin='OAuthApplication.id == OAuthAuthorizationCode.application_id',
        back_populates='application',
        cascade='all, delete-orphan'
    )

    user = db.relationship('User', backref=db.backref('oauth_applications', cascade='all, delete-orphan'))

    def generate_credentials(self):
        self.client_id = secrets.token_urlsafe(32)
        self.client_secret = secrets.token_urlsafe(64)

    def get_redirect_uris(self):
        try:
            return json.loads(self.redirect_uris) if self.redirect_uris else []
        except:
            return []

    def set_redirect_uris(self, uris_list):
        self.redirect_uris = json.dumps(uris_list)

    def get_scopes(self):
        try:
            return json.loads(self.scopes) if self.scopes else []
        except:
            return []

    def set_scopes(self, scopes_list):
        self.scopes = json.dumps(scopes_list)

class OAuthToken(db.Model):
    __tablename__ = 'o_auth_token'
    
    id = db.Column(db.Integer, primary_key=True)
    access_token = db.Column(db.String(128), unique=True, nullable=False, index=True)
    refresh_token = db.Column(db.String(128), unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    application_id = db.Column(db.Integer, db.ForeignKey('o_auth_application.id'), nullable=False)
    scopes = db.Column(db.Text)  # JSON array of granted scopes
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    is_active = db.Column(db.Boolean, default=True)

    user = db.relationship('User', backref=db.backref('oauth_tokens', cascade='all, delete-orphan'))
    application = db.relationship('OAuthApplication', back_populates='tokens', foreign_keys=[application_id])

    def generate_tokens(self):
        self.access_token = secrets.token_urlsafe(48)
        self.refresh_token = secrets.token_urlsafe(48)
        self.expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

    def get_scopes(self):
        try:
            return json.loads(self.scopes) if self.scopes else []
        except:
            return []

    def set_scopes(self, scopes_list):
        self.scopes = json.dumps(scopes_list)

class OAuthAuthorizationCode(db.Model):
    __tablename__ = 'o_auth_authorization_code'
    
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(128), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    application_id = db.Column(db.Integer, db.ForeignKey('o_auth_application.id'), nullable=False)
    redirect_uri = db.Column(db.String(500), nullable=False)
    scopes = db.Column(db.Text)  # JSON array of requested scopes
    state = db.Column(db.String(500))
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    user = db.relationship('User', backref=db.backref('oauth_authorization_codes', cascade='all, delete-orphan'))
    application = db.relationship('OAuthApplication', back_populates='authorization_codes', foreign_keys=[application_id])

    def generate_code(self):
        self.code = secrets.token_urlsafe(32)
        self.expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

    def get_scopes(self):
        try:
            return json.loads(self.scopes) if self.scopes else []
        except:
            return []

    def set_scopes(self, scopes_list):
        self.scopes = json.dumps(scopes_list)

# API authentication decorators
def api_key_required(scopes=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return jsonify({'error': 'API key required'}), 401

            api_key = auth_header.split(' ')[1]
            key_obj = APIKey.query.filter_by(key=api_key, is_active=True).first()

            if not key_obj:
                return jsonify({'error': 'Invalid API key'}), 401

            # Check scopes if provided
            if scopes:
                key_scopes = key_obj.get_scopes()
                if not any(scope in key_scopes for scope in scopes):
                    return jsonify({'error': 'Insufficient permissions'}), 403

            # Update last used timestamp
            key_obj.last_used_at = datetime.now(timezone.utc)
            db.session.commit()

            # Add key info to request context
            request.api_key = key_obj
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def oauth_required(scopes=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return jsonify({'error': 'OAuth token required'}), 401

            access_token = auth_header.split(' ')[1]
            token_obj = OAuthToken.query.filter_by(
                access_token=access_token, 
                is_active=True
            ).first()

            if not token_obj:
                return jsonify({'error': 'Invalid OAuth token'}), 401

            # Check if token is expired
            if token_obj.expires_at < datetime.now(timezone.utc):
                return jsonify({'error': 'OAuth token expired'}), 401

            # Check scopes if provided
            if scopes:
                token_scopes = token_obj.get_scopes()
                if not any(scope in token_scopes for scope in scopes):
                    return jsonify({'error': 'Insufficient permissions'}), 403

            # Add token and user info to request context
            request.oauth_token = token_obj
            request.oauth_user = token_obj.user
            return f(*args, **kwargs)
        return decorated_function
    return decorator

class Club(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    location = db.Column(db.String(255))
    leader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    join_code = db.Column(db.String(8), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    balance = db.Column(db.Numeric(10, 2), default=0.00)

    leader = db.relationship('User', backref='led_clubs')
    members = db.relationship('ClubMembership', back_populates='club', cascade='all, delete-orphan')

    def generate_join_code(self):
        self.join_code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))

class ClubMembership(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    role = db.Column(db.String(20), default='member')
    joined_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    user = db.relationship('User', backref='club_memberships')
    club = db.relationship('Club', back_populates='members')

class ClubPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

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
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

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
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    club = db.relationship('Club', backref='meetings')

class ClubResource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text)
    icon = db.Column(db.String(50), default='book')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

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
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    club = db.relationship('Club', backref='projects')
    user = db.relationship('User', backref='projects')

# Authentication helpers
def get_current_user():
    user_id = session.get('user_id')
    logged_in = session.get('logged_in')

    if not user_id or not logged_in:
        return None

    try:
        user = db.session.get(User, int(user_id))
        if not user:
            # Clear invalid session
            session.clear()
            return None
        return user
    except Exception as e:
        app.logger.error(f"Error getting current user: {e}")
        try:
            db.session.rollback()
            user = db.session.get(User, int(user_id))
            if not user:
                session.clear()
            return user
        except Exception as e2:
            app.logger.error(f"Error on retry getting current user: {e2}")
            session.clear()
            return None

def login_user(user, remember=False):
    session['user_id'] = user.id
    session['logged_in'] = True
    if remember:
        session.permanent = True
    user.last_login = datetime.now(timezone.utc)
    try:
        db.session.commit()
    except:
        db.session.rollback()

def logout_user():
    session.pop('user_id', None)
    session.pop('logged_in', None)
    session.clear()

def is_authenticated():
    return session.get('logged_in') and session.get('user_id')

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        authenticated = is_authenticated()
        current_user = get_current_user()

        app.logger.debug(f"Auth check for {request.endpoint}: authenticated={authenticated}, user_id={session.get('user_id')}, logged_in={session.get('logged_in')}, current_user={current_user.username if current_user else None}")

        if not authenticated or not current_user:
            app.logger.warning(f"Authentication failed for {request.endpoint}: user_id={session.get('user_id')}, logged_in={session.get('logged_in')}")
            if request.is_json:
                return jsonify({'error': 'Authentication required'}), 401
            flash('Please log in to access this page.', 'info')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Make current_user available in templates
@app.context_processor
def inject_user():
    return dict(current_user=get_current_user())

# Airtable Service for Pizza Grants
class AirtableService:
    def __init__(self):
        self.api_token = os.environ.get('AIRTABLE_TOKEN')
        self.base_id = os.environ.get('AIRTABLE_BASE_ID', 'appSnnIu0BhjI3E1p')
        self.table_name = os.environ.get('AIRTABLE_TABLE_NAME', 'Grants')
        self.headers = {
            'Authorization': f'Bearer {self.api_token}',
            'Content-Type': 'application/json'
        }
        encoded_table_name = urllib.parse.quote(self.table_name)
        self.base_url = f'https://api.airtable.com/v0/{self.base_id}/{encoded_table_name}'

    def verify_club_leader(self, email, club_name):
        if not self.api_token:
            return False
        leaders_table_name = urllib.parse.quote('Club Leaders & Emails')
        leaders_url = f'https://api.airtable.com/v0/{self.base_id}/{leaders_table_name}'
        try:
            params = {
                'filterByFormula': f'AND(FIND("{email}", {{Current Leaders\' Emails}}) > 0, FIND("{club_name}", {{Venue}}) > 0)'
            }
            response = requests.get(leaders_url, headers=self.headers, params=params)
            if response.status_code == 200:
                data = response.json()
                records = data.get('records', [])
                return len(records) > 0
            return False
        except:
            return False

    def log_pizza_grant(self, submission_data):
        if not self.api_token:
            return None

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
            return None
        except:
            return None

    def submit_pizza_grant(self, grant_data):
        """Submit pizza grant to Grants table"""
        if not self.api_token:
            return None

        # Use Grants table instead
        grants_table_name = urllib.parse.quote('Grants')
        grants_url = f'https://api.airtable.com/v0/{self.base_id}/{grants_table_name}'

        fields = {
            'Club': grant_data.get('club_name', ''),
            'Email': grant_data.get('contact_email', ''),
            'Status': 'In progress',
            'Grant Amount': str(grant_data.get('grant_amount', 0)),
            'Grant Type': 'Pizza Card',
            'Address': grant_data.get('club_address', ''),
            'Order ID': grant_data.get('order_id', '')
        }

        payload = {'records': [{'fields': fields}]}

        try:
            response = requests.post(grants_url, headers=self.headers, json=payload)
            app.logger.debug(f"Airtable response status: {response.status_code}")
            app.logger.debug(f"Airtable response body: {response.text}")
            if response.status_code in [200, 201]:
                return response.json()
            else:
                app.logger.error(f"Airtable error: {response.text}")
                return None
        except Exception as e:
            app.logger.error(f"Exception submitting to Airtable: {str(e)}")
            return None

    def get_pizza_grant_submissions(self):
        if not self.api_token:
            return []

        try:
            response = requests.get(self.base_url, headers=self.headers)
            if response.status_code == 200:
                data = response.json()
                records = data.get('records', [])

                submissions = []
                for record in records:
                    fields = record.get('fields', {})
                    submissions.append({
                        'id': record['id'],
                        'project_name': fields.get('Hackatime Project', ''),
                        'first_name': fields.get('First Name', ''),
                        'last_name': fields.get('Last Name', ''),
                        'email': fields.get('Email', ''),
                        'github_username': fields.get('GitHub Username', ''),
                        'description': fields.get('Description', ''),
                        'playable_url': fields.get('Playable URL', ''),
                        'code_url': fields.get('Code URL', ''),
                        'doing_well': fields.get('What are we doing well?', ''),
                        'improve': fields.get('How can we improve?', ''),
                        'address_1': fields.get('Address (Line 1)', ''),
                        'address_2': fields.get('Address (Line 2)', ''),
                        'city': fields.get('City', ''),
                        'state': fields.get('State / Province', ''),
                        'zip': fields.get('ZIP / Postal Code', ''),
                        'country': fields.get('Country', ''),
                        'club_name': fields.get('Club Name', ''),
                        'leader_email': fields.get('Leader Email', ''),
                        'hours': fields.get('Hours', '0'),
                        'grant_amount': fields.get('Grant Amount', '$0'),
                        'status': fields.get('Status', 'Pending'),
                        'screenshot_url': fields.get('Screenshot', [{}])[0].get('url', '') if fields.get('Screenshot') else '',
                        'created_time': record.get('createdTime', '')
                    })

                return submissions
            return []
        except Exception as e:
            app.logger.error(f"Error fetching pizza grant submissions: {str(e)}")
            return []

    def get_submission_by_id(self, submission_id):
        if not self.api_token:
            return None

        try:
            url = f"{self.base_url}/{submission_id}"
            response = requests.get(url, headers=self.headers)
            if response.status_code == 200:
                data = response.json()
                fields = data.get('fields', {})
                return {
                    'id': data['id'],
                    'club_name': fields.get('Club Name', ''),
                    'grant_amount': fields.get('Grant Amount', '$0'),
                    'status': fields.get('Status', 'Pending')
                }
            return None
        except Exception as e:
            app.logger.error(f"Error fetching submission {submission_id}: {str(e)}")
            return None

    def update_submission_status(self, submission_id, action):
        if not self.api_token:
            return False

        status = 'Approved' if action == 'approve' else 'Rejected'

        try:
            url = f"{self.base_url}/{submission_id}"
            payload = {
                'fields': {
                    'Status': status
                }
            }
            response = requests.patch(url, headers=self.headers, json=payload)
            return response.status_code == 200
        except Exception as e:
            app.logger.error(f"Error updating submission status: {str(e)}")
            return False

    def delete_submission(self, submission_id):
        if not self.api_token:
            return False

        try:
            url = f"{self.base_url}/{submission_id}"
            response = requests.delete(url, headers=self.headers)
            return response.status_code == 200
        except Exception as e:
            app.logger.error(f"Error deleting submission: {str(e)}")
            return False

airtable_service = AirtableService()

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
        except:
            return None

    def get_user_projects(self, api_key):
        stats = self.get_user_stats(api_key)
        if not stats or 'data' not in stats:
            return []
        projects = stats['data'].get('projects', [])
        active_projects = [p for p in projects if p.get('total_seconds', 0) > 0]
        active_projects.sort(key=lambda x: x.get('total_seconds', 0), reverse=True)
        for project in active_projects:
            total_seconds = project.get('total_seconds', 0)
            project['formatted_time'] = self.format_duration(total_seconds)
        return active_projects

    def format_duration(self, total_seconds):
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
            return response.json()
        except:
            return {'ok': False, 'error': 'Request failed'}

    def get_user_info(self, access_token):
        headers = {'Authorization': f'Bearer {access_token}'}
        identity_url = f'{self.base_url}/users.identity'
        identity_response = requests.get(identity_url, headers=headers)
        if identity_response.status_code != 200:
            return None
        try:
            identity_data = identity_response.json()
            if not identity_data.get('ok'):
                return None
            user_id = identity_data['user']['id']
            profile_url = f'{self.base_url}/users.info'
            profile_params = {'user': user_id}
            profile_response = requests.get(profile_url, headers=headers, params=profile_params)
            if profile_response.status_code == 200:
                try:
                    profile_data = profile_response.json()
                    if profile_data.get('ok'):
                        identity_data['user']['profile'] = profile_data['user']['profile']
                except:
                    pass
            return identity_data
        except:
            return None

slack_oauth_service = SlackOAuthService()

# Routes
@app.route('/')
def index():
    if is_authenticated():
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if is_authenticated():
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        remember_me = request.form.get('remember_me') == 'on'

        if not email or not password:
            flash('Email and password are required', 'error')
            return render_template('login.html')

        try:
            user = User.query.filter_by(email=email).first()
        except Exception as e:
            try:
                db.session.rollback()
                user = User.query.filter_by(email=email).first()
            except:
                flash('Database connection error. Please try again.', 'error')
                return render_template('login.html')

        if user and user.check_password(password):
            app.logger.info(f"User {user.username} (ID: {user.id}) logging in from IP: {request.remote_addr}")
            login_user(user, remember=remember_me)
            app.logger.info(f"Session created for user {user.username}: session_id={session.get('user_id')}, logged_in={session.get('logged_in')}")
            flash(f'Welcome back, {user.username}!', 'success')

            # Check for pending OAuth flow
            oauth_params = session.get('oauth_params')
            if oauth_params:
                session.pop('oauth_params', None)
                # Redirect back to OAuth authorize with original params
                query_string = '&'.join([f"{k}={v}" for k, v in oauth_params.items()])
                return redirect(url_for('oauth_authorize') + f'?{query_string}')

            # Check for pending join code
            pending_join_code = session.get('pending_join_code')
            if pending_join_code:
                session.pop('pending_join_code', None)
                return redirect(url_for('join_club_redirect') + f'?code={pending_join_code}')

            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'error')

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def signup():
    if is_authenticated():
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # Get and validate inputs
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        birthday = request.form.get('birthday', '')
        is_leader = request.form.get('is_leader') == 'on'

        # Validate username
        valid, result = validate_username(username)
        if not valid:
            flash(result, 'error')
            return render_template('signup.html')
        username = result

        # Validate email
        valid, result = validate_email(email)
        if not valid:
            flash(result, 'error')
            return render_template('signup.html')
        email = result

        # Validate password
        if not password or len(password) < 6:
            flash('Password must be at least 6 characters long', 'error')
            return render_template('signup.html')

        # Validate names
        if first_name:
            valid, result = validate_name(first_name, "First name")
            if not valid:
                flash(result, 'error')
                return render_template('signup.html')
            first_name = result

        if last_name:
            valid, result = validate_name(last_name, "Last name")
            if not valid:
                flash(result, 'error')
                return render_template('signup.html')
            last_name = result

        # Check for existing users
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return render_template('signup.html')

        if User.query.filter_by(username=username).first():
            flash('Username already taken', 'error')
            return render_template('signup.html')

        if is_leader:
            session['signup_data'] = {
                'username': username,
                'email': email,
                'password': password,
                'first_name': first_name,
                'last_name': last_name,
                'birthday': birthday,
                'is_leader': True
            }
            return redirect(url_for('verify_leader'))

        user = User(
            username=username, 
            email=email, 
            first_name=first_name, 
            last_name=last_name, 
            birthday=datetime.strptime(birthday, '%Y-%m-%d').date() if birthday else None
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    current_user = get_current_user()
    if not current_user:
        flash('Please log in to access your dashboard.', 'info')
        return redirect(url_for('login'))

    memberships = ClubMembership.query.filter_by(user_id=current_user.id).all()
    led_clubs = Club.query.filter_by(leader_id=current_user.id).all()

    all_clubs = led_clubs + [m.club for m in memberships]
    if len(all_clubs) == 1:
        return redirect(url_for('club_dashboard', club_id=all_clubs[0].id))

    return render_template('dashboard.html', memberships=memberships, led_clubs=led_clubs)

@app.route('/club-dashboard')
@app.route('/club-dashboard/<int:club_id>')
@login_required
def club_dashboard(club_id=None):
    current_user = get_current_user()
    if not current_user:
        flash('Please log in to access the club dashboard.', 'info')
        return redirect(url_for('login'))

    if club_id:
        club = Club.query.get_or_404(club_id)
        is_leader = club.leader_id == current_user.id
        is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

        if not is_leader and not is_member:
            flash('You are not a member of this club', 'error')
            return redirect(url_for('dashboard'))
    else:
        club = Club.query.filter_by(leader_id=current_user.id).first()
        if not club:
            membership = ClubMembership.query.filter_by(user_id=current_user.id).first()
            if membership:
                club = membership.club

        if not club:
            flash('You are not a member of any club', 'error')
            return redirect(url_for('dashboard'))

    return render_template('club_dashboard.html', club=club)

@app.route('/verify-leader', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def verify_leader():
    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email', '').strip()
        club_name = data.get('club_name', '').strip()

        if not email or not club_name:
            return jsonify({'error': 'Email and club name are required'}), 400

        is_verified = airtable_service.verify_club_leader(email, club_name)

        if is_verified:
            session['leader_verification'] = {
                'email': email,
                'club_name': club_name,
                'verified': True,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            return jsonify({'success': True, 'message': 'Leader verification successful!'})
        else:
            return jsonify({'error': 'Club leader verification failed. Please check your email and club name.'}), 400

    return render_template('verify_leader.html')

@app.route('/complete-leader-signup', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def complete_leader_signup():
    leader_verification = session.get('leader_verification')

    if not leader_verification or not leader_verification.get('verified'):
        flash('Invalid verification session. Please start over.', 'error')
        return redirect(url_for('dashboard'))

    if 'timestamp' in leader_verification:
        verification_time = datetime.fromisoformat(leader_verification['timestamp'])
        if (datetime.now(timezone.utc) - verification_time).total_seconds() > 3600:
            session.pop('leader_verification', None)
            flash('Verification expired. Please start over.', 'error')
            return redirect(url_for('verify_leader'))

    try:
        signup_data = session.get('signup_data')

        if signup_data:
            user = User(
                username=signup_data['username'],
                email=signup_data['email'],
                first_name=signup_data['first_name'],
                last_name=signup_data['last_name'],
                birthday=datetime.strptime(signup_data['birthday'], '%Y-%m-%d').date() if signup_data['birthday'] else None
            )
            user.set_password(signup_data['password'])
            db.session.add(user)
            db.session.flush()

            session.pop('signup_data', None)
            flash_message = f'Account created successfully! Welcome to {leader_verification["club_name"]}!'
            redirect_route = 'login'
        else:
            user = get_current_user()
            flash_message = f'Club created successfully! Welcome to {leader_verification["club_name"]}!'
            redirect_route = 'club_dashboard'

        club = Club(
            name=leader_verification['club_name'],
            description=f"Official {leader_verification['club_name']} Hack Club",
            leader_id=user.id
        )
        club.generate_join_code()
        db.session.add(club)
        db.session.commit()

        session.pop('leader_verification', None)
        flash(flash_message, 'success')

        if redirect_route == 'club_dashboard':
            return redirect(url_for('club_dashboard', club_id=club.id))
        else:
            return redirect(url_for(redirect_route))

    except Exception as e:
        db.session.rollback()
        flash('Database error. Please try again later.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/join-club')
def join_club_redirect():
    join_code = request.args.get('code')
    if not join_code:
        flash('Invalid join code', 'error')
        return redirect(url_for('dashboard'))

    if is_authenticated():
        current_user = get_current_user()
        club = Club.query.filter_by(join_code=join_code).first()
        if not club:
            flash('Invalid join code', 'error')
            return redirect(url_for('dashboard'))

        # Check if user is already the leader
        if club.leader_id == current_user.id:
            flash(f"You are the leader of {club.name}", 'info')
            return redirect(url_for('club_dashboard', club_id=club.id))

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

# Slack OAuth Routes
@app.route('/auth/slack')
@limiter.limit("20 per minute")
def slack_login():
    if not SLACK_CLIENT_ID or not SLACK_CLIENT_SECRET:
        flash('Slack OAuth is not configured', 'error')
        return redirect(url_for('login'))

    redirect_uri = url_for('slack_callback', _external=True, _scheme='https')
    auth_url = slack_oauth_service.get_auth_url(redirect_uri)
    return redirect(auth_url)

@app.route('/auth/slack/callback')
@limiter.limit("20 per minute")
def slack_callback():
    stored_state = session.get('oauth_state')
    received_state = request.args.get('state')

    if not stored_state or received_state != stored_state:
        session.clear()
        flash('Invalid OAuth state parameter. Please try again.', 'error')
        return redirect(url_for('login'))

    session.pop('oauth_state', None)

    code = request.args.get('code')
    if not code:
        error = request.args.get('error', 'Unknown error')
        flash(f'Slack authorization failed: {error}', 'error')
        return redirect(url_for('login'))

    redirect_uri = url_for('slack_callback', _external=True, _scheme='https')
    token_data = slack_oauth_service.exchange_code(code, redirect_uri)

    if not token_data.get('ok'):
        error = token_data.get('error', 'Token exchange failed')
        flash(f'Slack authentication failed: {error}', 'error')
        return redirect(url_for('login'))

    user_token = None
    if 'authed_user' in token_data:
        user_token = token_data['authed_user'].get('access_token')

    if not user_token:
        user_token = token_data.get('access_token')

    if not user_token:
        flash('Failed to get user access token from Slack', 'error')
        return redirect(url_for('login'))

    user_info = slack_oauth_service.get_user_info(user_token)
    if not user_info or not user_info.get('ok'):
        if 'authed_user' in token_data:
            slack_user_id = token_data['authed_user']['id']
            user_info = {
                'ok': True,
                'user': {
                    'id': slack_user_id,
                    'name': f"user_{slack_user_id}",
                    'real_name': "",
                    'profile': {}
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

    user = None
    try:
        if slack_user_id:
            user = User.query.filter_by(slack_user_id=slack_user_id).first()

        if not user and email:
            user = User.query.filter_by(email=email).first()
            if user:
                user.slack_user_id = slack_user_id
                db.session.commit()
    except Exception as e:
        try:
            db.session.rollback()
            if slack_user_id:
                user = User.query.filter_by(slack_user_id=slack_user_id).first()
            if not user and email:
                user = User.query.filter_by(email=email).first()
        except Exception as e2:
            flash('Database connection error. Please try again.', 'error')
            return redirect(url_for('login'))

    if user:
        app.logger.info(f"Slack OAuth: User {user.username} (ID: {user.id}) logging in from IP: {request.remote_addr}")
        login_user(user, remember=True)
        app.logger.info(f"Slack OAuth: Session created for user {user.username}: session_id={session.get('user_id')}, logged_in={session.get('logged_in')}")
        flash(f'Welcome back, {user.username}!', 'success')

        # Check for pending join code
        pending_join_code = session.get('pending_join_code')
        if pending_join_code:
            session.pop('pending_join_code', None)
            return redirect(url_for('join_club_redirect') + f'?code={pending_join_code}')

        return redirect(url_for('dashboard'))
    else:
        session.clear()
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
@limiter.limit("10 per minute")
def complete_slack_signup():
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
        password = data.get('password', '').strip()
        is_leader = data.get('is_leader', False)

        if not username or len(username) < 3:
            return jsonify({'error': 'Username must be at least 3 characters long'}), 400

        if not email:
            return jsonify({'error': 'Email is required'}), 400

        if not first_name:
            return jsonify({'error': 'First name is required'}), 400

        if not password or len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters long'}), 400

        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already taken'}), 400

        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already registered'}), 400

        try:
            user = User(
                username=username,
                email=email,
                first_name=first_name,
                last_name=last_name,
                slack_user_id=slack_data['slack_user_id'],
                birthday=datetime.strptime(birthday, '%Y-%m-%d').date() if birthday else None
            )
            user.set_password(password)

            db.session.add(user)
            db.session.flush()

            if is_leader:
                club = Club(
                    name=f"{username}'s Club",
                    description="A new Hack Club - edit your club details in the dashboard",
                    leader_id=user.id
                )
                club.generate_join_code()
                db.session.add(club)

            db.session.commit()

            session.pop('slack_signup_data', None)

            login_user(user, remember=True)

            return jsonify({'success': True, 'message': 'Account created successfully!'})

        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Database error: {str(e)}'}), 500

    return render_template('slack_signup_complete.html', slack_data=slack_data)

@app.route('/account')
@login_required
def account():
    return render_template('account.html')

# API Routes
@app.route('/api/clubs/<int:club_id>/join-code', methods=['POST'])
@login_required
@limiter.limit("50 per hour")
def generate_club_join_code(club_id):
    current_user = get_current_user()
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
@limiter.limit("500 per hour")
def club_posts(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    is_leader = club.leader_id == current_user.id
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

    if not is_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403

    if request.method == 'POST':
        data = request.get_json()
        content = data.get('content')

        if not content:
            return jsonify({'error': 'Content is required'}), 400

        # Sanitize content to prevent XSS
        content = sanitize_string(content, max_length=5000, allow_html=False)

        if not content.strip():
            return jsonify({'error': 'Content cannot be empty after sanitization'}), 400

        post = ClubPost(
            club_id=club_id,
            user_id=current_user.id,
            content=content
        )
        db.session.add(post)
        db.session.commit()

        return jsonify({'message': 'Post created successfully'})

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

@app.route('/api/user/update', methods=['PUT'])
@login_required
@limiter.limit("20 per hour")
def update_user():
    current_user = get_current_user()
    data = request.get_json()

    username = data.get('username')
    email = data.get('email')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    birthday = data.get('birthday')
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    hackatime_api_key = data.get('hackatime_api_key')

    # Validate username
    if username and username != current_user.username:
        valid, result = validate_username(username)
        if not valid:
            return jsonify({'error': result}), 400

        existing_user = User.query.filter_by(username=result).first()
        if existing_user:
            return jsonify({'error': 'Username already taken'}), 400
        current_user.username = result

    # Validate email
    if email and email != current_user.email:
        valid, result = validate_email(email)
        if not valid:
            return jsonify({'error': result}), 400

        existing_user = User.query.filter_by(email=result).first()
        if existing_user:
            return jsonify({'error': 'Email already registered'}), 400
        current_user.email = result

    # Validate names
    if first_name is not None:
        valid, result = validate_name(first_name, "First name")
        if not valid:
            return jsonify({'error': result}), 400
        current_user.first_name = result if result.strip() else None

    if last_name is not None:
        valid, result = validate_name(last_name, "Last name")
        if not valid:
            return jsonify({'error': result}), 400
        current_user.last_name = result if result.strip() else None

    if birthday is not None:
        current_user.birthday = datetime.strptime(birthday, '%Y-%m-%d').date() if birthday else None

    if hackatime_api_key is not None:
        # Sanitize API key
        api_key = sanitize_string(hackatime_api_key, max_length=255)
        current_user.hackatime_api_key = api_key if api_key.strip() else None

    if new_password:
        if not current_password:
            return jsonify({'error': 'Current password required to change password'}), 400
        if not current_user.check_password(current_password):
            return jsonify({'error': 'Current password is incorrect'}), 400
        current_user.set_password(new_password)

    db.session.commit()
    return jsonify({'message': 'Account updated successfully'})

# Admin routes (simplified)
@app.route('/admin')
@login_required
def admin_dashboard():
    current_user = get_current_user()
    if not current_user.is_admin:
        flash('Admin access required', 'error')
        return redirect(url_for('index'))

    total_users = User.query.count()
    total_clubs = Club.query.count()
    total_posts = ClubPost.query.count()
    total_assignments = ClubAssignment.query.count()

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

@app.route('/api/clubs/<int:club_id>/assignments', methods=['GET', 'POST'])
@login_required
@limiter.limit("500 per hour")
def club_assignments(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    is_leader = club.leader_id == current_user.id
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

    if not is_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403

    if request.method == 'POST':
        if not is_leader:
            return jsonify({'error': 'Only club leaders can create assignments'}), 403

        data = request.get_json()
        title = data.get('title')
        description = data.get('description')
        due_date = data.get('due_date')
        for_all_members = data.get('for_all_members', True)

        if not title or not description:
            return jsonify({'error': 'Title and description are required'}), 400

        # Sanitize inputs
        title = sanitize_string(title, max_length=200)
        description = sanitize_string(description, max_length=5000)

        if not title.strip() or not description.strip():
            return jsonify({'error': 'Title and description cannot be empty'}), 400

        assignment = ClubAssignment(
            club_id=club_id,
            title=title,
            description=description,
            due_date=datetime.fromisoformat(due_date) if due_date else None,
            for_all_members=for_all_members
        )
        db.session.add(assignment)
        db.session.commit()

        return jsonify({'message': 'Assignment created successfully'})

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
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    is_leader = club.leader_id == current_user.id
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

    if not is_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403

    if request.method == 'POST':
        if not is_leader:
            return jsonify({'error': 'Only club leaders can schedule meetings'}), 403

        data = request.get_json()
        title = data.get('title')
        description = data.get('description')
        meeting_date = data.get('meeting_date')
        start_time = data.get('start_time')
        end_time = data.get('end_time')
        location = data.get('location')
        meeting_link = data.get('meeting_link')

        if not title or not meeting_date or not start_time:
            return jsonify({'error': 'Title, date, and start time are required'}), 400

        meeting = ClubMeeting(
            club_id=club_id,
            title=title,
            description=description,
            meeting_date=datetime.strptime(meeting_date, '%Y-%m-%d').date(),
            start_time=start_time,
            end_time=end_time,
            location=location,
            meeting_link=meeting_link
        )
        db.session.add(meeting)
        db.session.commit()

        return jsonify({'message': 'Meeting scheduled successfully'})

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
def club_meeting_detail(club_id, meeting_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)
    meeting = ClubMeeting.query.get_or_404(meeting_id)

    if club.leader_id != current_user.id:
        return jsonify({'error': 'Only club leaders can manage meetings'}), 403

    if meeting.club_id != club_id:
        return jsonify({'error': 'Meeting does not belong to this club'}), 404

    if request.method == 'DELETE':
        db.session.delete(meeting)
        db.session.commit()
        return jsonify({'message': 'Meeting deleted successfully'})

    if request.method == 'PUT':
        data = request.get_json()
        meeting.title = data.get('title', meeting.title)
        meeting.description = data.get('description', meeting.description)
        if data.get('meeting_date'):
            meeting.meeting_date = datetime.strptime(data['meeting_date'], '%Y-%m-%d').date()
        meeting.start_time = data.get('start_time', meeting.start_time)
        meeting.end_time = data.get('end_time', meeting.end_time)
        meeting.location = data.get('location', meeting.location)
        meeting.meeting_link = data.get('meeting_link', meeting.meeting_link)

        db.session.commit()
        return jsonify({'message': 'Meeting updated successfully'})

@app.route('/api/clubs/<int:club_id>/projects', methods=['GET'])
@login_required
@limiter.limit("500 per hour")
def club_projects(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    is_leader = club.leader_id == current_user.id
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

    if not is_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403

    projects = ClubProject.query.filter_by(club_id=club_id).order_by(ClubProject.updated_at.desc()).all()
    projects_data = [{
        'id': project.id,
        'name': project.name,
        'description': project.description,
        'url': project.url,
        'github_url': project.github_url,
        'featured': project.featured,
        'created_at': project.created_at.isoformat(),
        'updated_at': project.updated_at.isoformat(),
        'owner': {
            'id': project.user.id,
            'username': project.user.username
        }
    } for project in projects]

    return jsonify({'projects': projects_data})

@app.route('/api/clubs/<int:club_id>/resources', methods=['GET', 'POST'])
@login_required
@limiter.limit("500 per hour")
def club_resources(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    is_leader = club.leader_id == current_user.id
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

    if not is_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403

    if request.method == 'POST':
        if not is_leader:
            return jsonify({'error': 'Only club leaders can add resources'}), 403

        data = request.get_json()
        title = data.get('title')
        url = data.get('url')
        description = data.get('description')
        icon = data.get('icon', 'book')

        if not title or not url:
            return jsonify({'error': 'Title and URL are required'}), 400

        resource = ClubResource(
            club_id=club_id,
            title=title,
            url=url,
            description=description,
            icon=icon
        )
        db.session.add(resource)
        db.session.commit()

        return jsonify({'message': 'Resource added successfully'})

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
def club_resource_detail(club_id, resource_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)
    resource = ClubResource.query.get_or_404(resource_id)

    if club.leader_id != current_user.id:
        return jsonify({'error': 'Only club leaders can manage resources'}), 403

    if resource.club_id != club_id:
        return jsonify({'error': 'Resource does not belong to this club'}), 404

    if request.method == 'DELETE':
        db.session.delete(resource)
        db.session.commit()
        return jsonify({'message': 'Resource deleted successfully'})

    if request.method == 'PUT':
        data = request.get_json()
        resource.title = data.get('title', resource.title)
        resource.url = data.get('url', resource.url)
        resource.description = data.get('description', resource.description)
        resource.icon = data.get('icon', resource.icon)

        db.session.commit()
        return jsonify({'message': 'Resource updated successfully'})

@app.route('/api/clubs/<int:club_id>/members/<int:user_id>', methods=['DELETE'])
@login_required
@limiter.limit("100 per hour")
def remove_club_member(club_id, user_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    if club.leader_id != current_user.id:
        return jsonify({'error': 'Only club leaders can remove members'}), 403

    if user_id == club.leader_id:
        return jsonify({'error': 'Cannot remove club leader'}), 400

    membership = ClubMembership.query.filter_by(club_id=club_id, user_id=user_id).first()
    if not membership:
        return jsonify({'error': 'User is not a member of this club'}), 404

    db.session.delete(membership)
    db.session.commit()

    return jsonify({'success': True, 'message': 'Member removed successfully'})

@app.route('/api/clubs/<int:club_id>/pizza-grants', methods=['POST'])
@login_required
@limiter.limit("10 per hour")
def submit_pizza_grant(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    is_leader = club.leader_id == current_user.id
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

    if not is_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json()
    member_id = data.get('member_id')

    # Only leaders can submit on behalf of others
    if member_id != str(current_user.id) and not is_leader:
        return jsonify({'error': 'You can only submit grants for yourself'}), 403

    # Get member info
    member = User.query.get(member_id)
    if not member:
        return jsonify({'error': 'Member not found'}), 404

    # Prepare submission data for Airtable
    submission_data = {
        'project_name': data.get('project_name', ''),
        'project_hours': data.get('project_hours', '0'),
        'first_name': data.get('first_name', ''),
        'last_name': data.get('last_name', ''),
        'username': member.username,
        'email': data.get('email', ''),
        'birthday': data.get('birthday', ''),
        'project_description': data.get('project_description', ''),
        'github_url': data.get('github_url', ''),
        'live_url': data.get('live_url', ''),
        'learning': data.get('learning', ''),
        'doing_well': data.get('doing_well', ''),
        'improve': data.get('improve', ''),
        'address_1': data.get('address_1', ''),
        'address_2': data.get('address_2', ''),
        'city': data.get('city', ''),
        'state': data.get('state', ''),
        'zip': data.get('zip', ''),
        'country': data.get('country', ''),
        'screenshot_url': data.get('screenshot_url', ''),
        'club_name': club.name,
        'leader_email': club.leader.email
    }

    # Submit to Airtable
    result = airtable_service.log_pizza_grant(submission_data)
    if result:
        return jsonify({'message': 'Pizza grant submitted successfully!'})
    else:
        return jsonify({'error': 'Failed to submit pizza grant. Please try again.'}), 500

@app.route('/api/upload-screenshot', methods=['POST'])
@login_required
@limiter.limit("20 per hour")
def upload_screenshot():
    if 'screenshot' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'}), 400

    file = request.files['screenshot']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400

    if not file.content_type.startswith('image/'):
        return jsonify({'success': False, 'error': 'File must be an image'}), 400

    try:
        # For now, return a placeholder URL since we don't have CDN setup
        # In production, this would upload to Hack Club CDN or another service
        placeholder_url = f"https://cdn.hackclub.com/screenshots/{file.filename}"
        return jsonify({'success': True, 'url': placeholder_url})
    except Exception as e:
        return jsonify({'success': False, 'error': 'Upload failed'}), 500

@app.route('/api/user/<int:user_id>', methods=['GET'])
@login_required
@limiter.limit("100 per hour")
def get_user_info(user_id):
    current_user = get_current_user()

    # Only allow users to access their own info or club leaders to access member info
    if user_id != current_user.id:
        # Check if current user is a leader of any club where this user is a member
        is_leader = False
        led_clubs = Club.query.filter_by(leader_id=current_user.id).all()
        for club in led_clubs:
            membership = ClubMembership.query.filter_by(club_id=club.id, user_id=user_id).first()
            if membership or club.leader_id == user_id:
                is_leader = True
                break

        if not is_leader:
            return jsonify({'error': 'Unauthorized'}), 403

    user = User.query.get_or_404(user_id)

    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'birthday': user.birthday.isoformat() if user.birthday else None
    })

@app.route('/api/hackatime/projects/<int:user_id>', methods=['GET'])
@login_required
@limiter.limit("100 per hour")
def get_hackatime_projects(user_id):
    current_user = get_current_user()

    # Only allow users to access their own data or club leaders to access member data
    if user_id != current_user.id:
        is_leader = False
        led_clubs = Club.query.filter_by(leader_id=current_user.id).all()
        for club in led_clubs:
            membership = ClubMembership.query.filter_by(club_id=club.id, user_id=user_id).first()
            if membership or club.leader_id == user_id:
                is_leader = True
                break

        if not is_leader:
            return jsonify({'error': 'Unauthorized'}), 403

    user = User.query.get_or_404(user_id)

    if not user.hackatime_api_key:
        return jsonify({'error': 'User has not configured Hackatime API key'}), 400

    projects = hackatime_service.get_user_projects(user.hackatime_api_key)

    return jsonify({
        'username': user.username,
        'projects': projects
    })

@app.route('/api/admin/users', methods=['GET'])
@login_required
@limiter.limit("100 per hour")
def admin_get_users():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    users = User.query.all()
    users_data = [{
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'is_admin': user.is_admin,
        'is_suspended': False,  # Add suspended field when implemented
        'created_at': user.created_at.isoformat() if user.created_at else None,
        'last_login': user.last_login.isoformat() if user.last_login else None,
        'clubs_led': len(user.led_clubs),
        'clubs_joined': len(user.club_memberships)
    } for user in users]

    return jsonify({'users': users_data})

@app.route('/api/admin/clubs', methods=['GET'])
@login_required
@limiter.limit("100 per hour")
def admin_get_clubs():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    clubs = Club.query.all()
    clubs_data = [{
        'id': club.id,
        'name': club.name,
        'description': club.description,
        'location': club.location,
        'leader': club.leader.username,
        'leader_email': club.leader.email,
        'member_count': len(club.members) + 1,  # +1 for leader
        'balance': float(club.balance),
        'created_at': club.created_at.isoformat() if club.created_at else None,
        'join_code': club.join_code
    } for club in clubs]

    return jsonify({'clubs': clubs_data})

@app.route('/api/admin/administrators', methods=['GET'])
@login_required
@limiter.limit("100 per hour")
def admin_get_administrators():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    admins = User.query.filter_by(is_admin=True).all()
    admins_data = [{
        'id': admin.id,
        'username': admin.username,
        'email': admin.email,
        'is_admin': admin.is_admin,
        'is_super_admin': admin.email == 'ethan@hackclub.com',  # Super admin check
        'is_suspended': False,  # Add suspended field when implemented
        'created_at': admin.created_at.isoformat() if admin.created_at else None,
        'last_login': admin.last_login.isoformat() if admin.last_login else None,
        'clubs_led': len(admin.led_clubs)
    } for admin in admins]

    return jsonify({'admins': admins_data})

@app.route('/api/admin/users/<int:user_id>', methods=['PUT', 'DELETE'])
@login_required
@limiter.limit("50 per hour")
def admin_manage_user(user_id):
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    user = User.query.get_or_404(user_id)

    if request.method == 'DELETE':
        try:
            # Don't allow deleting super admin
            if user.email == 'ethan@hackclub.com':
                return jsonify({'error': 'Cannot delete super admin'}), 400

            # Delete related data in correct order to avoid foreign key violations
            # Delete club assignments for clubs led by this user
            led_clubs = Club.query.filter_by(leader_id=user_id).all()
            for club in led_clubs:
                ClubAssignment.query.filter_by(club_id=club.id).delete()
                ClubPost.query.filter_by(club_id=club.id).delete()
                ClubMeeting.query.filter_by(club_id=club.id).delete()
                ClubResource.query.filter_by(club_id=club.id).delete()
                ClubProject.query.filter_by(club_id=club.id).delete()
                ClubMembership.query.filter_by(club_id=club.id).delete()
                db.session.delete(club)

            # Delete user's own posts, projects, etc.
            ClubPost.query.filter_by(user_id=user_id).delete()
            ClubProject.query.filter_by(user_id=user_id).delete()

            # Delete user's memberships
            ClubMembership.query.filter_by(user_id=user_id).delete()

            # Finally delete the user
            db.session.delete(user)
            db.session.commit()

            app.logger.info(f"Admin {current_user.username} deleted user {user.username} (ID: {user_id})")
            return jsonify({'message': 'User deleted successfully'})

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error deleting user {user_id}: {str(e)}")
            return jsonify({'error': 'Failed to delete user due to database constraints'}), 500

    if request.method == 'PUT':
        try:
            data = request.get_json()

            if 'username' in data:
                valid, result = validate_username(data['username'])
                if not valid:
                    return jsonify({'error': result}), 400

                existing_user = User.query.filter_by(username=result).first()
                if existing_user and existing_user.id != user_id:
                    return jsonify({'error': 'Username already taken'}), 400
                user.username = result

            if 'email' in data:
                valid, result = validate_email(data['email'])
                if not valid:
                    return jsonify({'error': result}), 400

                existing_user = User.query.filter_by(email=result).first()
                if existing_user and existing_user.id != user_id:
                    return jsonify({'error': 'Email already registered'}), 400
                user.email = result

            if 'is_admin' in data:
                # Don't allow removing super admin privileges
                if user.email == 'ethan@hackclub.com' and not data['is_admin']:
                    return jsonify({'error': 'Cannot remove super admin privileges'}), 400
                user.is_admin = bool(data['is_admin'])

            db.session.commit()
            return jsonify({'message': 'User updated successfully'})

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error updating user {user_id}: {str(e)}")
            return jsonify({'error': 'Failed to update user'}), 500

@app.route('/api/admin/clubs/<int:club_id>', methods=['PUT', 'DELETE'])
@login_required
@limiter.limit("50 per hour")
def admin_manage_club(club_id):
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    club = Club.query.get_or_404(club_id)

    if request.method == 'DELETE':
        # Delete all memberships first
        ClubMembership.query.filter_by(club_id=club_id).delete()

        # Delete all related data
        ClubPost.query.filter_by(club_id=club_id).delete()
        ClubAssignment.query.filter_by(club_id=club_id).delete()
        ClubMeeting.query.filter_by(club_id=club_id).delete()
        ClubResource.query.filter_by(club_id=club_id).delete()
        ClubProject.query.filter_by(club_id=club_id).delete()

        db.session.delete(club)
        db.session.commit()
        return jsonify({'message': 'Club deleted successfully'})

    if request.method == 'PUT':
        data = request.get_json()

        if 'name' in data:
            club.name = data['name']
        if 'description' in data:
            club.description = data['description']
        if 'location' in data:
            club.location = data['location']
        if 'balance' in data:
            club.balance = data['balance']

        db.session.commit()
        return jsonify({'message': 'Club updated successfully'})

@app.route('/api/admin/administrators', methods=['POST'])
@login_required
@limiter.limit("20 per hour")
def admin_add_administrator():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    data = request.get_json()
    email = data.get('email', '').strip().lower()

    if not email:
        return jsonify({'error': 'Email is required'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    if user.is_admin:
        return jsonify({'error': 'User is already an administrator'}), 400

    user.is_admin = True
    db.session.commit()

    return jsonify({'message': 'Administrator added successfully'})

@app.route('/api/admin/administrators/<int:admin_id>', methods=['DELETE'])
@login_required
@limiter.limit("20 per hour")
def admin_remove_administrator(admin_id):
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    admin = User.query.get_or_404(admin_id)

    # Don't allow removing super admin
    if admin.email == 'ethan@hackclub.com':
        return jsonify({'error': 'Cannot remove super admin privileges'}), 400

    admin.is_admin = False
    db.session.commit()

    return jsonify({'message': 'Administrator privileges removed successfully'})

@app.route('/api/admin/login-as-user/<int:user_id>', methods=['POST'])
@login_required
@limiter.limit("10 per hour")
def admin_login_as_user(user_id):
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    user = User.query.get_or_404(user_id)

    # Don't allow logging in as super admin
    if user.email == 'ethan@hackclub.com':
        return jsonify({'error': 'Cannot login as super admin'}), 400

    # Log out current user and log in as the target user
    logout_user()
    login_user(user, remember=False)

    app.logger.info(f"Admin logged in as user {user.username} (ID: {user.id})")

    return jsonify({'message': f'Successfully logged in as {user.username}'})

@app.route('/api/admin/reset-password/<int:user_id>', methods=['POST'])
@login_required
@limiter.limit("10 per hour")
def admin_reset_password(user_id):
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    user = User.query.get_or_404(user_id)
    data = request.get_json()
    new_password = data.get('new_password')

    if not new_password or len(new_password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters long'}), 400

    # Don't allow resetting super admin password
    if user.email == 'ethan@hackclub.com':
        return jsonify({'error': 'Cannot reset super admin password'}), 400

    user.set_password(new_password)
    db.session.commit()

    app.logger.info(f"Admin reset password for user {user.username} (ID: {user.id})")

    return jsonify({'message': 'Password reset successfully'})

# API Key Management
@app.route('/api/admin/api-keys', methods=['GET'])
@app.route('/api/admin/apikeys', methods=['GET'])
@login_required
@limiter.limit("100 per hour")
def admin_get_api_keys():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    api_keys = APIKey.query.all()
    api_keys_data = [{
        'id': key.id,
        'name': key.name,
        'description': key.description,
        'user': key.user.username,
        'user_email': key.user.email,
        'scopes': key.get_scopes(),
        'is_active': key.is_active,
        'rate_limit': key.rate_limit,
        'created_at': key.created_at.isoformat() if key.created_at else None,
        'last_used_at': key.last_used_at.isoformat() if key.last_used_at else None
    } for key in api_keys]

    return jsonify({'api_keys': api_keys_data})

@app.route('/api/admin/api-keys', methods=['POST'])
@app.route('/api/admin/apikeys', methods=['POST'])
@login_required
@limiter.limit("20 per hour")
def admin_create_api_key():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    data = request.get_json()
    name = data.get('name', '').strip()
    description = data.get('description', '').strip()
    user_email = data.get('user_email', current_user.email).strip()
    rate_limit = data.get('rate_limit', 1000)
    scopes = data.get('scopes', [])

    if not name:
        return jsonify({'error': 'Name is required'}), 400

    if not scopes:
        return jsonify({'error': 'At least one scope is required'}), 400

    user = User.query.filter_by(email=user_email).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Validate scopes - map frontend values to backend values
    scope_mapping = {
        'read:clubs': 'clubs:read',
        'write:clubs': 'clubs:write', 
        'read:users': 'users:read',
        'write:users': 'users:write',
        'clubs:read': 'clubs:read',
        'clubs:write': 'clubs:write',
        'users:read': 'users:read',
        'projects:read': 'projects:read',
        'assignments:read': 'assignments:read',
        'meetings:read': 'meetings:read',
        'analytics:read': 'analytics:read'
    }
    
    # Convert scopes using mapping
    converted_scopes = []
    for scope in scopes:
        if scope in scope_mapping:
            converted_scopes.append(scope_mapping[scope])
        else:
            return jsonify({'error': f'Invalid scope: {scope}'}), 400

    api_key = APIKey(
        name=name,
        description=description,
        user_id=user.id,
        rate_limit=rate_limit
    )
    api_key.generate_key()
    api_key.set_scopes(converted_scopes)

    db.session.add(api_key)
    db.session.commit()

    return jsonify({
        'message': 'API key created successfully',
        'api_key': api_key.key
    })

@app.route('/api/admin/api-keys/<int:key_id>', methods=['PUT', 'DELETE'])
@login_required
@limiter.limit("50 per hour")
def admin_manage_api_key(key_id):
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    api_key = APIKey.query.get_or_404(key_id)

    if request.method == 'DELETE':
        db.session.delete(api_key)
        db.session.commit()
        return jsonify({'message': 'API key deleted successfully'})

    if request.method == 'PUT':
        data = request.get_json()
        
        if 'name' in data:
            api_key.name = data['name']
        if 'description' in data:
            api_key.description = data['description']
        if 'is_active' in data:
            api_key.is_active = bool(data['is_active'])
        if 'rate_limit' in data:
            api_key.rate_limit = int(data['rate_limit'])
        if 'scopes' in data:
            api_key.set_scopes(data['scopes'])

        db.session.commit()
        return jsonify({'message': 'API key updated successfully'})

# OAuth Application Management
@app.route('/api/admin/oauth-applications', methods=['GET'])
@app.route('/api/admin/oauthapps', methods=['GET'])
@login_required
@limiter.limit("100 per hour")
def admin_get_oauth_apps():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    oauth_apps = OAuthApplication.query.all()
    oauth_apps_data = [{
        'id': app.id,
        'name': app.name,
        'description': app.description,
        'client_id': app.client_id,
        'user': app.user.username,
        'user_email': app.user.email,
        'redirect_uris': app.get_redirect_uris(),
        'scopes': app.get_scopes(),
        'is_active': app.is_active,
        'created_at': app.created_at.isoformat() if app.created_at else None
    } for app in oauth_apps]

    return jsonify({'oauth_apps': oauth_apps_data, 'oauth_applications': oauth_apps_data})

@app.route('/api/admin/oauth-applications', methods=['POST'])
@app.route('/api/admin/oauthapps', methods=['POST'])
@login_required
@limiter.limit("20 per hour")
def admin_create_oauth_app():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    data = request.get_json()
    name = data.get('name', '').strip()
    description = data.get('description', '').strip()
    user_email = data.get('user_email', current_user.email).strip()
    redirect_uris = data.get('redirect_uris', [])
    scopes = data.get('scopes', [])

    if not name:
        return jsonify({'error':'Name is required'}), 400

    if not redirect_uris:
        return jsonify({'error': 'At least one redirect URI is required'}), 400

    user = User.query.filter_by(email=user_email).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Validate scopes
    valid_scopes = ['clubs:read', 'clubs:write', 'users:read', 'projects:read', 
                   'assignments:read', 'meetings:read', 'analytics:read']
    invalid_scopes = [s for s in scopes if s not in valid_scopes]
    if invalid_scopes:
        return jsonify({'error': f'Invalid scopes: {", ".join(invalid_scopes)}'}), 400

    oauth_app = OAuthApplication(
        name=name,
        description=description,
        user_id=user.id
    )
    oauth_app.generate_credentials()
    oauth_app.set_redirect_uris(redirect_uris)
    oauth_app.set_scopes(scopes)

    db.session.add(oauth_app)
    db.session.commit()

    return jsonify({
        'message': 'OAuth application created successfully',
        'client_id': oauth_app.client_id,
        'client_secret': oauth_app.client_secret
    })

@app.route('/api/admin/oauth-applications/<int:app_id>', methods=['PUT', 'DELETE'])
@login_required
@limiter.limit("50 per hour")
def admin_manage_oauth_app(app_id):
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    oauth_app = OAuthApplication.query.get_or_404(app_id)

    if request.method == 'DELETE':
        # Delete related tokens and authorization codes
        OAuthToken.query.filter_by(application_id=app_id).delete()
        OAuthAuthorizationCode.query.filter_by(application_id=app_id).delete()

        db.session.delete(oauth_app)
        db.session.commit()
        return jsonify({'message': 'OAuth application deleted successfully'})

    if request.method == 'PUT':
        data = request.get_json()
        
        if 'name' in data:
            oauth_app.name = data['name']
        if 'description' in data:
            oauth_app.description = data['description']
        if 'is_active' in data:
            oauth_app.is_active = bool(data['is_active'])
        if 'redirect_uris' in data:
            oauth_app.set_redirect_uris(data['redirect_uris'])
        if 'scopes' in data:
            oauth_app.set_scopes(data['scopes'])

        db.session.commit()
        return jsonify({'message': 'OAuth application updated successfully'})

# Admin Pizza Grant Management
@app.route('/api/admin/pizza-grants', methods=['GET'])
@login_required
@limiter.limit("100 per hour")
def admin_get_pizza_grants():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    try:
        airtable_service = AirtableService()
        submissions = airtable_service.get_pizza_grant_submissions()
        return jsonify({'submissions': submissions})
    except Exception as e:
        app.logger.error(f"Error fetching pizza grant submissions: {str(e)}")
        return jsonify({'error': 'Failed to fetch submissions'}), 500

@app.route('/api/admin/pizza-grants/review', methods=['POST'])
@login_required
@limiter.limit("50 per hour")
def admin_review_pizza_grant():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body is required'}), 400

    submission_id = data.get('submission_id')
    action = data.get('action')  # 'approve' or 'reject'

    if not submission_id or not action:
        return jsonify({'error': 'submission_id and action are required'}), 400

    if action not in ['approve', 'reject']:
        return jsonify({'error': 'action must be approve or reject'}), 400

    try:
        airtable_service = AirtableService()
        # Update the submission status in Airtable
        result = airtable_service.update_submission_status(submission_id, action)
        
        if result:
            return jsonify({'message': f'Grant {action}d successfully'})
        else:
            return jsonify({'error': f'Failed to {action} grant'}), 500
    except Exception as e:
        app.logger.error(f"Error {action}ing submission {submission_id}: {str(e)}")
        return jsonify({'error': f'Failed to {action} grant'}), 500

@app.route('/api/admin/pizza-grants/<string:submission_id>', methods=['DELETE'])
@login_required
@limiter.limit("50 per hour")
def admin_delete_pizza_grant(submission_id):
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    try:
        airtable_service = AirtableService()
        result = airtable_service.delete_submission(submission_id)
        
        if result:
            return jsonify({'message': 'Submission deleted successfully'})
        else:
            return jsonify({'error': 'Failed to delete submission'}), 500
    except Exception as e:
        app.logger.error(f"Error deleting submission {submission_id}: {str(e)}")
        return jsonify({'error': 'Failed to delete submission'}), 500

# Public API Endpoints
@app.route('/api/v1/clubs', methods=['GET'])
@api_key_required(['clubs:read'])
@limiter.limit("100 per hour")
def api_get_clubs():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '').strip()
    all_clubs = request.args.get('all', '').lower() == 'true'

    query = Club.query

    if search:
        search_term = f"%{search}%"
        query = query.filter(
            db.or_(
                Club.name.ilike(search_term),
                Club.location.ilike(search_term),
                Club.description.ilike(search_term)
            )
        )

    if all_clubs:
        # Return all clubs without pagination
        clubs = query.all()
        clubs_data = []
        for club in clubs:
            clubs_data.append({
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
            })

        return jsonify({
            'clubs': clubs_data,
            'total': len(clubs_data)
        })
    else:
        # Use pagination with no upper limit on per_page
        clubs_paginated = query.paginate(
            page=page, 
            per_page=per_page, 
            error_out=False
        )

        clubs_data = []
        for club in clubs_paginated.items:
            clubs_data.append({
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
            })

        return jsonify({
            'clubs': clubs_data,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': clubs_paginated.total,
                'pages': clubs_paginated.pages,
                'has_next': clubs_paginated.has_next,
                'has_prev': clubs_paginated.has_prev
            }
        })

@app.route('/api/v1/clubs/<int:club_id>', methods=['GET'])
@api_key_required(['clubs:read'])
@limiter.limit("200 per hour")
def api_get_club(club_id):
    club = Club.query.get(club_id)

    if not club:
        # Try Airtable lookup as fallback
        try:
            # Search for club in Airtable
            airtable_url = f'https://api.airtable.com/v0/{airtable_service.base_id}/Club%20Leaders%20%26%20Emails'
            headers = {'Authorization': f'Bearer {airtable_service.api_token}'}
            params = {'filterByFormula': f'{{ID}} = "{club_id}"'}

            response = requests.get(airtable_url, headers=headers, params=params)
            if response.status_code == 200:
                data = response.json()
                records = data.get('records', [])
                if records:
                    record = records[0]
                    fields = record.get('fields', {})
                    return jsonify({
                        'club': {
                            'id': club_id,
                            'name': fields.get('Venue', 'Unknown Club'),
                            'description': 'Club found in Hack Club directory',
                            'location': fields.get('Location', ''),
                            'leader': {
                                'email': fields.get("Current Leaders' Emails", '').split(',')[0].strip()
                            },
                            'member_count': 0,
                            'balance': 0.0,
                            'created_at': None,
                            'source': 'airtable'
                        }
                    })
        except:
            pass

        return jsonify({'error': 'Club not found'}), 404

    club_data = {
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

    return jsonify({'club': club_data})

@app.route('/api/v1/clubs/<int:club_id>/members', methods=['GET'])
@api_key_required(['clubs:read'])
@limiter.limit("200 per hour")
def api_get_club_members(club_id):
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

    # Add members
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
@api_key_required(['projects:read'])
@limiter.limit("200 per hour")
def api_get_club_projects(club_id):
    club = Club.query.get_or_404(club_id)

    projects = ClubProject.query.filter_by(club_id=club_id).order_by(ClubProject.updated_at.desc()).all()

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

@app.route('/api/v1/users/<int:user_id>', methods=['GET'])
@api_key_required(['users:read'])
@limiter.limit("200 per hour")
def api_get_user(user_id):
    user = User.query.get_or_404(user_id)

    user_data = {
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'created_at': user.created_at.isoformat() if user.created_at else None,
        'clubs_led': len(user.led_clubs),
        'clubs_joined': len(user.club_memberships)
    }

    return jsonify({'user': user_data})

@app.route('/api/v1/analytics/overview', methods=['GET'])
@api_key_required(['analytics:read'])
@limiter.limit("100 per hour")
def api_get_analytics():
    total_users = User.query.count()
    total_clubs = Club.query.count()
    total_posts = ClubPost.query.count()
    total_assignments = ClubAssignment.query.count()
    total_meetings = ClubMeeting.query.count()
    total_projects = ClubProject.query.count()

    # Calculate 30-day stats
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
    new_users_30d = User.query.filter(User.created_at >= thirty_days_ago).count()
    new_clubs_30d = Club.query.filter(Club.created_at >= thirty_days_ago).count()
    active_users_30d = User.query.filter(User.last_login >= thirty_days_ago).count()

    analytics_data = {
        'totals': {
            'users': total_users,
            'clubs': total_clubs,
            'posts': total_posts,
            'assignments': total_assignments,
            'meetings': total_meetings,
            'projects': total_projects
        },
        'recent': {
            'new_users_30d': new_users_30d,
            'new_clubs_30d': new_clubs_30d,
            'active_users_30d': active_users_30d
        }
    }

    return jsonify({'analytics': analytics_data})

# OAuth Endpoints
@app.route('/oauth/authorize', methods=['GET', 'POST'])
@limiter.limit("60 per minute")
def oauth_authorize():
    client_id = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')
    response_type = request.args.get('response_type')
    scope = request.args.get('scope', '')
    state = request.args.get('state', '')

    if not client_id or not redirect_uri or response_type != 'code':
        return jsonify({'error': 'Invalid OAuth parameters'}), 400

    oauth_app = OAuthApplication.query.filter_by(client_id=client_id, is_active=True).first()
    if not oauth_app:
        return jsonify({'error': 'Invalid client_id'}), 400

    # Check if redirect_uri is allowed
    if redirect_uri not in oauth_app.get_redirect_uris():
        return jsonify({'error': 'Invalid redirect_uri'}), 400

    # Check if user is authenticated
    if not is_authenticated():
        # Store OAuth params in session and redirect to login
        session['oauth_params'] = {
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'response_type': response_type,
            'scope': scope,
            'state': state
        }
        return redirect(url_for('login'))

    # Validate requested scopes
    requested_scopes = scope.split() if scope else []
    allowed_scopes = oauth_app.get_scopes()
    invalid_scopes = [s for s in requested_scopes if s not in allowed_scopes]
    if invalid_scopes:
        return jsonify({'error': f'Invalid scopes: {", ".join(invalid_scopes)}'}), 400

    current_user = get_current_user()

    # Handle POST request (user approved/denied)
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'deny':
            # Redirect back with error
            error_url = f"{redirect_uri}?error=access_denied"
            if state:
                error_url += f"&state={state}"
            return redirect(error_url)
        
        elif action == 'approve':
            # Generate authorization code
            auth_code = OAuthAuthorizationCode(
                user_id=current_user.id,
                application_id=oauth_app.id,
                redirect_uri=redirect_uri,
                state=state
            )
            auth_code.generate_code()
            auth_code.set_scopes(requested_scopes)

            db.session.add(auth_code)
            db.session.commit()

            # Redirect back to client with authorization code
            redirect_url = f"{redirect_uri}?code={auth_code.code}"
            if state:
                redirect_url += f"&state={state}"

            return redirect(redirect_url)

    # Show consent page
    scope_descriptions = {
        'clubs:read': 'View your clubs and club information',
        'clubs:write': 'Create and manage clubs on your behalf',
        'users:read': 'View your profile information',
        'projects:read': 'View your projects and club projects',
        'assignments:read': 'View club assignments',
        'meetings:read': 'View club meetings',
        'analytics:read': 'View analytics and statistics'
    }

    scopes_with_descriptions = []
    for scope_name in requested_scopes:
        scopes_with_descriptions.append({
            'name': scope_name,
            'description': scope_descriptions.get(scope_name, f'Access {scope_name}')
        })

    return render_template('oauth_consent.html', 
                         app=oauth_app, 
                         scopes=scopes_with_descriptions,
                         client_id=client_id,
                         redirect_uri=redirect_uri,
                         response_type=response_type,
                         scope=scope,
                         state=state)

@app.route('/oauth/token', methods=['POST'])
@limiter.limit("60 per minute")
def oauth_token():
    grant_type = request.form.get('grant_type')
    client_id = request.form.get('client_id')
    client_secret = request.form.get('client_secret')
    code = request.form.get('code')
    redirect_uri = request.form.get('redirect_uri')

    if grant_type != 'authorization_code':
        return jsonify({'error': 'Unsupported grant_type'}), 400

    if not all([client_id, client_secret, code, redirect_uri]):
        return jsonify({'error': 'Missing required parameters'}), 400

    # Verify client credentials
    oauth_app = OAuthApplication.query.filter_by(
        client_id=client_id,
        client_secret=client_secret,
        is_active=True
    ).first()

    if not oauth_app:
        return jsonify({'error': 'Invalid client credentials'}), 401

    # Verify authorization code
    auth_code = OAuthAuthorizationCode.query.filter_by(
        code=code,
        application_id=oauth_app.id,
        redirect_uri=redirect_uri,
        used=False
    ).first()

    if not auth_code:
        return jsonify({'error': 'Invalid authorization code'}), 400

    # Check if code is expired
    if auth_code.expires_at < datetime.now(timezone.utc):
        return jsonify({'error': 'Authorization code expired'}), 400

    # Mark code as used
    auth_code.used = True

    # Generate access token
    oauth_token = OAuthToken(
        user_id=auth_code.user_id,
        application_id=oauth_app.id
    )
    oauth_token.generate_tokens()
    oauth_token.set_scopes(auth_code.get_scopes())

    db.session.add(oauth_token)
    db.session.commit()

    return jsonify({
        'access_token': oauth_token.access_token,
        'token_type': 'Bearer',
        'expires_in': 3600,
        'refresh_token': oauth_token.refresh_token,
        'scope': ' '.join(oauth_token.get_scopes())
    })

@app.route('/oauth/user', methods=['GET'])
@oauth_required()
@limiter.limit("200 per hour")
def oauth_user():
    user = request.oauth_user

    user_data = {
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name
    }

    return jsonify({'user': user_data})

@app.route('/pizza-order/<int:club_id>')
@login_required
def pizza_order(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)
    
    # Check if user is a member or leader of the club
    is_leader = club.leader_id == current_user.id
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()
    
    if not is_leader and not is_member:
        flash('You are not a member of this club', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('pizza_order.html', club=club)

@app.route('/api/clubs/<int:club_id>/pizza-order', methods=['POST'])
@login_required
@limiter.limit("10 per hour")
def submit_pizza_order(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)
    
    # Check if user is a member or leader of the club
    is_leader = club.leader_id == current_user.id
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()
    
    if not is_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    grant_amount = data.get('grant_amount')
    club_address = data.get('club_address')
    contact_email = data.get('contact_email')
    
    if not grant_amount or not club_address or not contact_email:
        return jsonify({'error': 'All fields are required'}), 400
    
    # Check if club has sufficient balance
    if float(grant_amount) > float(club.balance):
        return jsonify({'error': 'Insufficient club balance'}), 400
    
    # Generate order ID
    order_id = f"PO-{club.id}-{int(time.time())}"
    
    # Submit to Airtable
    grant_data = {
        'club_name': club.name,
        'contact_email': contact_email,
        'grant_amount': grant_amount,
        'club_address': club_address,
        'order_id': order_id
    }
    
    result = airtable_service.submit_pizza_grant(grant_data)
    
    if result:
        # Deduct amount from club balance
        club.balance = float(club.balance) - float(grant_amount)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Pizza order submitted successfully!',
            'order_id': order_id
        })
    else:
        return jsonify({'error': 'Failed to submit pizza order. Please try again.'}), 500

@app.route('/api/docs')
def api_documentation():
    return render_template('api_docs.html')

if __name__ == '__main__':
    import logging

    # Configure logging for production
    if os.getenv('FLASK_ENV') == 'production':
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s %(levelname)s %(name)s %(message)s',
            handlers=[logging.StreamHandler()]
        )
        app.logger.setLevel(logging.INFO)
    else:
        logging.basicConfig(level=logging.DEBUG)
        app.logger.setLevel(logging.DEBUG)

    try:
        with app.app_context():
            db.create_all()

            # Create super admin if doesn't exist
            super_admin = User.query.filter_by(email='ethan@hackclub.com').first()
            if not super_admin:
                super_admin = User(
                    username='ethan',
                    email='ethan@hackclub.com',
                    first_name='Ethan',
                    last_name='Davidson',
                    is_admin=True
                )
                super_admin.set_password('hackclub2024')
                db.session.add(super_admin)
                db.session.commit()
                app.logger.info("Created super admin account: ethan@hackclub.com / hackclub2024")
            else:
                super_admin.is_admin = True
                db.session.commit()
                app.logger.info("Super admin account exists and is active")

    except Exception as e:
        app.logger.error(f"Database setup error: {e}")

    port = int(os.getenv('PORT', 5000))
    app.logger.info(f"Starting server on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)