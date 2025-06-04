import os
import time
import json
import hashlib
import requests
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

def get_database_url():
    url = os.getenv('DATABASE_URL')
    if url and url.startswith('postgres://'):
        url = url.replace('postgres://', 'postgresql://', 1)
    return url

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(16))
app.config['SQLALCHEMY_DATABASE_URI'] = get_database_url()
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

SLACK_CLIENT_ID = os.getenv('SLACK_CLIENT_ID')
SLACK_CLIENT_SECRET = os.getenv('SLACK_CLIENT_SECRET')
SLACK_SIGNING_SECRET = os.getenv('SLACK_SIGNING_SECRET')

db_available = True

try:
    db = SQLAlchemy(app)
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'

    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=["5000 per hour", "500 per minute"],
        storage_uri="memory://",
        strategy="fixed-window"
    )
except Exception as e:
    print(f"Database initialization failed: {e}")
    db_available = False
    db = None
    login_manager = None
    limiter = None

# Models
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
    remember_token = db.Column(db.String(255), unique=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return not self.is_suspended

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

    def generate_remember_token(self):
        """Generate a secure remember token"""
        self.remember_token = secrets.token_urlsafe(32)
        return self.remember_token

    def verify_remember_token(self, token):
        """Verify a remember token"""
        return self.remember_token == token

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

@login_manager.user_loader
def load_user(user_id):
    if not db_available:
        # When DB is down, try to load from cached session data
        user_data = session.get('user_cache')
        if user_data and user_data.get('id') == int(user_id):
            # Create a temporary user object
            class TempUser:
                def __init__(self, data):
                    self.id = data['id']
                    self.username = data['username']
                    self.email = data['email']
                    self.first_name = data.get('first_name')
                    self.last_name = data.get('last_name')
                    self.is_admin = data.get('is_admin', False)
                    self.is_suspended = data.get('is_suspended', False)

                @property
                def is_authenticated(self):
                    return True

                @property
                def is_active(self):
                    return not self.is_suspended

                @property
                def is_anonymous(self):
                    return False

                def get_id(self):
                    return str(self.id)

            temp_user = TempUser(user_data)
            return temp_user
        return None

    try:
        user = db.session.get(User, int(user_id))
        # If user is found and we have cached data, make sure cache is up to date
        if user:
            session['user_cache'] = {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'is_admin': user.is_admin,
                'is_suspended': user.is_suspended
            }
        return user
    except Exception as e:
        print(f"Error loading user {user_id}: {e}")
        return None

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

    def verify_club_leader(self, email, club_name):
        """Verify if the given email and club name match in the Club Leaders & Emails table"""
        if not self.api_token:
            print("No Airtable API token found")
            return False

        # URL encode the table name for Club Leaders & Emails
        leaders_table_name = urllib.parse.quote('Club Leaders & Emails')
        leaders_url = f'https://api.airtable.com/v0/{self.base_id}/{leaders_table_name}'

        try:
            # Search for records matching the email and club name
            # Using the exact field names from the Airtable table
            params = {
                'filterByFormula': f'AND(FIND("{email}", {{Current Leaders\' Emails}}) > 0, FIND("{club_name}", {{Venue}}) > 0)'
            }

            response = requests.get(leaders_url, headers=self.headers, params=params)

            if response.status_code == 200:
                data = response.json()
                records = data.get('records', [])
                return len(records) > 0  # Return True if any matching records found
            else:
                print(f"Airtable leaders verification error: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            print(f"Error verifying club leader: {str(e)}")
            return False

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
        remember_token = user.generate_remember_token()
        user.last_login = datetime.utcnow()
        db.session.commit()

        login_user(user, remember=True)

        # Cache user data in session for when DB is down
        session['user_cache'] = {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'is_admin': user.is_admin,
            'is_suspended': user.is_suspended
        }

        # Set remember token cookie (5 days)
        resp = redirect(url_for('dashboard'))
        resp.set_cookie('remember_token', remember_token, 
                      max_age=5*24*60*60,  # 5 days
                      secure=False,  # Set to True in production with HTTPS
                      httponly=True,
                      samesite='Lax')

        flash(f'Welcome back, {user.username}!', 'success')
        return resp
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

@app.route('/verify-leader', methods=['GET', 'POST'])
@limiter.limit("50 per minute")
def verify_leader():
    if not db_available:
        flash('Database is currently unavailable. Please try again later.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        data = request.get_json()

        email = data.get('email', '').strip()
        club_name = data.get('club_name', '').strip()

        if not email or not club_name:
            return jsonify({'error': 'Email and club name are required'}), 400

        # Verify with Airtable
        is_verified = airtable_service.verify_club_leader(email, club_name)

        if is_verified:
            # Store verification data in session
            session['leader_verification'] = {
                'email': email,
                'club_name': club_name,
                'verified': True
            }
            return jsonify({'success': True, 'message': 'Leader verification successful!'})
        else:
            return jsonify({'error': 'Club leader verification failed. Please check your email and club name.'}), 400

    return render_template('verify_leader.html')

@app.route('/complete-leader-signup', methods=['GET', 'POST'])
@limiter.limit("50 per minute")
def complete_leader_signup():
    if not db_available:
        flash('Database is currently unavailable. Please try again later.', 'error')
        return redirect(url_for('dashboard'))

    leader_verification = session.get('leader_verification')

    if not leader_verification or not leader_verification.get('verified'):
        flash('Invalid verification session. Please start over.', 'error')
        return redirect(url_for('dashboard'))

    try:
        # Check if this is for an existing user or new signup
        signup_data = session.get('signup_data')

        if signup_data:
            # New user signup flow
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

            # Clear signup session data
            session.pop('signup_data', None)

            flash_message = f'Account created successfully! Welcome to {leader_verification["club_name"]}!'
            redirect_route = 'login'
        else:
            # Existing user creating a club
            user = current_user
            flash_message = f'Club created successfully! Welcome to {leader_verification["club_name"]}!'
            redirect_route = 'club_dashboard'

        # Create the club with the verified club name
        club = Club(
            name=leader_verification['club_name'],
            description=f"Official {leader_verification['club_name']} Hack Club",
            leader_id=user.id
        )
        club.generate_join_code()
        db.session.add(club)

        db.session.commit()

        # Clear verification session data
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

        # Validation
        if not username or len(username) < 3:
            return jsonify({'error': 'Username must be at least 3 characters long'}), 400

        if not email:
            return jsonify({'error': 'Email is required'}),```python
 400

        if not first_name:
            return jsonify({'error': 'First name is required'}), 400

        # Check if username or email is already taken
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already taken'}), 400

        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already registered'}), 400

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
                club = Club(
                    name=f"{username}'s Club",
                    description="A new Hack Club - edit your club details in the dashboard",
                    leader_id=user.id
                )
                club.generate_join_code()
                db.session.add(club)

            db.session.commit()

            # Generate remember token
            remember_token = user.generate_remember_token()

            # Log user in first
            login_user(user, remember=True)

            # Set remember token cookie (5 days)
            resp = redirect(url_for('dashboard'))
            resp.set_cookie('remember_token', remember_token, 
                          max_age=5*24*60*60,  # 5 days
                          secure=False,  # Set to True in production with HTTPS
                          httponly=True,
                          samesite='Lax')

            # Cache user data in session for when DB is down
            session['user_cache'] = {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'is_admin': user.is_admin,
                'is_suspended': user.is_suspended,
                'remember_token': remember_token
            }
            session.permanent = True

            # Clear Slack signup data after successful login
            session.pop('slack_signup_data', None)

            return jsonify({
                'success': True, 
                'message': 'Account created successfully!',
                'remember_token': remember_token
            })

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
        email = request.form.get('email')
        password = request.form.get('password')

        try:
            user = User.query.filter_by(email=email).first()
            if user and user.check_password(password):
                # Generate remember token for persistent login
                remember_token = user.generate_remember_token()
                user.last_login = datetime.utcnow()
                db.session.commit()

                # Generate remember token FIRST before login
                remember_token = user.generate_remember_token()
                user.last_login = datetime.utcnow()
                db.session.commit()

                print(f"DEBUG: Generated remember token for {user.username}")

                # Cache user data in session for when DB is down
                session['user_cache'] = {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'is_admin': user.is_admin,
                    'is_suspended': user.is_suspended,
                    'remember_token': remember_token
                }
                session.permanent = True

                # Login user AFTER setting up session
                login_user(user, remember=True)
                print(f"DEBUG: User {user.username} logged in successfully, is_authenticated: {current_user.is_authenticated}")

                # Set remember token cookie (5 days)
                resp = redirect(url_for('dashboard'))
                resp.set_cookie('remember_token', remember_token, 
                              max_age=5*24*60*60,  # 5 days
                              secure=False,  # Set to True in production with HTTPS
                              httponly=True,
                              samesite='Lax')

                flash(f'Welcome back, {user.username}!', 'success')
                return resp

            flash('Invalid email or password', 'error')
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
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        birthday = request.form.get('birthday')
        is_leader = request.form.get('is_leader') == 'on'

        try:
            if User.query.filter_by(email=email).first():
                flash('Email already registered', 'error')
                return render_template('signup.html')

            if User.query.filter_by(username=username).first():
                flash('Username already taken', 'error')
                return render_template('signup.html')

            # If user wants to be a leader, redirect to verification
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

            user = User(username=username, email=email, first_name=first_name, last_name=last_name, birthday=datetime.strptime(birthday, '%Y-%m-%d').date() if birthday else None)
            user.set_password(password)
            db.session.add(user)
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
def logout():
    # Clear remember token from database if available
    if db_available and current_user.is_authenticated:
        try:
            if hasattr(current_user, 'id'):
                user = User.query.get(current_user.id)
                if user:
                    user.remember_token = None
                    db.session.commit()
        except:
            pass

    # Clear session cache
    session.pop('user_cache', None)

    logout_user()

    # Clear remember token cookie
    resp = redirect(url_for('index'))
    resp.set_cookie('remember_token', '', expires=0)

    flash('You have been logged out.', 'success')
    return resp

@app.before_request
def validate_remember_token():
    """Validate remember token and sync with database when available"""
    # Skip validation for auth routes to avoid conflicts
    auth_routes = ['login', 'logout', 'signup', 'slack_login', 'slack_callback', 
                   'complete_slack_signup', 'verify_leader', 'complete_leader_signup', 'static']

    # Skip for static files and auth routes
    if request.endpoint in auth_routes or (request.endpoint and request.endpoint.startswith('static')):
        return

    print(f"DEBUG: before_request for endpoint: {request.endpoint}, authenticated: {current_user.is_authenticated}")

    remember_token = request.cookies.get('remember_token')

    if db_available and remember_token:
        try:
            # Always check the remember token against the database when it's available
            user = User.query.filter_by(remember_token=remember_token).first()
            if user and not user.is_suspended:
                # If user is not currently authenticated, log them in
                if not current_user.is_authenticated:
                    login_user(user, remember=True)
                    user.last_login = datetime.utcnow()
                    db.session.commit()

                # Always update cached user data when DB is available
                session['user_cache'] = {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'is_admin': user.is_admin,
                    'is_suspended': user.is_suspended,
                    'remember_token': remember_token
                }
                session.permanent = True
            elif user and user.is_suspended:
                # If user is suspended, log them out and clear token
                if current_user.is_authenticated:
                    logout_user()
                session.pop('user_cache', None)
            elif not user:
                # If token is invalid, clear it
                if current_user.is_authenticated:
                    logout_user()
                session.pop('user_cache', None)
        except Exception as e:
            print(f"Error validating remember token: {e}")
            pass
    elif not db_available and remember_token and not current_user.is_authenticated:
        # When DB is down, try to use cached session data
        user_data = session.get('user_cache')
        if user_data:
            # Create a temporary user object from cached data
            class TempUser:
                def __init__(self, data):
                    self.id = data['id']
                    self.username = data['username']
                    self.email = data['email']
                    self.first_name = data.get('first_name')
                    self.last_name = data.get('last_name')
                    self.is_admin = data.get('is_admin', False)
                    self.is_suspended = data.get('is_suspended', False)

                @property
                def is_authenticated(self):
                    return True

                @property
                def is_active(self):
                    return not self.is_suspended

                @property
                def is_anonymous(self):
                    return False

                def get_id(self):
                    return str(self.id)

            temp_user = TempUser(user_data)
            # Set the current user manually for this request
            from flask_login import _login_user
            _login_user(temp_user, remember=True, fresh=False)

@app.route('/dashboard')
@login_required
def dashboard():
    print(f"DEBUG: Dashboard route accessed. User authenticated: {current_user.is_authenticated}")
    if current_user.is_authenticated:
        print(f"DEBUG: Current user: {current_user.username} (ID: {current_user.id})")
    else:
        print("DEBUG: User not authenticated, should be redirected by @login_required")

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
    join_code = request.args.get('code')
    if not join_code:
        flash('Invalid join code', 'error')
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
        content = data.get('content')

        if not content:
            return jsonify({'error': 'Content is required'}), 400

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

        assignment = ClubAssignment(
            club_id=club_id,
            title=data.get('title'),
            description=data.get('description'),
            due_date=datetime.fromisoformat(data.get('due_date')) if data.get('due_date') else None,
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

        meeting = ClubMeeting(
            club_id=club_id,
            title=data.get('title'),
            description=data.get('description'),
            meeting_date=datetime.strptime(data.get('meeting_date'), '%Y-%m-%d').date(),
            start_time=data.get('start_time'),
            end_time=data.get('end_time'),
            location=data.get('location'),
            meeting_link=data.get('meeting_link')
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

            # Handle screenshot upload (for now, we'll just note it was provided)
            screenshot_url = "Screenshot provided" if data.get('screenshot') else ""

            # Submit to Airtable with all required fields
            submission_data = {
                'project_name': data.get('project_name', ''),
                'first_name': data.get('first_name', ''),
                'last_name': data.get('last_name', ''),
                'username': member_user.username,
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
                'club_name': club.name,
                'leader_email': club.leader.email,
                'project_hours': data.get('project_hours', 0),
                'screenshot_url': data.get('screenshot_url', '')
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

    username = data.get('username')
    email = data.get('email')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    birthday = data.get('birthday')
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    hackatime_api_key = data.get('hackatime_api_key')

    # Check if username is taken by another user
    if username and username != current_user.username:
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({'error': 'Username already taken'}), 400

    # Check if email is taken by another user
    if email and email != current_user.email:
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({'error': 'Email already registered'}), 400

    # Update user fields
    if username:
        current_user.username = username
    if email:
        current_user.email = email
    if first_name is not None:
        current_user.first_name = first_name.strip() if first_name.strip() else None
    if last_name is not None:
        current_user.last_name = last_name.strip() if last_name.strip() else None
    if birthday is not None:
        current_user.birthday = datetime.strptime(birthday, '%Y-%m-%d').date() if birthday else None
    if hackatime_api_key is not None:
        current_user.hackatime_api_key = hackatime_api_key if hackatime_api_key.strip() else None

    # Update password if provided
    if new_password:
        if not current_password:
            return jsonify({'error': 'Current password required to change password'}), 400
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

if __name__ == '__main__':
    # Install Flask-Limiter if not available
    try:
        import flask_limiter
    except ImportError:
        print("Installing Flask-Limiter...")
        import subprocess
        subprocess.check_call(['pip', 'install', 'Flask-Limiter'])

    if db_available:
        try:
            with app.app_context():
                db.create_all()

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
                else:
                    # Ensure admin status
                    super_admin.is_admin = True
                    db.session.commit()

        except Exception as e:
            print(f"Database connection failed: {e}")
            print("Starting app without database functionality...")
            db_available = False
    else:
        print("Starting app without database functionality...")

    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)