
import os
import time
import json
import hashlib
import requests
import logging
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
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        birthday = request.form.get('birthday', '')
        is_leader = request.form.get('is_leader') == 'on'

        if not username or len(username) < 3:
            flash('Username must be at least 3 characters long', 'error')
            return render_template('signup.html')

        if not email:
            flash('Email is required', 'error')
            return render_template('signup.html')

        if not password or len(password) < 6:
            flash('Password must be at least 6 characters long', 'error')
            return render_template('signup.html')

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
        is_leader = data.get('is_leader', False)

        if not username or len(username) < 3:
            return jsonify({'error': 'Username must be at least 3 characters long'}), 400

        if not email:
            return jsonify({'error': 'Email is required'}), 400

        if not first_name:
            return jsonify({'error': 'First name is required'}), 400

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
            user.set_password(secrets.token_urlsafe(32))

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

    if username and username != current_user.username:
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({'error': 'Username already taken'}), 400

    if email and email != current_user.email:
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({'error': 'Email already registered'}), 400

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
        # Don't allow deleting super admin
        if user.email == 'ethan@hackclub.com':
            return jsonify({'error': 'Cannot delete super admin'}), 400
        
        # Delete user's memberships first
        ClubMembership.query.filter_by(user_id=user_id).delete()
        
        # Transfer leadership of clubs or delete clubs if needed
        led_clubs = Club.query.filter_by(leader_id=user_id).all()
        for club in led_clubs:
            db.session.delete(club)
        
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'User deleted successfully'})
    
    if request.method == 'PUT':
        data = request.get_json()
        
        if 'username' in data:
            existing_user = User.query.filter_by(username=data['username']).first()
            if existing_user and existing_user.id != user_id:
                return jsonify({'error': 'Username already taken'}), 400
            user.username = data['username']
        
        if 'email' in data:
            existing_user = User.query.filter_by(email=data['email']).first()
            if existing_user and existing_user.id != user_id:
                return jsonify({'error': 'Email already registered'}), 400
            user.email = data['email']
        
        if 'is_admin' in data:
            # Don't allow removing super admin privileges
            if user.email == 'ethan@hackclub.com' and not data['is_admin']:
                return jsonify({'error': 'Cannot remove super admin privileges'}), 400
            user.is_admin = data['is_admin']
        
        db.session.commit()
        return jsonify({'message': 'User updated successfully'})

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
        return jsonify({'error': 'User not found with this email'}), 404
    
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
    
    # Log the admin action
    app.logger.info(f"Admin {current_user.username} (ID: {current_user.id}) logging in as user {user.username} (ID: {user.id}) from IP: {request.remote_addr}")
    
    # Switch session to the target user
    login_user(user, remember=False)
    
    return jsonify({'message': f'Successfully logged in as {user.username}'})

@app.route('/api/admin/reset-password/<int:user_id>', methods=['POST'])
@login_required
@limiter.limit("10 per hour")
def admin_reset_password(user_id):
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    data = request.get_json()
    new_password = data.get('new_password')
    
    if not new_password or len(new_password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters long'}), 400

    user = User.query.get_or_404(user_id)
    user.set_password(new_password)
    db.session.commit()
    
    # Log the admin action
    app.logger.info(f"Admin {current_user.username} (ID: {current_user.id}) reset password for user {user.username} (ID: {user.id}) from IP: {request.remote_addr}")
    
    return jsonify({'message': 'Password reset successfully'})

@app.route('/api/clubs/<int:club_id>/info', methods=['GET', 'PUT'])
@login_required
@limiter.limit("200 per hour")
def club_info(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    is_leader = club.leader_id == current_user.id
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

    if not is_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403

    if request.method == 'GET':
        members = []
        # Add leader
        members.append({
            'id': club.leader.id,
            'username': club.leader.username,
            'email': club.leader.email,
            'role': 'leader',
            'joined_at': club.created_at.isoformat() if club.created_at else None
        })
        # Add members
        for membership in club.members:
            members.append({
                'id': membership.user.id,
                'username': membership.user.username,
                'email': membership.user.email,
                'role': membership.role,
                'joined_at': membership.joined_at.isoformat() if membership.joined_at else None
            })

        return jsonify({
            'id': club.id,
            'name': club.name,
            'description': club.description,
            'location': club.location,
            'join_code': club.join_code if is_leader else None,
            'balance': float(club.balance),
            'created_at': club.created_at.isoformat() if club.created_at else None,
            'members': members,
            'is_leader': is_leader
        })

    if request.method == 'PUT':
        if not is_leader:
            return jsonify({'error': 'Only club leaders can update club info'}), 403

        data = request.get_json()
        if 'name' in data:
            club.name = data['name']
        if 'description' in data:
            club.description = data['description']
        if 'location' in data:
            club.location = data['location']

        db.session.commit()
        return jsonify({'message': 'Club updated successfully'})

@app.route('/api/clubs/<int:club_id>/assignments/<int:assignment_id>', methods=['PUT', 'DELETE'])
@login_required
@limiter.limit("200 per hour")
def club_assignment_detail(club_id, assignment_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)
    assignment = ClubAssignment.query.get_or_404(assignment_id)

    if club.leader_id != current_user.id:
        return jsonify({'error': 'Only club leaders can manage assignments'}), 403

    if assignment.club_id != club_id:
        return jsonify({'error': 'Assignment does not belong to this club'}), 404

    if request.method == 'DELETE':
        db.session.delete(assignment)
        db.session.commit()
        return jsonify({'message': 'Assignment deleted successfully'})

    if request.method == 'PUT':
        data = request.get_json()
        assignment.title = data.get('title', assignment.title)
        assignment.description = data.get('description', assignment.description)
        if data.get('due_date'):
            assignment.due_date = datetime.fromisoformat(data['due_date'])
        assignment.for_all_members = data.get('for_all_members', assignment.for_all_members)
        assignment.status = data.get('status', assignment.status)

        db.session.commit()
        return jsonify({'message': 'Assignment updated successfully'})

@app.route('/api/clubs/<int:club_id>/posts/<int:post_id>', methods=['PUT', 'DELETE'])
@login_required
@limiter.limit("200 per hour")
def club_post_detail(club_id, post_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)
    post = ClubPost.query.get_or_404(post_id)

    is_leader = club.leader_id == current_user.id
    is_author = post.user_id == current_user.id

    if not is_leader and not is_author:
        return jsonify({'error': 'Unauthorized'}), 403

    if post.club_id != club_id:
        return jsonify({'error': 'Post does not belong to this club'}), 404

    if request.method == 'DELETE':
        db.session.delete(post)
        db.session.commit()
        return jsonify({'message': 'Post deleted successfully'})

    if request.method == 'PUT':
        if not is_author:
            return jsonify({'error': 'Only the author can edit this post'}), 403
        
        data = request.get_json()
        content = data.get('content')
        if not content:
            return jsonify({'error': 'Content is required'}), 400

        post.content = content
        db.session.commit()
        return jsonify({'message': 'Post updated successfully'})

@app.route('/api/clubs/<int:club_id>/projects', methods=['POST'])
@login_required
@limiter.limit("50 per hour")
def create_club_project(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    is_leader = club.leader_id == current_user.id
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

    if not is_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json()
    name = data.get('name')
    description = data.get('description')
    url = data.get('url')
    github_url = data.get('github_url')

    if not name:
        return jsonify({'error': 'Project name is required'}), 400

    project = ClubProject(
        club_id=club_id,
        user_id=current_user.id,
        name=name,
        description=description,
        url=url,
        github_url=github_url
    )
    db.session.add(project)
    db.session.commit()

    return jsonify({'message': 'Project created successfully'})

@app.route('/api/clubs/<int:club_id>/projects/<int:project_id>', methods=['PUT', 'DELETE'])
@login_required
@limiter.limit("200 per hour")
def club_project_detail(club_id, project_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)
    project = ClubProject.query.get_or_404(project_id)

    is_leader = club.leader_id == current_user.id
    is_author = project.user_id == current_user.id

    if not is_leader and not is_author:
        return jsonify({'error': 'Unauthorized'}), 403

    if project.club_id != club_id:
        return jsonify({'error': 'Project does not belong to this club'}), 404

    if request.method == 'DELETE':
        db.session.delete(project)
        db.session.commit()
        return jsonify({'message': 'Project deleted successfully'})

    if request.method == 'PUT':
        data = request.get_json()
        project.name = data.get('name', project.name)
        project.description = data.get('description', project.description)
        project.url = data.get('url', project.url)
        project.github_url = data.get('github_url', project.github_url)
        
        if is_leader and 'featured' in data:
            project.featured = data['featured']

        project.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        return jsonify({'message': 'Project updated successfully'})

@app.route('/api/clubs/<int:club_id>/settings', methods=['PUT'])
@login_required
@limiter.limit("50 per hour")
def update_club_settings(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)
    
    # Only club leaders can update settings
    if club.leader_id != current_user.id:
        return jsonify({'error': 'Only club leaders can update settings'}), 403
    
    try:
        data = request.get_json()
        
        # Update club information
        if 'name' in data:
            club.name = data['name'].strip()
        if 'description' in data:
            club.description = data['description'].strip() if data['description'] else None
        if 'location' in data:
            club.location = data['location'].strip() if data['location'] else None
        
        club.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        
        return jsonify({'message': 'Club settings updated successfully'})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating club settings: {str(e)}")
        return jsonify({'error': 'Failed to update club settings'}), 500

@app.route('/api/clubs/<int:club_id>/pizza-grants', methods=['GET'])
@login_required
@limiter.limit("100 per hour")
def get_club_pizza_grants(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    is_leader = club.leader_id == current_user.id
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

    if not is_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        all_submissions = airtable_service.get_pizza_grant_submissions()
        # Filter submissions for this club only
        club_submissions = [sub for sub in all_submissions if sub.get('club_name') == club.name]
        return jsonify({'submissions': club_submissions})
    except Exception as e:
        logger.error(f"Error fetching club pizza grant submissions: {str(e)}")
        return jsonify({'error': 'Failed to fetch submissions from Airtable'}), 500

@app.route('/api/admin/pizza-grants', methods=['GET'])
@login_required
@limiter.limit("100 per hour")
def admin_get_pizza_grants():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    try:
        submissions = airtable_service.get_pizza_grant_submissions()
        return jsonify({'submissions': submissions})
    except Exception as e:
        logger.error(f"Error fetching pizza grant submissions: {str(e)}")
        return jsonify({'error': 'Failed to fetch submissions from Airtable'}), 500

@app.route('/api/admin/pizza-grants/<submission_id>', methods=['DELETE'])
@login_required
@limiter.limit("20 per hour")
def admin_delete_pizza_grant(submission_id):
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    try:
        # Delete from Airtable
        url = f"{airtable_service.base_url}/{submission_id}"
        response = requests.delete(url, headers=airtable_service.headers)
        
        if response.status_code == 200:
            return jsonify({'message': 'Submission deleted successfully'})
        else:
            return jsonify({'error': 'Failed to delete submission from Airtable'}), 500
            
    except Exception as e:
        logger.error(f"Error deleting pizza grant submission: {str(e)}")
        return jsonify({'error': 'Failed to delete submission'}), 500

@app.route('/api/admin/pizza-grants/review', methods=['POST'])
@login_required
@limiter.limit("50 per hour")
def admin_review_pizza_grant():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    data = request.get_json()
    submission_id = data.get('submission_id')
    action = data.get('action')  # 'approve' or 'reject'

    if not submission_id or action not in ['approve', 'reject']:
        return jsonify({'error': 'Invalid submission ID or action'}), 400

    try:
        # Update submission status in Airtable
        success = airtable_service.update_submission_status(submission_id, action)
        
        if not success:
            return jsonify({'error': 'Failed to update submission status'}), 500

        if action == 'approve':
            # Get submission details to update club balance
            submission = airtable_service.get_submission_by_id(submission_id)
            if submission and submission.get('grant_amount'):
                grant_amount = float(submission['grant_amount'].replace('$', ''))
                club_name = submission.get('club_name')
                
                if club_name:
                    # Find the club and update balance
                    club = Club.query.filter_by(name=club_name).first()
                    if club:
                        from decimal import Decimal
                        club.balance += Decimal(str(grant_amount))
                        db.session.commit()
                        logger.info(f"Updated club {club_name} balance by ${grant_amount}")
                    else:
                        logger.warning(f"Club {club_name} not found for grant approval")

        return jsonify({'message': f'Grant {action}d successfully'})
        
    except Exception as e:
        logger.error(f"Error processing pizza grant review: {str(e)}")
        return jsonify({'error': f'Failed to {action} grant'}), 500

@app.route('/pizza-order/<int:club_id>')
@login_required
def pizza_order(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)
    
    # Check if user is club leader or member
    is_leader = club.leader_id == current_user.id
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()
    
    if not is_leader and not is_member:
        flash('You are not authorized to order pizza for this club', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('pizza_order.html', club=club)

@app.route('/api/clubs/<int:club_id>/pizza-order', methods=['POST'])
@login_required
@limiter.limit("10 per hour")
def submit_pizza_order(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)
    
    # Check if user is club leader or member
    is_leader = club.leader_id == current_user.id
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()
    
    if not is_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    grant_amount = float(data.get('grant_amount', 0))
    club_address = data.get('club_address', '').strip()
    contact_email = data.get('contact_email', '').strip()
    
    # Validate inputs
    if grant_amount <= 0:
        return jsonify({'error': 'Grant amount must be greater than 0'}), 400
    
    if grant_amount > float(club.balance):
        return jsonify({'error': 'Grant amount cannot exceed club balance'}), 400
    
    if not club_address or not contact_email:
        return jsonify({'error': 'Club address and contact email are required'}), 400
    
    try:
        # Generate a unique order ID
        import uuid
        order_id = str(uuid.uuid4())[:8].upper()
        
        # Submit to Grants table in Airtable
        result = airtable_service.submit_pizza_grant({
            'club_name': club.name,
            'contact_email': contact_email,
            'grant_amount': grant_amount,
            'club_address': club_address,
            'order_id': order_id
        })
        
        if result:
            # Deduct amount from club balance
            from decimal import Decimal
            club.balance -= Decimal(str(grant_amount))
            db.session.commit()
            
            app.logger.info(f"Pizza order submitted for club {club.name}: ${grant_amount}, Order ID: {order_id}")
            
            return jsonify({
                'success': True,
                'message': 'Pizza order submitted successfully',
                'order_id': order_id,
                'remaining_balance': float(club.balance)
            })
        else:
            app.logger.error(f"Failed to submit pizza order to Airtable for club {club.name}")
            return jsonify({'error': 'Failed to submit order to grants system. Please try again or contact support.'}), 500
            
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error submitting pizza order: {str(e)}")
        return jsonify({'error': 'An error occurred while processing your order'}), 500

@app.route('/api/clubs/<int:club_id>/balance', methods=['GET'])
@login_required
@limiter.limit("100 per hour")
def get_club_balance(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)
    
    # Check if user is club leader or member
    is_leader = club.leader_id == current_user.id
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()
    
    if not is_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403
    
    return jsonify({
        'balance': float(club.balance),
        'club_name': club.name
    })

@app.route('/api/admin/stats', methods=['GET'])
@login_required
@limiter.limit("100 per hour")
def admin_get_stats():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    # Basic stats
    total_users = User.query.count()
    total_clubs = Club.query.count()
    total_posts = ClubPost.query.count()
    total_assignments = ClubAssignment.query.count()
    total_meetings = ClubMeeting.query.count()
    total_projects = ClubProject.query.count()
    total_resources = ClubResource.query.count()
    
    # Growth stats (last 30 days)
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
    new_users_30d = User.query.filter(User.created_at >= thirty_days_ago).count()
    new_clubs_30d = Club.query.filter(Club.created_at >= thirty_days_ago).count()
    
    # Active users (logged in within last 30 days)
    active_users = User.query.filter(User.last_login >= thirty_days_ago).count()
    
    return jsonify({
        'total_users': total_users,
        'total_clubs': total_clubs,
        'total_posts': total_posts,
        'total_assignments': total_assignments,
        'total_meetings': total_meetings,
        'total_projects': total_projects,
        'total_resources': total_resources,
        'new_users_30d': new_users_30d,
        'new_clubs_30d': new_clubs_30d,
        'active_users': active_users
    })

@app.route('/api/user/delete-account', methods=['DELETE'])
@login_required
@limiter.limit("5 per hour")
def delete_user_account():
    current_user = get_current_user()
    
    # Don't allow super admin to delete their account
    if current_user.email == 'ethan@hackclub.com':
        return jsonify({'error': 'Cannot delete super admin account'}), 400
    
    # Transfer or delete clubs led by this user
    led_clubs = Club.query.filter_by(leader_id=current_user.id).all()
    for club in led_clubs:
        # Find another admin member to transfer leadership to
        admin_member = ClubMembership.query.filter_by(club_id=club.id, role='co-leader').first()
        if admin_member:
            club.leader_id = admin_member.user_id
        else:
            # Delete the club if no co-leader exists
            db.session.delete(club)
    
    # Delete user's memberships
    ClubMembership.query.filter_by(user_id=current_user.id).delete()
    
    # Delete user's posts, assignments, meetings, etc.
    ClubPost.query.filter_by(user_id=current_user.id).delete()
    ClubProject.query.filter_by(user_id=current_user.id).delete()
    
    # Delete the user
    db.session.delete(current_user)
    db.session.commit()
    
    # Log out the user
    logout_user()
    
    return jsonify({'message': 'Account deleted successfully'})

@app.route('/settings')
@login_required
def settings():
    return render_template('account.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/help')
def help_page():
    return render_template('help.html')

@app.route('/api/search', methods=['GET'])
@login_required
@limiter.limit("200 per hour")
def search():
    current_user = get_current_user()
    query = request.args.get('q', '').strip()
    
    if not query or len(query) < 2:
        return jsonify({'results': []})
    
    # Get user's clubs
    user_club_ids = []
    led_clubs = Club.query.filter_by(leader_id=current_user.id).all()
    user_club_ids.extend([club.id for club in led_clubs])
    
    memberships = ClubMembership.query.filter_by(user_id=current_user.id).all()
    user_club_ids.extend([membership.club_id for membership in memberships])
    
    results = {
        'clubs': [],
        'users': [],
        'posts': [],
        'projects': []
    }
    
    # Search clubs user has access to
    clubs = Club.query.filter(
        Club.id.in_(user_club_ids),
        Club.name.ilike(f'%{query}%')
    ).limit(10).all()
    
    results['clubs'] = [{
        'id': club.id,
        'name': club.name,
        'description': club.description,
        'type': 'club'
    } for club in clubs]
    
    # Search users in user's clubs
    if user_club_ids:
        user_ids = set()
        for club_id in user_club_ids:
            club = Club.query.get(club_id)
            if club:
                user_ids.add(club.leader_id)
                for membership in club.members:
                    user_ids.add(membership.user_id)
        
        users = User.query.filter(
            User.id.in_(user_ids),
            User.username.ilike(f'%{query}%')
        ).limit(10).all()
        
        results['users'] = [{
            'id': user.id,
            'username': user.username,
            'type': 'user'
        } for user in users]
    
    # Search posts in user's clubs
    posts = ClubPost.query.filter(
        ClubPost.club_id.in_(user_club_ids),
        ClubPost.content.ilike(f'%{query}%')
    ).limit(10).all()
    
    results['posts'] = [{
        'id': post.id,
        'content': post.content[:100] + '...' if len(post.content) > 100 else post.content,
        'club_name': post.club.name,
        'author': post.user.username,
        'type': 'post'
    } for post in posts]
    
    # Search projects in user's clubs
    projects = ClubProject.query.filter(
        ClubProject.club_id.in_(user_club_ids),
        ClubProject.name.ilike(f'%{query}%')
    ).limit(10).all()
    
    results['projects'] = [{
        'id': project.id,
        'name': project.name,
        'description': project.description,
        'club_name': project.club.name,
        'author': project.user.username,
        'type': 'project'
    } for project in projects]
    
    return jsonify({'results': results})

@app.errorhandler(404)
def not_found(error):
    if request.is_json:
        return jsonify({'error': 'Not found'}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    if request.is_json:
        return jsonify({'error': 'Internal server error'}), 500
    return render_template('500.html'), 500

@app.errorhandler(403)
def forbidden(error):
    if request.is_json:
        return jsonify({'error': 'Forbidden'}), 403
    return render_template('403.html'), 403

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
