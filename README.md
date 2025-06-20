
# Hack Club Dashboard

A comprehensive club management platform built for Hack Club communities worldwide. Empower your coding community with smart member management, event organization, and project tracking.

## Features

### 🚀 Core Features
- **Smart Member Management** - Track members, progress, and engagement analytics
- **Event Organization** - Plan hackathons, workshops, and meetings with automated reminders
- **Project Tracking** - Monitor coding challenges and member projects with achievement systems
- **Pizza Grant Integration** - Streamlined submission process for Hack Club pizza grants
- **Achievement Showcase** - Create stunning portfolios of member projects and club achievements
- **Advanced Analytics** - Track club growth, engagement, and project completion rates

### 🔐 Authentication
- Traditional email/password signup and login
- Slack OAuth integration for seamless authentication
- Admin panel for user and club management

### 🏆 Integrations
- **Hackatime** - Track coding time and project statistics
- **Airtable** - Automated pizza grant submissions
- **Slack** - OAuth authentication and user profile integration

## Tech Stack

- **Backend**: Flask (Python)
- **Database**: PostgreSQL with SQLAlchemy ORM
- **Frontend**: HTML5, CSS3, JavaScript (Vanilla)
- **Authentication**: Flask-Login with Slack OAuth
- **Rate Limiting**: Flask-Limiter
- **File Uploads**: Hack Club CDN integration
- **Deployment**: Docker-ready with Replit support

## Getting Started

### Prerequisites
- Python 3.11+
- PostgreSQL database
- Required environment variables (see Configuration section)

### Installation

1. Clone the repository or fork on Replit
2. Highly recommended to use a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```
   If using Replit, this step is handled automatically.
3. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```
4. Set up environment variables (see Configuration section)
5. Run the application:
   ```bash
   python3 main.py
   ```

The application will be available at `http://0.0.0.0:5000`

## Configuration

### Required Environment Variables

```bash
# Database
DATABASE_URL=postgresql://username:password@host:port/database

# Flask
SECRET_KEY=your-secret-key-here

# Slack OAuth (optional)
SLACK_CLIENT_ID=your-slack-client-id
SLACK_CLIENT_SECRET=your-slack-client-secret
SLACK_SIGNING_SECRET=your-slack-signing-secret

# Airtable Integration (for pizza grants)
AIRTABLE_TOKEN=your-airtable-api-token
AIRTABLE_BASE_ID=your-airtable-base-id
AIRTABLE_TABLE_NAME=your-table-name
```

### Database Setup

The application will automatically create the necessary database tables on first run. A super admin account is created with:
- Email: `ethan@hackclub.com`
- Password: `hackclub2024`

**Important**: Change the default admin password immediately after first login.

## Usage

### For Club Leaders
1. Sign up and select "I want to start a club"
2. Customize your club details in the dashboard
3. Share your join code with members
4. Create assignments, schedule meetings, and track projects
5. Submit pizza grants for member projects

### For Club Members
1. Sign up with a join code from your club leader
2. Complete assignments and track your progress
3. Submit projects for showcase
4. Connect your Hackatime account to track coding time

### For Administrators
- Access the admin panel at `/admin`
- Manage users, clubs, and system-wide settings
- View analytics and platform statistics
- Grant/revoke administrator privileges

## API Endpoints

### Authentication
- `POST /login` - User login
- `POST /signup` - User registration
- `GET /auth/slack` - Slack OAuth initiation
- `GET /auth/slack/callback` - Slack OAuth callback

### Club Management
- `GET /api/clubs/<id>/posts` - Get club posts
- `POST /api/clubs/<id>/posts` - Create club post
- `GET /api/clubs/<id>/assignments` - Get assignments
- `POST /api/clubs/<id>/assignments` - Create assignment
- `GET /api/clubs/<id>/meetings` - Get meetings
- `POST /api/clubs/<id>/meetings` - Schedule meeting

### Pizza Grants
- `POST /api/clubs/<id>/pizza-grants` - Submit pizza grant
- `POST /api/upload-screenshot` - Upload project screenshot

### Admin (Requires admin privileges)
- `GET /api/admin/users` - Get all users
- `GET /api/admin/clubs` - Get all clubs
- `GET /api/admin/stats` - Get platform statistics

## File Structure

```
├── main.py                 # Main Flask application
├── templates/              # HTML templates
│   ├── base.html          # Base template
│   ├── index.html         # Landing page
│   ├── dashboard.html     # User dashboard
│   ├── club_dashboard.html # Club management
│   ├── admin_dashboard.html # Admin panel
│   └── ...
├── static/                # Static assets
│   ├── css/               # Stylesheets
│   ├── js/                # JavaScript files
│   └── assets/            # Images and media
└── README.md              # This file
```

## Security Features

- Password hashing with Werkzeug
- Rate limiting on all endpoints
- CSRF protection
- SQL injection prevention with SQLAlchemy ORM
- Admin-only endpoints protection
- File upload validation

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## Deployment

### Replit Deployment
This project is optimized for Replit deployment:
1. Fork the repl
2. Set up environment variables in Replit Secrets
3. Click Run to start the application
4. Use Replit's deployment feature to publish

### Docker Deployment
```bash
docker build -t hack-club-dashboard .
docker run -p 5000:5000 --env-file .env hack-club-dashboard
```

## Support

For support and questions:
- Create an issue in the repository
- Contact the Hack Club community
- Check the [Hack Club Slack](https://hackclub.com/slack)

## License

Built with ❤️ for the Hack Club community.

---

*Join the global movement of teenage hackers at [hackclub.com](https://hackclub.com)*
