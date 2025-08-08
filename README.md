# HandoffHub - Inter-departmental Handoff Tracking

Never drop the ball between teams again. Track every handoff, eliminate bottlenecks, boost accountability.

## Features

- 🚀 Simple handoff creation in seconds
- 📧 Instant email notifications
- 📊 Real-time dashboard with metrics
- 💬 Comments and status updates
- ⏰ Deadline tracking and overdue alerts
- 👥 Team-based organization

## Quick Start

### Local Development

1. Clone the repository:
```bash
git clone https://github.com/linuspiorkowsky/handoffhub.git
cd handoffhub
```

2. Create virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your settings
```

5. Initialize database:
```bash
flask init-db
flask create-sample-data  # Optional: creates test data
```

6. Run the application:
```bash
flask run
```

Visit http://localhost:5000

### Docker Development

```bash
docker-compose up
```

Visit http://localhost:5000

## Deployment

### Railway

1. Connect your GitHub repo to Railway
2. Add environment variables in Railway dashboard
3. Deploy!

### Render

1. Connect GitHub repo to Render
2. Choose "Web Service"
3. Add environment variables
4. Deploy!

## Default Test Accounts

If you run `flask create-sample-data`:
- alice@example.com / password123 (Sales team)
- bob@example.com / password123 (Marketing team)
- charlie@example.com / password123 (Development team)
- diana@example.com / password123 (Support team)

## Tech Stack

- **Backend**: Flask, SQLAlchemy, Flask-Login
- **Frontend**: HTMX, Alpine.js, Tailwind CSS
- **Database**: PostgreSQL (or SQLite for development)
- **Email**: Flask-Mail with SMTP
- **Deployment**: Railway, Render, or any PaaS

## License

MIT

## Support

For questions or issues, contact: support@handoffhub.com