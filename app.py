"""
HandoffHub - Inter-departmental Handoff Tracking System
Complete MVP with Flask, SQLAlchemy, and HTMX
"""

import os
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SelectField, DateTimeField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
import enum

# Initialize Flask app
app = Flask(__name__)

database_url = os.environ.get('DATABASE_URL', 'sqlite:///handoffhub.db')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY'), secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@handoffhub.com')

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)

# Enums
class HandoffStatus(enum.Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    WAITING_INFO = "waiting_info"
    COMPLETED = "completed"
    CANCELLED = "cancelled"

class Priority(enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    URGENT = "urgent"

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    team = db.relationship('Team', backref='members')
    created_handoffs = db.relationship('Handoff', foreign_keys='Handoff.created_by_id', backref='creator')
    assigned_handoffs = db.relationship('Handoff', foreign_keys='Handoff.assigned_to_id', backref='assignee')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    organization = db.relationship('Organization', backref='teams')
    sent_handoffs = db.relationship('Handoff', foreign_keys='Handoff.from_team_id', backref='from_team')
    received_handoffs = db.relationship('Handoff', foreign_keys='Handoff.to_team_id', backref='to_team')

class Organization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Handoff(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.Enum(HandoffStatus), default=HandoffStatus.PENDING)
    priority = db.Column(db.Enum(Priority), default=Priority.MEDIUM)
    
    # Foreign keys
    from_team_id = db.Column(db.Integer, db.ForeignKey('team.id'), nullable=False)
    to_team_id = db.Column(db.Integer, db.ForeignKey('team.id'), nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    deadline = db.Column(db.DateTime)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    
    # Relationships
    comments = db.relationship('Comment', backref='handoff', lazy='dynamic', cascade='all, delete-orphan')
    
    @property
    def is_overdue(self):
        if self.deadline and self.status not in [HandoffStatus.COMPLETED, HandoffStatus.CANCELLED]:
            return datetime.utcnow() > self.deadline
        return False
    
    @property
    def time_in_status(self):
        if self.status == HandoffStatus.COMPLETED and self.completed_at:
            return self.completed_at - self.created_at
        elif self.status == HandoffStatus.IN_PROGRESS and self.started_at:
            return datetime.utcnow() - self.started_at
        else:
            return datetime.utcnow() - self.created_at

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    handoff_id = db.Column(db.Integer, db.ForeignKey('handoff.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref='comments')

# Forms
class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=100)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    organization_name = StringField('Organization Name', validators=[DataRequired()])
    team_name = StringField('Team Name', validators=[DataRequired()])
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])

class HandoffForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=200)])
    description = TextAreaField('Description')
    to_team = SelectField('To Team', coerce=int, validators=[DataRequired()])
    priority = SelectField('Priority', choices=[(p.value, p.value.title()) for p in Priority])
    deadline = DateTimeField('Deadline', format='%Y-%m-%d %H:%M', validators=[], optional=True)

class CommentForm(FlaskForm):
    content = TextAreaField('Comment', validators=[DataRequired()])

# Login Manager
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper Functions
def send_notification_email(handoff, recipient_email, action):
    """Send email notifications for handoff actions"""
    try:
        msg = Message(
            f'HandoffHub: {action} - {handoff.title}',
            recipients=[recipient_email]
        )
        msg.body = f'''
        A handoff requires your attention:
        
        Title: {handoff.title}
        From: {handoff.from_team.name}
        To: {handoff.to_team.name}
        Priority: {handoff.priority.value.upper()}
        Status: {handoff.status.value.replace('_', ' ').title()}
        
        Description:
        {handoff.description}
        
        View it here: {url_for('view_handoff', handoff_id=handoff.id, _external=True)}
        '''
        mail.send(msg)
    except Exception as e:
        print(f"Failed to send email: {e}")

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        # Create organization
        org = Organization(name=form.organization_name.data)
        db.session.add(org)
        db.session.flush()
        
        # Create team
        team = Team(name=form.team_name.data, organization_id=org.id)
        db.session.add(team)
        db.session.flush()
        
        # Create user
        user = User(
            name=form.name.data,
            email=form.email.data,
            team_id=team.id
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        
        login_user(user)
        flash('Registration successful! Welcome to HandoffHub.', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            flash('Logged in successfully!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get handoffs for user's team
    team_handoffs_received = Handoff.query.filter_by(to_team_id=current_user.team_id)\
        .order_by(Handoff.created_at.desc()).limit(10).all()
    
    team_handoffs_sent = Handoff.query.filter_by(from_team_id=current_user.team_id)\
        .order_by(Handoff.created_at.desc()).limit(10).all()
    
    # Get personal assignments
    my_handoffs = Handoff.query.filter_by(assigned_to_id=current_user.id)\
        .filter(Handoff.status != HandoffStatus.COMPLETED)\
        .order_by(Handoff.created_at.desc()).all()
    
    # Calculate metrics
    total_pending = Handoff.query.filter_by(to_team_id=current_user.team_id)\
        .filter_by(status=HandoffStatus.PENDING).count()
    
    total_in_progress = Handoff.query.filter_by(to_team_id=current_user.team_id)\
        .filter_by(status=HandoffStatus.IN_PROGRESS).count()
    
    overdue_count = 0
    for h in Handoff.query.filter_by(to_team_id=current_user.team_id).all():
        if h.is_overdue:
            overdue_count += 1
    
    return render_template('dashboard.html',
                         received=team_handoffs_received,
                         sent=team_handoffs_sent,
                         my_handoffs=my_handoffs,
                         pending_count=total_pending,
                         in_progress_count=total_in_progress,
                         overdue_count=overdue_count)

@app.route('/handoff/create', methods=['GET', 'POST'])
@login_required
def create_handoff():
    form = HandoffForm()
    
    # Get all teams in organization except current user's team
    org_teams = Team.query.filter_by(organization_id=current_user.team.organization_id)\
        .filter(Team.id != current_user.team_id).all()
    form.to_team.choices = [(t.id, t.name) for t in org_teams]
    
    if form.validate_on_submit():
        handoff = Handoff(
            title=form.title.data,
            description=form.description.data,
            from_team_id=current_user.team_id,
            to_team_id=form.to_team.data,
            created_by_id=current_user.id,
            priority=Priority(form.priority.data),
            deadline=form.deadline.data
        )
        db.session.add(handoff)
        db.session.commit()
        
        # Send notification to receiving team members
        receiving_team_members = User.query.filter_by(team_id=form.to_team.data).all()
        for member in receiving_team_members:
            send_notification_email(handoff, member.email, 'New Handoff')
        
        flash('Handoff created successfully!', 'success')
        return redirect(url_for('view_handoff', handoff_id=handoff.id))
    
    return render_template('create_handoff.html', form=form)

@app.route('/handoff/<int:handoff_id>')
@login_required
def view_handoff(handoff_id):
    handoff = Handoff.query.get_or_404(handoff_id)
    
    # Check if user has access
    if current_user.team_id not in [handoff.from_team_id, handoff.to_team_id]:
        flash('You do not have access to this handoff.', 'danger')
        return redirect(url_for('dashboard'))
    
    form = CommentForm()
    comments = handoff.comments.order_by(Comment.created_at.desc()).all()
    
    return render_template('view_handoff.html', handoff=handoff, form=form, comments=comments)

@app.route('/handoff/<int:handoff_id>/update_status', methods=['POST'])
@login_required
def update_handoff_status(handoff_id):
    handoff = Handoff.query.get_or_404(handoff_id)
    
    # Check permissions
    if current_user.team_id != handoff.to_team_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    new_status = request.form.get('status')
    if new_status:
        try:
            handoff.status = HandoffStatus(new_status)
            
            # Update timestamps
            if new_status == 'in_progress':
                handoff.started_at = datetime.utcnow()
                handoff.assigned_to_id = current_user.id
            elif new_status == 'completed':
                handoff.completed_at = datetime.utcnow()
            
            db.session.commit()
            
            # Send notification
            send_notification_email(handoff, handoff.creator.email, f'Status Updated: {new_status}')
            
            flash(f'Status updated to {new_status.replace("_", " ").title()}', 'success')
        except ValueError:
            flash('Invalid status', 'danger')
    
    return redirect(url_for('view_handoff', handoff_id=handoff_id))

@app.route('/handoff/<int:handoff_id>/comment', methods=['POST'])
@login_required
def add_comment(handoff_id):
    handoff = Handoff.query.get_or_404(handoff_id)
    
    # Check permissions
    if current_user.team_id not in [handoff.from_team_id, handoff.to_team_id]:
        return jsonify({'error': 'Unauthorized'}), 403
    
    form = CommentForm()
    if form.validate_on_submit():
        comment = Comment(
            content=form.content.data,
            handoff_id=handoff_id,
            user_id=current_user.id
        )
        db.session.add(comment)
        db.session.commit()
        flash('Comment added!', 'success')
    
    return redirect(url_for('view_handoff', handoff_id=handoff_id))

@app.route('/api/stats')
@login_required
def api_stats():
    """API endpoint for dashboard auto-refresh with HTMX"""
    team_id = current_user.team_id
    
    stats = {
        'pending': Handoff.query.filter_by(to_team_id=team_id, status=HandoffStatus.PENDING).count(),
        'in_progress': Handoff.query.filter_by(to_team_id=team_id, status=HandoffStatus.IN_PROGRESS).count(),
        'completed_today': Handoff.query.filter_by(to_team_id=team_id, status=HandoffStatus.COMPLETED)\
            .filter(Handoff.completed_at >= datetime.utcnow().date()).count(),
        'overdue': sum(1 for h in Handoff.query.filter_by(to_team_id=team_id).all() if h.is_overdue)
    }
    
    return jsonify(stats)

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

# CLI Commands for initialization
@app.cli.command()
def init_db():
    """Initialize the database."""
    db.create_all()
    print("Database initialized!")

@app.cli.command()
def create_sample_data():
    """Create sample data for testing."""
    # Create sample organization
    org = Organization(name="Sample Corp")
    db.session.add(org)
    db.session.flush()
    
    # Create teams
    teams = [
        Team(name="Sales", organization_id=org.id),
        Team(name="Marketing", organization_id=org.id),
        Team(name="Development", organization_id=org.id),
        Team(name="Support", organization_id=org.id)
    ]
    for team in teams:
        db.session.add(team)
    db.session.flush()
    
    # Create users
    users = [
        User(name="Alice Sales", email="alice@example.com", team_id=teams[0].id),
        User(name="Bob Marketing", email="bob@example.com", team_id=teams[1].id),
        User(name="Charlie Dev", email="charlie@example.com", team_id=teams[2].id),
        User(name="Diana Support", email="diana@example.com", team_id=teams[3].id)
    ]
    
    for user in users:
        user.set_password("password123")
        db.session.add(user)
    
    db.session.commit()
    print("Sample data created! Login with alice@example.com / password123")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
