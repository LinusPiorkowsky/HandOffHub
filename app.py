"""
HandoffHub Premium - Enhanced Inter-departmental Handoff Tracking System
Complete application with advanced features, better UX, and robust error handling
"""

import os
import secrets
import json
from datetime import datetime, timedelta, date
from functools import wraps
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SelectField, DateTimeField, BooleanField, IntegerField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError, Optional
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from sqlalchemy import func, and_, or_, desc
from sqlalchemy.orm import joinedload
import enum
import io
import csv

# Initialize Flask app
app = Flask(__name__)

# Database configuration MUSS VOR SQLAlchemy init kommen!
database_url = os.environ.get('DATABASE_URL', 'sqlite:///handoffhub.db')
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

if database_url.startswith("postgresql://") and "sslmode=" not in database_url:
    separator = '&' if '?' in database_url else '?'
    database_url += f"{separator}sslmode=require"

# Set ALL configuration BEFORE initializing extensions
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 10,
    'pool_recycle': 3600,
    'pool_pre_ping': True
}

# Email configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@handoffhub.com')

# NOW initialize extensions (nur EINMAL!)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
mail = Mail(app)

# Enums
class HandoffStatus(enum.Enum):
    PENDING = "pending"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    WAITING_INFO = "waiting_info"
    REVIEW = "review"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    ESCALATED = "escalated"

class Priority(enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    URGENT = "urgent"
    CRITICAL = "critical"

class NotificationType(enum.Enum):
    EMAIL = "email"
    IN_APP = "in_app"
    BOTH = "both"

class HandoffType(enum.Enum):
    TASK = "task"
    APPROVAL = "approval"
    REVIEW = "review"
    INFORMATION = "information"
    ESCALATION = "escalation"

# Database Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    team_id = db.Column(db.Integer, db.ForeignKey('teams.id'))
    role = db.Column(db.String(50), default='member')  # member, team_lead, admin
    avatar_color = db.Column(db.String(7), default='#6366f1')
    notification_preference = db.Column(db.Enum(NotificationType), default=NotificationType.BOTH)
    is_active = db.Column(db.Boolean, default=True)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Performance metrics
    handoffs_completed = db.Column(db.Integer, default=0)
    average_completion_time = db.Column(db.Float, default=0.0)
    on_time_rate = db.Column(db.Float, default=100.0)
    
    # Relationships
    team = db.relationship('Team', backref='members', lazy='joined')
    created_handoffs = db.relationship('Handoff', foreign_keys='Handoff.created_by_id', backref='creator', lazy='dynamic')
    assigned_handoffs = db.relationship('Handoff', foreign_keys='Handoff.assigned_to_id', backref='assignee', lazy='dynamic')
    notifications = db.relationship('Notification', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def get_initials(self):
        return ''.join([n[0].upper() for n in self.name.split()[:2]])
    
    def update_metrics(self):
        completed = self.assigned_handoffs.filter_by(status=HandoffStatus.COMPLETED).all()
        self.handoffs_completed = len(completed)
        
        if completed:
            total_time = sum([(h.completed_at - h.created_at).total_seconds() for h in completed if h.completed_at])
            self.average_completion_time = total_time / len(completed) / 3600  # in hours
            
            on_time = sum([1 for h in completed if h.deadline and h.completed_at <= h.deadline])
            self.on_time_rate = (on_time / len(completed)) * 100 if completed else 100.0

class Team(db.Model):
    __tablename__ = 'teams'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500))
    color = db.Column(db.String(7), default='#6366f1')
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Metrics
    total_handoffs_sent = db.Column(db.Integer, default=0)
    total_handoffs_received = db.Column(db.Integer, default=0)
    average_response_time = db.Column(db.Float, default=0.0)
    
    # Relationships
    organization = db.relationship('Organization', backref='teams')
    sent_handoffs = db.relationship('Handoff', foreign_keys='Handoff.from_team_id', backref='from_team', lazy='dynamic')
    received_handoffs = db.relationship('Handoff', foreign_keys='Handoff.to_team_id', backref='to_team', lazy='dynamic')
    # templates = db.relationship('HandoffTemplate', backref='team', lazy='dynamic', cascade='all, delete-orphan')

class Organization(db.Model):
    __tablename__ = 'organizations'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    domain = db.Column(db.String(100))
    subscription_tier = db.Column(db.String(20), default='free')  # free, starter, pro, enterprise
    max_users = db.Column(db.Integer, default=10)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Settings
    auto_escalate_hours = db.Column(db.Integer, default=48)
    require_acknowledgment = db.Column(db.Boolean, default=True)
    allow_templates = db.Column(db.Boolean, default=True)

class Handoff(db.Model):
    __tablename__ = 'handoffs'
    
    id = db.Column(db.Integer, primary_key=True)
    reference_id = db.Column(db.String(20), unique=True)  # HO-2024-0001
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    handoff_type = db.Column(db.Enum(HandoffType), default=HandoffType.TASK)
    status = db.Column(db.Enum(HandoffStatus), default=HandoffStatus.PENDING, index=True)
    priority = db.Column(db.Enum(Priority), default=Priority.MEDIUM, index=True)
    
    # Foreign keys
    from_team_id = db.Column(db.Integer, db.ForeignKey('teams.id'), nullable=False)
    to_team_id = db.Column(db.Integer, db.ForeignKey('teams.id'), nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    template_id = db.Column(db.Integer, db.ForeignKey('handoff_templates.id'))
    parent_handoff_id = db.Column(db.Integer, db.ForeignKey('handoffs.id'))
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    acknowledged_at = db.Column(db.DateTime)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    cancelled_at = db.Column(db.DateTime)
    escalated_at = db.Column(db.DateTime)
    deadline = db.Column(db.DateTime)
    
    # Additional fields
    tags = db.Column(db.String(500))  # comma-separated tags
    attachments = db.Column(db.Text)  # JSON array of attachment URLs
    completion_notes = db.Column(db.Text)
    rejection_reason = db.Column(db.Text)
    estimated_hours = db.Column(db.Float)
    actual_hours = db.Column(db.Float)
    
    # Metrics
    view_count = db.Column(db.Integer, default=0)
    comment_count = db.Column(db.Integer, default=0)
    
    # Relationships
    comments = db.relationship('Comment', backref='handoff', lazy='dynamic', cascade='all, delete-orphan')
    notifications = db.relationship('Notification', backref='handoff', lazy='dynamic', cascade='all, delete-orphan')
    sub_handoffs = db.relationship('Handoff', backref=db.backref('parent_handoff', remote_side=[id]), lazy='dynamic')
    template_used = db.relationship('HandoffTemplate', foreign_keys='Handoff.template_id')
    
    def __init__(self, **kwargs):
        super(Handoff, self).__init__(**kwargs)
        self.generate_reference_id()
    
    def generate_reference_id(self):
        year = datetime.utcnow().year
        count = Handoff.query.filter(db.extract('year', Handoff.created_at) == year).count() + 1
        self.reference_id = f"HO-{year}-{count:04d}"
    
    @property
    def is_overdue(self):
        if self.deadline and self.status not in [HandoffStatus.COMPLETED, HandoffStatus.CANCELLED]:
            return datetime.utcnow() > self.deadline
        return False
    
    @property
    def time_elapsed(self):
        if self.status == HandoffStatus.COMPLETED and self.completed_at:
            return (self.completed_at - self.created_at).total_seconds() / 3600  # in hours
        return (datetime.utcnow() - self.created_at).total_seconds() / 3600
    
    @property
    def sla_status(self):
        if not self.deadline:
            return 'no_sla'
        if self.is_overdue:
            return 'breached'
        hours_left = (self.deadline - datetime.utcnow()).total_seconds() / 3600
        if hours_left < 4:
            return 'at_risk'
        return 'on_track'
    
    def get_status_color(self):
        colors = {
            HandoffStatus.PENDING: 'yellow',
            HandoffStatus.ACKNOWLEDGED: 'blue',
            HandoffStatus.IN_PROGRESS: 'indigo',
            HandoffStatus.WAITING_INFO: 'orange',
            HandoffStatus.REVIEW: 'purple',
            HandoffStatus.COMPLETED: 'green',
            HandoffStatus.CANCELLED: 'gray',
            HandoffStatus.ESCALATED: 'red'
        }
        return colors.get(self.status, 'gray')
    
    def get_priority_color(self):
        colors = {
            Priority.LOW: 'gray',
            Priority.MEDIUM: 'blue',
            Priority.HIGH: 'yellow',
            Priority.URGENT: 'orange',
            Priority.CRITICAL: 'red'
        }
        return colors.get(self.priority, 'gray')

class Comment(db.Model):
    __tablename__ = 'comments'
    
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    handoff_id = db.Column(db.Integer, db.ForeignKey('handoffs.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    is_internal = db.Column(db.Boolean, default=False)  # Internal notes not visible to other team
    mentioned_users = db.Column(db.String(500))  # comma-separated user IDs
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    edited_at = db.Column(db.DateTime)
    
    # Relationships
    user = db.relationship('User', backref='comments')

class Notification(db.Model):
    __tablename__ = 'notifications'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    handoff_id = db.Column(db.Integer, db.ForeignKey('handoffs.id'))
    type = db.Column(db.String(50))  # new_handoff, status_change, comment, mention, deadline
    title = db.Column(db.String(200))
    message = db.Column(db.Text)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class HandoffTemplate(db.Model):
    __tablename__ = 'handoff_templates'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500))
    title_template = db.Column(db.String(200))
    description_template = db.Column(db.Text)
    handoff_type = db.Column(db.Enum(HandoffType), default=HandoffType.TASK)
    priority = db.Column(db.Enum(Priority), default=Priority.MEDIUM)
    team_id = db.Column(db.Integer, db.ForeignKey('teams.id'))
    to_team_id = db.Column(db.Integer, db.ForeignKey('teams.id'))
    estimated_hours = db.Column(db.Float)
    tags = db.Column(db.String(500))
    checklist = db.Column(db.Text)  # JSON array of checklist items
    is_active = db.Column(db.Boolean, default=True)
    use_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    team = db.relationship('Team', foreign_keys=[team_id], backref='owned_templates')
    to_team = db.relationship('Team', foreign_keys=[to_team_id])

# Forms
class RegistrationForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=100)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    organization_name = StringField('Organization Name', validators=[DataRequired()])
    team_name = StringField('Your Team Name', validators=[DataRequired()])
    invite_code = StringField('Invite Code (Optional)', validators=[Optional()])
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data.lower()).first()
        if user:
            raise ValidationError('This email is already registered. Please login instead.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')

class HandoffForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=200)])
    description = TextAreaField('Description', validators=[DataRequired()])
    handoff_type = SelectField('Type', choices=[(t.value, t.value.replace('_', ' ').title()) for t in HandoffType])
    to_team = SelectField('To Team', coerce=int, validators=[DataRequired()])
    assigned_to = SelectField('Assign To (Optional)', coerce=int, validators=[Optional()])  # NEU
    priority = SelectField('Priority', choices=[(p.value, p.value.title()) for p in Priority])
    deadline = DateTimeField('Deadline (Optional)', format='%Y-%m-%d %H:%M', validators=[Optional()])
    estimated_hours = IntegerField('Estimated Hours', validators=[Optional()])
    tags = StringField('Tags (comma-separated)', validators=[Optional()])
    template_id = SelectField('Use Template', coerce=int, validators=[Optional()])

class CommentForm(FlaskForm):
    content = TextAreaField('Comment', validators=[DataRequired()])
    is_internal = BooleanField('Internal Note (not visible to other team)')

class TeamForm(FlaskForm):
    name = StringField('Team Name', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description', validators=[Optional(), Length(max=500)])
    color = StringField('Team Color', default='#6366f1')

# Login Manager
@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except:
        return None

# Helper Functions
def create_notification(user_id, handoff_id, notification_type, title, message):
    """Create an in-app notification"""
    notification = Notification(
        user_id=user_id,
        handoff_id=handoff_id,
        type=notification_type,
        title=title,
        message=message
    )
    db.session.add(notification)
    return notification

def send_notification_email(handoff, recipient_email, action):
    """Send email notifications for handoff actions"""
    if not app.config.get('MAIL_USERNAME'):
        print(f"Email not configured. Would send: {action} to {recipient_email}")
        return
    
    try:
        msg = Message(
            f'HandoffHub: {action} - {handoff.reference_id}: {handoff.title}',
            recipients=[recipient_email]
        )
        
        status_color = handoff.get_status_color()
        priority_color = handoff.get_priority_color()
        
        msg.html = f'''
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: #4f46e5; color: white; padding: 20px; text-align: center;">
                <h1 style="margin: 0;">HandoffHub</h1>
            </div>
            <div style="padding: 20px; background: #f9fafb;">
                <h2 style="color: #111827;">{action}</h2>
                <div style="background: white; padding: 20px; border-radius: 8px; margin-top: 20px;">
                    <p style="margin: 0 0 10px 0;"><strong>Reference:</strong> {handoff.reference_id}</p>
                    <p style="margin: 0 0 10px 0;"><strong>Title:</strong> {handoff.title}</p>
                    <p style="margin: 0 0 10px 0;"><strong>From:</strong> {handoff.from_team.name}</p>
                    <p style="margin: 0 0 10px 0;"><strong>To:</strong> {handoff.to_team.name}</p>
                    <p style="margin: 0 0 10px 0;">
                        <strong>Priority:</strong> 
                        <span style="background: {priority_color}20; color: {priority_color}; padding: 2px 8px; border-radius: 4px;">
                            {handoff.priority.value.upper()}
                        </span>
                    </p>
                    <p style="margin: 0 0 10px 0;">
                        <strong>Status:</strong> 
                        <span style="background: {status_color}20; color: {status_color}; padding: 2px 8px; border-radius: 4px;">
                            {handoff.status.value.replace('_', ' ').title()}
                        </span>
                    </p>
                    {f'<p style="margin: 0 0 10px 0;"><strong>Deadline:</strong> {handoff.deadline.strftime("%Y-%m-%d %H:%M")}</p>' if handoff.deadline else ''}
                    <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #e5e7eb;">
                        <p style="margin: 0 0 10px 0;"><strong>Description:</strong></p>
                        <p style="margin: 0; color: #6b7280;">{handoff.description}</p>
                    </div>
                    <div style="margin-top: 30px;">
                        <a href="{url_for('view_handoff', handoff_id=handoff.id, _external=True)}" 
                           style="background: #4f46e5; color: white; padding: 10px 20px; text-decoration: none; border-radius: 6px; display: inline-block;">
                            View Handoff
                        </a>
                    </div>
                </div>
            </div>
        </div>
        '''
        
        mail.send(msg)
    except Exception as e:
        print(f"Failed to send email: {e}")

def require_team_member(f):
    """Decorator to ensure user belongs to a team"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.team_id:
            flash('You need to be part of a team to access this feature.', 'warning')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Context Processor
@app.context_processor
def inject_notifications():
    if current_user.is_authenticated:
        unread_count = current_user.notifications.filter_by(is_read=False).count()
        return dict(unread_notifications=unread_count)
    return dict(unread_notifications=0)

# Routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        # Check for existing organization by invite code
        org = None
        if form.invite_code.data:
            # In production, implement proper invite code logic
            org = Organization.query.filter_by(domain=form.invite_code.data.lower()).first()
        
        if not org:
            # Create new organization
            org = Organization(name=form.organization_name.data)
            db.session.add(org)
            db.session.flush()
        
        # Check if team exists
        team = Team.query.filter_by(name=form.team_name.data, organization_id=org.id).first()
        if not team:
            team = Team(name=form.team_name.data, organization_id=org.id)
            db.session.add(team)
            db.session.flush()
        
        # Create user
        user = User(
            name=form.name.data,
            email=form.email.data.lower(),
            team_id=team.id,
            avatar_color=f"#{secrets.token_hex(3)}"
        )
        user.set_password(form.password.data)
        
        # First user in org becomes admin
        if User.query.filter_by(team_id=team.id).count() == 0:
            user.role = 'admin'
        
        db.session.add(user)
        db.session.commit()
        
        # Create welcome notification
        create_notification(
            user.id, 
            None, 
            'welcome',
            'Welcome to HandoffHub!',
            'Get started by creating your first handoff or inviting team members.'
        )
        db.session.commit()
        
        login_user(user, remember=True)
        flash('Welcome to HandoffHub! Your account has been created.', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user and user.check_password(form.password.data):
            if not user.is_active:
                flash('Your account has been deactivated. Please contact your administrator.', 'danger')
                return redirect(url_for('login'))
            
            login_user(user, remember=form.remember_me.data)
            user.last_seen = datetime.utcnow()
            db.session.commit()
            
            next_page = request.args.get('next')
            flash(f'Welcome back, {user.name}!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password. Please try again.', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Update last seen
    current_user.last_seen = datetime.utcnow()
    db.session.commit()
    
    # Get date range for metrics (last 30 days)
    date_from = datetime.utcnow() - timedelta(days=30)
    
    if not current_user.team_id:
        # User without team - show limited dashboard
        return render_template('dashboard_no_team.html')
    
    # Team handoffs
    team_handoffs_received = Handoff.query.filter_by(to_team_id=current_user.team_id)\
        .order_by(Handoff.created_at.desc()).limit(10).all()
    
    team_handoffs_sent = Handoff.query.filter_by(from_team_id=current_user.team_id)\
        .order_by(Handoff.created_at.desc()).limit(10).all()
    
    # Personal assignments
    my_handoffs = Handoff.query.filter_by(assigned_to_id=current_user.id)\
        .filter(Handoff.status.notin_([HandoffStatus.COMPLETED, HandoffStatus.CANCELLED]))\
        .order_by(Handoff.priority.desc(), Handoff.created_at.desc()).all()
    
    # Metrics
    metrics = {
        'pending': Handoff.query.filter_by(to_team_id=current_user.team_id, status=HandoffStatus.PENDING).count(),
        'in_progress': Handoff.query.filter_by(to_team_id=current_user.team_id, status=HandoffStatus.IN_PROGRESS).count(),
        'overdue': 0,
        'completed_today': Handoff.query.filter_by(to_team_id=current_user.team_id, status=HandoffStatus.COMPLETED)\
            .filter(Handoff.completed_at >= datetime.utcnow().date()).count(),
        'avg_completion_time': 0,
        'on_time_rate': 100
    }
    
    # Calculate overdue
    for h in Handoff.query.filter_by(to_team_id=current_user.team_id).all():
        if h.is_overdue:
            metrics['overdue'] += 1
    
    # Calculate average completion time
    completed = Handoff.query.filter_by(to_team_id=current_user.team_id, status=HandoffStatus.COMPLETED)\
        .filter(Handoff.created_at >= date_from).all()
    
    if completed:
        total_time = sum([h.time_elapsed for h in completed])
        metrics['avg_completion_time'] = round(total_time / len(completed), 1)
        
        on_time = sum([1 for h in completed if h.deadline and h.completed_at <= h.deadline])
        metrics['on_time_rate'] = round((on_time / len(completed)) * 100, 1)
    
    # Recent notifications
    notifications = current_user.notifications.filter_by(is_read=False)\
        .order_by(Notification.created_at.desc()).limit(5).all()
    
    # Team performance data for chart
    chart_data = {
        'labels': [],
        'sent': [],
        'received': [],
        'completed': []
    }
    
    for i in range(7):
        date = datetime.utcnow().date() - timedelta(days=i)
        chart_data['labels'].append(date.strftime('%m/%d'))
        
        sent = Handoff.query.filter_by(from_team_id=current_user.team_id)\
            .filter(func.date(Handoff.created_at) == date).count()
        chart_data['sent'].append(sent)
        
        received = Handoff.query.filter_by(to_team_id=current_user.team_id)\
            .filter(func.date(Handoff.created_at) == date).count()
        chart_data['received'].append(received)
        
        completed = Handoff.query.filter_by(to_team_id=current_user.team_id, status=HandoffStatus.COMPLETED)\
            .filter(func.date(Handoff.completed_at) == date).count()
        chart_data['completed'].append(completed)
    
    chart_data['labels'].reverse()
    chart_data['sent'].reverse()
    chart_data['received'].reverse()
    chart_data['completed'].reverse()

    active_members_count = len([m for m in current_user.team.members if m.is_active])
    pending_count = len([h for h in current_user.team.received_handoffs if h.status == HandoffStatus.PENDING])
    
    return render_template('dashboard.html',
                         received=team_handoffs_received,
                         sent=team_handoffs_sent,
                         my_handoffs=my_handoffs,
                         metrics=metrics,
                         notifications=notifications,
                         active_members_count=active_members_count,
                         pending_count=pending_count,
                         chart_data=json.dumps(chart_data))


@app.route('/handoff/create', methods=['GET', 'POST'])
@require_team_member
def create_handoff():
    form = HandoffForm()
    
    # Get all teams in organization except current user's team
    org_teams = Team.query.filter_by(organization_id=current_user.team.organization_id)\
        .filter(Team.id != current_user.team_id).all()
    
    if not org_teams:
        flash('No other teams found. Please create more teams first.', 'warning')
        return redirect(url_for('teams'))
    
    form.to_team.choices = [(0, '-- Select Team --')] + [(t.id, t.name) for t in org_teams]
    
    # NEU: Personen zur Direktzuweisung laden
    form.assigned_to.choices = [(0, '-- Auto-assign --')]
    if request.method == 'GET' or form.to_team.data:
        if form.to_team.data and form.to_team.data != 0:
            team_members = User.query.filter_by(team_id=form.to_team.data, is_active=True).all()
            form.assigned_to.choices += [(u.id, u.name) for u in team_members]
    
    # Get templates for current team
    templates = HandoffTemplate.query.filter_by(team_id=current_user.team_id, is_active=True).all()
    form.template_id.choices = [(0, '-- No Template --')] + [(t.id, t.name) for t in templates]
    
    if form.validate_on_submit():
        if form.to_team.data == 0:
            flash('Please select a team to send the handoff to.', 'danger')
            return render_template('create_handoff.html', form=form)
        
        handoff = Handoff(
            title=form.title.data,
            description=form.description.data,
            handoff_type=HandoffType(form.handoff_type.data),
            from_team_id=current_user.team_id,
            to_team_id=form.to_team.data,
            created_by_id=current_user.id,
            assigned_to_id=form.assigned_to.data if form.assigned_to.data != 0 else None,  # NEU
            priority=Priority(form.priority.data),
            deadline=form.deadline.data,
            estimated_hours=form.estimated_hours.data,
            tags=form.tags.data
        )
        
        # Apply template if selected
        if form.template_id.data > 0:
            template = HandoffTemplate.query.get(form.template_id.data)
            if template:
                handoff.template_id = template.id
                template.use_count += 1
        
        db.session.add(handoff)
        db.session.flush()
        
        # Update team metrics
        current_user.team.total_handoffs_sent += 1
        receiving_team = Team.query.get(form.to_team.data)
        receiving_team.total_handoffs_received += 1
        
        # NEU: Wenn direkt zugewiesen, Status auf ACKNOWLEDGED setzen
        if handoff.assigned_to_id:
            handoff.status = HandoffStatus.ACKNOWLEDGED
            handoff.acknowledged_at = datetime.utcnow()
            
            # Benachrichtigung nur an zugewiesene Person
            create_notification(
                handoff.assigned_to_id,
                handoff.id,
                'assigned',
                f'New {handoff.handoff_type.value} assigned to you',
                f'{handoff.title} from {current_user.team.name}'
            )
            
            assignee = User.query.get(handoff.assigned_to_id)
            if assignee.notification_preference in [NotificationType.EMAIL, NotificationType.BOTH]:
                send_notification_email(handoff, assignee.email, 'Handoff Assigned to You')
        else:
            # Benachrichtigung an alle Team-Mitglieder
            receiving_team_members = User.query.filter_by(team_id=form.to_team.data, is_active=True).all()
            for member in receiving_team_members:
                create_notification(
                    member.id,
                    handoff.id,
                    'new_handoff',
                    f'New {handoff.handoff_type.value} from {current_user.team.name}',
                    handoff.title
                )
                
                if member.notification_preference in [NotificationType.EMAIL, NotificationType.BOTH]:
                    send_notification_email(handoff, member.email, 'New Handoff Received')
        
        db.session.commit()
        
        flash(f'Handoff {handoff.reference_id} created successfully!', 'success')
        return redirect(url_for('view_handoff', handoff_id=handoff.id))
    
    return render_template('create_handoff.html', form=form)

@app.route('/handoff/<int:handoff_id>')
@login_required
def view_handoff(handoff_id):
    handoff = Handoff.query.options(
        joinedload(Handoff.from_team),
        joinedload(Handoff.to_team),
        joinedload(Handoff.creator),
        joinedload(Handoff.assignee)
    ).get_or_404(handoff_id)
    
    # Check if user has access
    if current_user.team_id not in [handoff.from_team_id, handoff.to_team_id]:
        flash('You do not have access to this handoff.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Update view count
    handoff.view_count += 1
    
    # Mark related notifications as read
    Notification.query.filter_by(
        user_id=current_user.id,
        handoff_id=handoff_id,
        is_read=False
    ).update({'is_read': True})
    
    db.session.commit()
    
    form = CommentForm()
    comments = handoff.comments.order_by(Comment.created_at.desc()).all()
    
    # Get sub-handoffs if any
    sub_handoffs = handoff.sub_handoffs.all()
    
    # Timeline events
    timeline = []
    timeline.append({
        'date': handoff.created_at,
        'action': 'created',
        'user': handoff.creator.name,
        'details': f'Handoff created by {handoff.creator.name}'
    })
    
    if handoff.acknowledged_at:
        timeline.append({
            'date': handoff.acknowledged_at,
            'action': 'acknowledged',
            'user': handoff.assignee.name if handoff.assignee else 'System',
            'details': 'Handoff acknowledged'
        })
    
    if handoff.started_at:
        timeline.append({
            'date': handoff.started_at,
            'action': 'started',
            'user': handoff.assignee.name if handoff.assignee else 'System',
            'details': 'Work started'
        })
    
    if handoff.completed_at:
        timeline.append({
            'date': handoff.completed_at,
            'action': 'completed',
            'user': handoff.assignee.name if handoff.assignee else 'System',
            'details': 'Handoff completed'
        })
    
    timeline.sort(key=lambda x: x['date'], reverse=True)
    
    return render_template('view_handoff.html',
                         handoff=handoff,
                         form=form,
                         comments=comments,
                         sub_handoffs=sub_handoffs,
                         timeline=timeline)

@app.route('/')
def index():
    """Landing page with login/register options"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/handoff/<int:handoff_id>/update_status', methods=['POST'])
@login_required
def update_handoff_status(handoff_id):
    handoff = Handoff.query.get_or_404(handoff_id)
    
    # Check permissions
    if current_user.team_id != handoff.to_team_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    new_status = request.form.get('status')
    notes = request.form.get('notes', '')
    
    if new_status:
        try:
            old_status = handoff.status
            handoff.status = HandoffStatus(new_status)
            
            # Update timestamps and assignments
            if new_status == 'acknowledged':
                handoff.acknowledged_at = datetime.utcnow()
                if not handoff.assigned_to_id:
                    handoff.assigned_to_id = current_user.id
                    
            elif new_status == 'in_progress':
                if not handoff.acknowledged_at:
                    handoff.acknowledged_at = datetime.utcnow()
                handoff.started_at = datetime.utcnow()
                if not handoff.assigned_to_id:
                    handoff.assigned_to_id = current_user.id
                    
            elif new_status == 'completed':
                handoff.completed_at = datetime.utcnow()
                handoff.completion_notes = notes
                if handoff.assigned_to_id:
                    assignee = User.query.get(handoff.assigned_to_id)
                    assignee.update_metrics()
                    
            elif new_status == 'cancelled':
                handoff.cancelled_at = datetime.utcnow()
                handoff.rejection_reason = notes
                
            elif new_status == 'escalated':
                handoff.escalated_at = datetime.utcnow()
            
            # Create notification for creator
            create_notification(
                handoff.created_by_id,
                handoff.id,
                'status_change',
                f'Status Update: {handoff.reference_id}',
                f'Status changed from {old_status.value} to {new_status} by {current_user.name}'
            )
            
            # Send email notification
            if handoff.creator.notification_preference in [NotificationType.EMAIL, NotificationType.BOTH]:
                send_notification_email(handoff, handoff.creator.email, f'Status Updated: {new_status.replace("_", " ").title()}')
            
            # Add system comment
            comment = Comment(
                content=f'Status changed from {old_status.value.replace("_", " ").title()} to {new_status.replace("_", " ").title()}' + (f'\nNotes: {notes}' if notes else ''),
                handoff_id=handoff_id,
                user_id=current_user.id,
                is_internal=False
            )
            db.session.add(comment)
            handoff.comment_count += 1
            
            db.session.commit()
            
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
            user_id=current_user.id,
            is_internal=form.is_internal.data
        )
        db.session.add(comment)
        handoff.comment_count += 1
        
        # Create notifications for other team if not internal
        if not form.is_internal.data:
            notify_team_id = handoff.from_team_id if current_user.team_id == handoff.to_team_id else handoff.to_team_id
            team_members = User.query.filter_by(team_id=notify_team_id, is_active=True).all()
            
            for member in team_members:
                if member.id != current_user.id:
                    create_notification(
                        member.id,
                        handoff.id,
                        'comment',
                        f'New comment on {handoff.reference_id}',
                        f'{current_user.name}: {form.content.data[:100]}...'
                    )
        
        db.session.commit()
        flash('Comment added successfully!', 'success')
    
    return redirect(url_for('view_handoff', handoff_id=handoff_id))

@app.route('/teams')
@login_required
def teams():
    if not current_user.team:
        org = Organization.query.first()
        if not org:
            org = Organization(name="Default Organization")
            db.session.add(org)
            db.session.commit()
    else:
        org = current_user.team.organization
    
    teams = Team.query.filter_by(organization_id=org.id).all()
    
    # Calculate team stats
    for team in teams:
        team.member_count = User.query.filter_by(team_id=team.id, is_active=True).count()
        team.pending_handoffs = Handoff.query.filter_by(to_team_id=team.id, status=HandoffStatus.PENDING).count()
    
    form = TeamForm()
    
    return render_template('teams.html', teams=teams, form=form, organization=org)

@app.route('/teams/create', methods=['POST'])
@login_required
def create_team():
    if current_user.role not in ['admin', 'team_lead']:
        flash('Only administrators can create teams.', 'danger')
        return redirect(url_for('teams'))
    
    form = TeamForm()
    if form.validate_on_submit():
        team = Team(
            name=form.name.data,
            description=form.description.data,
            color=form.color.data,
            organization_id=current_user.team.organization_id
        )
        db.session.add(team)
        db.session.commit()
        
        flash(f'Team "{team.name}" created successfully!', 'success')
    
    return redirect(url_for('teams'))

@app.route('/notifications')
@login_required
def notifications():
    page = request.args.get('page', 1, type=int)
    notifications = current_user.notifications\
        .order_by(Notification.created_at.desc())\
        .paginate(page=page, per_page=20, error_out=False)
    
    # Mark all as read
    current_user.notifications.filter_by(is_read=False).update({'is_read': True})
    db.session.commit()
    
    return render_template('notifications.html', notifications=notifications)

@app.route('/analytics')
@login_required
def analytics():
    if not current_user.team_id:
        flash('You need to be part of a team to view analytics.', 'warning')
        return redirect(url_for('dashboard'))
    
    # Date range
    date_from = request.args.get('from', (datetime.utcnow() - timedelta(days=30)).strftime('%Y-%m-%d'))
    date_to = request.args.get('to', datetime.utcnow().strftime('%Y-%m-%d'))
    
    date_from = datetime.strptime(date_from, '%Y-%m-%d')
    date_to = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
    
    # Team statistics
    stats = {
        'total_sent': Handoff.query.filter_by(from_team_id=current_user.team_id)\
            .filter(Handoff.created_at.between(date_from, date_to)).count(),
        'total_received': Handoff.query.filter_by(to_team_id=current_user.team_id)\
            .filter(Handoff.created_at.between(date_from, date_to)).count(),
        'completed': Handoff.query.filter_by(to_team_id=current_user.team_id, status=HandoffStatus.COMPLETED)\
            .filter(Handoff.completed_at.between(date_from, date_to)).count(),
        'cancelled': Handoff.query.filter_by(to_team_id=current_user.team_id, status=HandoffStatus.CANCELLED)\
            .filter(Handoff.cancelled_at.between(date_from, date_to)).count(),
        'avg_completion_hours': 0,
        'by_priority': {},
        'by_type': {},
        'top_collaborators': []
    }
    
    # Average completion time
    completed_handoffs = Handoff.query.filter_by(to_team_id=current_user.team_id, status=HandoffStatus.COMPLETED)\
        .filter(Handoff.completed_at.between(date_from, date_to)).all()
    
    if completed_handoffs:
        total_hours = sum([h.time_elapsed for h in completed_handoffs])
        stats['avg_completion_hours'] = round(total_hours / len(completed_handoffs), 1)
    
    # By priority
    for priority in Priority:
        count = Handoff.query.filter_by(to_team_id=current_user.team_id, priority=priority)\
            .filter(Handoff.created_at.between(date_from, date_to)).count()
        stats['by_priority'][priority.value] = count
    
    # By type
    for handoff_type in HandoffType:
        count = Handoff.query.filter_by(to_team_id=current_user.team_id, handoff_type=handoff_type)\
            .filter(Handoff.created_at.between(date_from, date_to)).count()
        stats['by_type'][handoff_type.value] = count
    
    # Top collaborating teams
    collaborator_stats = db.session.query(
        Team.name,
        func.count(Handoff.id).label('count')
    ).join(
        Handoff, Team.id == Handoff.from_team_id
    ).filter(
        Handoff.to_team_id == current_user.team_id,
        Handoff.created_at.between(date_from, date_to)
    ).group_by(Team.name).order_by(desc('count')).limit(5).all()
    
    stats['top_collaborators'] = [{'name': name, 'count': count} for name, count in collaborator_stats]
    
    # Team members performance
    team_members = User.query.filter_by(team_id=current_user.team_id, is_active=True).all()
    for member in team_members:
        member.update_metrics()
    
    return render_template('analytics.html',
                         stats=stats,
                         team_members=team_members,
                         date_from=date_from.strftime('%Y-%m-%d'),
                         date_to=(date_to - timedelta(days=1)).strftime('%Y-%m-%d'))

@app.route('/export/handoffs')
@login_required
def export_handoffs():
    # Get handoffs for user's team
    handoffs = Handoff.query.filter(
        or_(
            Handoff.from_team_id == current_user.team_id,
            Handoff.to_team_id == current_user.team_id
        )
    ).order_by(Handoff.created_at.desc()).all()
    
    # Create CSV
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow([
        'Reference ID', 'Title', 'Type', 'Status', 'Priority',
        'From Team', 'To Team', 'Created By', 'Assigned To',
        'Created At', 'Deadline', 'Completed At', 'Time Elapsed (Hours)',
        'Description', 'Tags'
    ])
    
    # Data
    for h in handoffs:
        writer.writerow([
            h.reference_id,
            h.title,
            h.handoff_type.value,
            h.status.value,
            h.priority.value,
            h.from_team.name,
            h.to_team.name,
            h.creator.name,
            h.assignee.name if h.assignee else '',
            h.created_at.strftime('%Y-%m-%d %H:%M'),
            h.deadline.strftime('%Y-%m-%d %H:%M') if h.deadline else '',
            h.completed_at.strftime('%Y-%m-%d %H:%M') if h.completed_at else '',
            round(h.time_elapsed, 1) if h.status == HandoffStatus.COMPLETED else '',
            h.description,
            h.tags or ''
        ])
    
    # Create response
    output.seek(0)
    output_bytes = io.BytesIO()
    output_bytes.write(output.getvalue().encode('utf-8'))
    output_bytes.seek(0)
    
    return send_file(
        output_bytes,
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'handoffs_export_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.csv'
    )

@app.route('/api/stats')
@login_required
def api_stats():
    """API endpoint for dashboard auto-refresh with HTMX"""
    if not current_user.team_id:
        return jsonify({'error': 'No team'}), 400
    
    team_id = current_user.team_id
    
    stats = {
        'pending': Handoff.query.filter_by(to_team_id=team_id, status=HandoffStatus.PENDING).count(),
        'in_progress': Handoff.query.filter_by(to_team_id=team_id, status=HandoffStatus.IN_PROGRESS).count(),
        'completed_today': Handoff.query.filter_by(to_team_id=team_id, status=HandoffStatus.COMPLETED)\
            .filter(Handoff.completed_at >= datetime.utcnow().date()).count(),
        'overdue': sum(1 for h in Handoff.query.filter_by(to_team_id=team_id).all() if h.is_overdue),
        'unread_notifications': current_user.notifications.filter_by(is_read=False).count()
    }
    
    return jsonify(stats)

@app.route('/admin/users')
@login_required
def admin_users():
    """Admin panel for user management"""
    if current_user.role != 'admin':
        flash('Admin access required', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get all users with eager loading
    users = User.query.options(
        joinedload(User.team).joinedload(Team.organization)
    ).all()
    
    # Get counts
    teams_count = Team.query.count()
    orgs_count = Organization.query.count()
    all_teams = Team.query.all()
    
    return render_template('admin_users.html',
                         users=users,
                         teams_count=teams_count,
                         orgs_count=orgs_count,
                         all_teams=all_teams)

@app.route('/admin/users/export')
@login_required
def export_users():
    """Export users to CSV"""
    if current_user.role != 'admin':
        flash('Admin access required', 'danger')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    
    # Create CSV
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow(['ID', 'Name', 'Email', 'Team', 'Organization', 'Role', 'Status', 'Created', 'Last Seen', 'Handoffs Completed'])
    
    # Data
    for user in users:
        writer.writerow([
            user.id,
            user.name,
            user.email,
            user.team.name if user.team else '',
            user.team.organization.name if user.team else '',
            user.role or 'member',
            'Active' if user.is_active else 'Inactive',
            user.created_at.strftime('%Y-%m-%d') if user.created_at else '',
            user.last_seen.strftime('%Y-%m-%d %H:%M') if user.last_seen else 'Never',
            user.handoffs_completed or 0
        ])
    
    # Create response
    output.seek(0)
    output_bytes = io.BytesIO()
    output_bytes.write(output.getvalue().encode('utf-8'))
    output_bytes.seek(0)
    
    return send_file(
        output_bytes,
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'users_export_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.csv'
    )

@app.route('/admin/users/<int:user_id>/toggle-status', methods=['POST'])
@login_required
def toggle_user_status(user_id):
    """Activate/Deactivate user"""
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        return jsonify({'error': 'Cannot deactivate yourself'}), 400
    
    user.is_active = not user.is_active
    db.session.commit()
    
    flash(f'User {"activated" if user.is_active else "deactivated"} successfully!', 'success')
    return redirect(url_for('admin_users'))

@app.route('/api/search')
@login_required
def search():
    query = request.args.get('q', '').strip()
    if len(query) < 2:
        return jsonify([])
    
    handoffs = Handoff.query.filter(
        and_(
            or_(
                Handoff.from_team_id == current_user.team_id,
                Handoff.to_team_id == current_user.team_id
            ),
            or_(
                Handoff.title.ilike(f'%{query}%'),
                Handoff.reference_id.ilike(f'%{query}%'),
                Handoff.description.ilike(f'%{query}%')
            )
        )
    ).limit(10).all()
    
    results = [{
        'id': h.id,
        'reference_id': h.reference_id,
        'title': h.title,
        'status': h.status.value,
        'url': url_for('view_handoff', handoff_id=h.id)
    } for h in handoffs]
    
    return jsonify(results)

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

# CLI Commands
@app.cli.command()
def init_db():
    """Initialize the database."""
    db.create_all()
    print("✅ Database initialized!")

@app.cli.command()
def reset_db():
    """Reset the database."""
    db.drop_all()
    db.create_all()
    print("✅ Database reset!")

@app.cli.command()
def create_demo_data():
    """Create comprehensive demo data."""
    from random import choice, randint
    
    # Create organization
    org = Organization(name="Acme Corporation", domain="acme.com", subscription_tier="pro")
    db.session.add(org)
    db.session.flush()
    
    # Create teams
    team_info = [
        ("Sales", "Revenue generation team", "#10b981"),
        ("Marketing", "Brand and demand generation", "#f59e0b"),
        ("Development", "Product engineering", "#6366f1"),
        ("Customer Success", "Customer satisfaction", "#ec4899"),
        ("Finance", "Financial operations", "#8b5cf6"),
        ("Operations", "Business operations", "#ef4444"),
        ("HR", "People and culture", "#06b6d4"),
        ("Legal", "Legal and compliance", "#64748b")
    ]
    
    teams = []
    for name, desc, color in team_info:
        team = Team(name=name, description=desc, color=color, organization_id=org.id)
        db.session.add(team)
        teams.append(team)
    db.session.flush()
    
    # Create users
    users = []
    first_names = ["Sarah", "John", "Emily", "Michael", "Jessica", "David", "Lisa", "James"]
    last_names = ["Johnson", "Smith", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis"]
    
    for i, team in enumerate(teams):
        # Team lead
        lead = User(
            name=f"{first_names[i]} {last_names[i]}",
            email=f"{first_names[i].lower()}.{last_names[i].lower()}@acme.com",
            team_id=team.id,
            role='team_lead',
            avatar_color=team.color
        )
        lead.set_password("demo123")
        users.append(lead)
        db.session.add(lead)
        
        # Team members
        for j in range(2):
            member = User(
                name=f"{choice(first_names)} {choice(last_names)}",
                email=f"user{len(users)+1}@acme.com",
                team_id=team.id,
                role='member',
                avatar_color=f"#{secrets.token_hex(3)}"
            )
            member.set_password("demo123")
            users.append(member)
            db.session.add(member)
    
    db.session.flush()
    
    # Create templates
    templates = [
        HandoffTemplate(
            name="New Customer Onboarding",
            description="Standard process for onboarding new customers",
            title_template="Onboard new customer: {customer_name}",
            description_template="Please set up the new customer account and schedule onboarding call.",
            handoff_type=HandoffType.TASK,
            priority=Priority.HIGH,
            team_id=teams[0].id,  # Sales
            to_team_id=teams[3].id,  # Customer Success
            estimated_hours=4,
            tags="onboarding,customer",
            checklist=json.dumps([
                "Create account in CRM",
                "Send welcome email",
                "Schedule onboarding call",
                "Prepare onboarding materials",
                "Assign customer success manager"
            ])
        ),
        HandoffTemplate(
            name="Marketing Campaign Review",
            description="Review and approval process for marketing campaigns",
            title_template="Review campaign: {campaign_name}",
            description_template="Please review the attached campaign materials and provide feedback.",
            handoff_type=HandoffType.APPROVAL,
            priority=Priority.MEDIUM,
            team_id=teams[1].id,  # Marketing
            to_team_id=teams[6].id,  # Legal
            estimated_hours=2,
            tags="campaign,review,approval"
        )
    ]
    
    for template in templates:
        db.session.add(template)
    
    # Create sample handoffs
    handoff_samples = [
        {
            "title": "Onboard TechCorp Enterprise Account",
            "description": "New enterprise client signed yesterday. Premium plan with custom requirements. Contact: John Smith (john@techcorp.com). They need API access and dedicated support channel.",
            "handoff_type": HandoffType.TASK,
            "from_team": teams[0],  # Sales
            "to_team": teams[3],     # Customer Success
            "priority": Priority.URGENT,
            "status": HandoffStatus.PENDING,
            "estimated_hours": 8,
            "tags": "enterprise,vip,api"
        },
        {
            "title": "Q1 Marketing Campaign Website Updates",
            "description": "Update landing pages for Q1 campaign. New designs attached in Figma. Need responsive design and A/B testing setup. Campaign launches next Monday.",
            "handoff_type": HandoffType.TASK,
            "from_team": teams[1],  # Marketing
            "to_team": teams[2],    # Development
            "priority": Priority.HIGH,
            "status": HandoffStatus.IN_PROGRESS,
            "estimated_hours": 16,
            "tags": "campaign,website,q1"
        },
        {
            "title": "Approve Vendor Contract - CloudServices Inc",
            "description": "Please review and approve the attached contract for our new cloud infrastructure provider. Annual contract value: $125,000. Terms negotiated with 20% discount.",
            "handoff_type": HandoffType.APPROVAL,
            "from_team": teams[5],  # Operations
            "to_team": teams[4],    # Finance
            "priority": Priority.HIGH,
            "status": HandoffStatus.PENDING,
            "estimated_hours": 2,
            "tags": "contract,vendor,urgent"
        },
        {
            "title": "Bug Fix: Payment Processing Error",
            "description": "Critical bug in payment processing. Some customers seeing error during checkout. Affects approximately 5% of transactions. Error logs attached.",
            "handoff_type": HandoffType.ESCALATION,
            "from_team": teams[3],  # Customer Success
            "to_team": teams[2],    # Development
            "priority": Priority.CRITICAL,
            "status": HandoffStatus.IN_PROGRESS,
            "estimated_hours": 4,
            "tags": "bug,critical,payment"
        },
        {
            "title": "New Hire Onboarding - Sarah Chen",
            "description": "New senior developer starting Monday. Need laptop setup, access credentials, and workspace preparation. She'll be working on the API team.",
            "handoff_type": HandoffType.TASK,
            "from_team": teams[6],  # HR
            "to_team": teams[5],    # Operations
            "priority": Priority.MEDIUM,
            "status": HandoffStatus.ACKNOWLEDGED,
            "estimated_hours": 3,
            "tags": "onboarding,new-hire,setup"
        }
    ]
    
    for i, sample in enumerate(handoff_samples):
        handoff = Handoff(
            title=sample["title"],
            description=sample["description"],
            handoff_type=sample["handoff_type"],
            from_team_id=sample["from_team"].id,
            to_team_id=sample["to_team"].id,
            created_by_id=choice([u.id for u in users if u.team_id == sample["from_team"].id]),
            priority=sample["priority"],
            status=sample["status"],
            estimated_hours=sample["estimated_hours"],
            tags=sample["tags"],
            deadline=datetime.utcnow() + timedelta(days=randint(1, 7))
        )
        
        # Set additional fields based on status
        if sample["status"] == HandoffStatus.IN_PROGRESS:
            handoff.acknowledged_at = datetime.utcnow() - timedelta(hours=randint(1, 24))
            handoff.started_at = datetime.utcnow() - timedelta(hours=randint(1, 12))
            handoff.assigned_to_id = choice([u.id for u in users if u.team_id == sample["to_team"].id])
        elif sample["status"] == HandoffStatus.ACKNOWLEDGED:
            handoff.acknowledged_at = datetime.utcnow() - timedelta(hours=randint(1, 6))
            handoff.assigned_to_id = choice([u.id for u in users if u.team_id == sample["to_team"].id])
        
        db.session.add(handoff)
    
    db.session.commit()
    
    print("✅ Demo data created successfully!")
    print("\n📧 Demo accounts (all passwords: demo123):")
    print("   Admin: sarah.johnson@acme.com")
    print("   Team Lead: john.smith@acme.com")
    print("   Member: emily.williams@acme.com")
    print("\n🚀 Your HandoffHub is ready with sample data!")


with app.app_context():
    try:
        db.create_all()
        print("✅ Database tables created successfully!")
        
        # Verify tables exist
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        print(f"📊 Created tables: {', '.join(tables)}")
    except Exception as e:
        print(f"Database initialization note: {e}")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
