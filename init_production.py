# init_production.py - Production Database Initialization
"""
Production database initialization script
Run this once after deployment to set up initial data
"""

import os
import sys
from app import app, db, User, Team, Organization, HandoffTemplate, HandoffType, Priority
import secrets

def init_production_db():
    """Initialize production database with essential data"""
    
    with app.app_context():
        # Create tables
        db.create_all()
        print("✅ Database tables created")
        
        # Check if already initialized
        if Organization.query.first():
            print("⚠️  Database already initialized. Skipping.")
            return
        
        # Create default organization
        org = Organization(
            name="Your Company",
            subscription_tier="pro",
            max_users=50,
            allow_templates=True
        )
        db.session.add(org)
        db.session.flush()
        
        # Create essential teams
        essential_teams = [
            ("Management", "Executive team and leadership", "#ef4444"),
            ("Operations", "Business operations", "#f59e0b"),
            ("Support", "Customer support team", "#10b981"),
            ("Admin", "Administrative team", "#6366f1")
        ]
        
        teams = []
        for name, desc, color in essential_teams:
            team = Team(
                name=name,
                description=desc,
                color=color,
                organization_id=org.id
            )
            db.session.add(team)
            teams.append(team)
        
        db.session.flush()
        
        # Create admin user
        admin_email = os.environ.get('ADMIN_EMAIL', 'admin@handoffhub.com')
        admin_password = os.environ.get('ADMIN_PASSWORD', secrets.token_urlsafe(16))
        
        admin = User(
            name="System Administrator",
            email=admin_email,
            team_id=teams[0].id,  # Management team
            role='admin',
            avatar_color='#ef4444'
        )
        admin.set_password(admin_password)
        db.session.add(admin)
        
        # Create useful templates
        templates = [
            {
                "name": "Urgent Request",
                "description": "For time-sensitive requests requiring immediate attention",
                "title_template": "URGENT: {request_title}",
                "description_template": "This is an urgent request that requires immediate attention.\n\nDetails: {details}\n\nDeadline: {deadline}",
                "handoff_type": HandoffType.TASK,
                "priority": Priority.URGENT,
                "team_id": teams[0].id,
                "estimated_hours": 2
            },
            {
                "name": "Approval Request",
                "description": "Standard approval request template",
                "title_template": "Approval Needed: {item_name}",
                "description_template": "Please review and approve the following:\n\n{description}\n\nApproval deadline: {deadline}",
                "handoff_type": HandoffType.APPROVAL,
                "priority": Priority.HIGH,
                "team_id": teams[0].id,
                "estimated_hours": 1
            },
            {
                "name": "Bug Report",
                "description": "Report technical issues or bugs",
                "title_template": "Bug: {bug_title}",
                "description_template": "Bug Description: {description}\n\nSteps to Reproduce:\n{steps}\n\nExpected Behavior:\n{expected}\n\nActual Behavior:\n{actual}",
                "handoff_type": HandoffType.ESCALATION,
                "priority": Priority.HIGH,
                "team_id": teams[2].id,
                "estimated_hours": 4
            }
        ]
        
        for template_data in templates:
            template = HandoffTemplate(**template_data)
            db.session.add(template)
        
        # Commit everything
        db.session.commit()
        
        print("\n" + "="*50)
        print("🚀 PRODUCTION DATABASE INITIALIZED SUCCESSFULLY!")
        print("="*50)
        print(f"\n📧 Admin Account Created:")
        print(f"   Email: {admin_email}")
        print(f"   Password: {admin_password}")
        print(f"\n⚠️  IMPORTANT: Save these credentials and change the password immediately!")
        print(f"\n✅ {len(teams)} teams created")
        print(f"✅ {len(templates)} templates created")
        print("\nYour HandoffHub is ready for production use!")
        print("="*50 + "\n")

if __name__ == "__main__":
    # Allow passing admin credentials as arguments
    if len(sys.argv) > 1:
        os.environ['ADMIN_EMAIL'] = sys.argv[1]
    if len(sys.argv) > 2:
        os.environ['ADMIN_PASSWORD'] = sys.argv[2]
    
    init_production_db()
