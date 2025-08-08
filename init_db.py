from app import app, db
from datetime import datetime, timedelta
import secrets
import json

def init_database():
    with app.app_context():
        # Erstelle alle Tabellen
        db.create_all()
        print("✅ Database tables created!")
        
        # Prüfe ob Demo-Daten benötigt werden
        from app import User, Team, Organization
        
        if Organization.query.count() == 0:
            print("📝 Creating initial demo data...")
            create_minimal_demo_data()
        else:
            print("ℹ️ Database already contains data, skipping demo data creation")

def create_minimal_demo_data():
    '''Erstellt minimale Demo-Daten für den Start'''
    from app import (Organization, Team, User, Handoff, HandoffStatus, 
                    HandoffType, Priority, db)
    
    # Organisation
    org = Organization(
        name="Demo Company",
        domain="demo.com",
        subscription_tier="starter"
    )
    db.session.add(org)
    db.session.flush()
    
    # Teams
    teams_data = [
        ("Operations", "#6366f1"),
        ("Development", "#10b981"),
        ("Support", "#f59e0b"),
        ("Management", "#ef4444")
    ]
    
    teams = []
    for name, color in teams_data:
        team = Team(
            name=name,
            description=f"{name} Team",
            color=color,
            organization_id=org.id
        )
        teams.append(team)
        db.session.add(team)
    
    db.session.flush()
    
    # Admin User
    admin = User(
        name="Admin User",
        email="admin@demo.com",
        team_id=teams[3].id,  # Management
        role='admin',
        avatar_color="#ef4444"
    )
    admin.set_password("admin123")
    db.session.add(admin)
    
    # Demo Users
    demo_users = [
        ("John Doe", "john@demo.com", teams[0].id, 'team_lead'),
        ("Jane Smith", "jane@demo.com", teams[1].id, 'member'),
        ("Bob Wilson", "bob@demo.com", teams[2].id, 'member')
    ]
    
    for name, email, team_id, role in demo_users:
        user = User(
            name=name,
            email=email,
            team_id=team_id,
            role=role,
            avatar_color=f"#{secrets.token_hex(3)}"
        )
        user.set_password("demo123")
        db.session.add(user)
    
    db.session.flush()
    
    # Beispiel Handoffs
    handoff1 = Handoff(
        title="Welcome to HandoffHub!",
        description="This is your first handoff. You can assign it, change its status, add comments, and track progress.",
        handoff_type=HandoffType.TASK,
        from_team_id=teams[3].id,
        to_team_id=teams[0].id,
        created_by_id=admin.id,
        priority=Priority.MEDIUM,
        deadline=datetime.utcnow() + timedelta(days=7),
        tags="welcome,demo,getting-started"
    )
    
    handoff2 = Handoff(
        title="System Setup Required",
        description="Please configure the email settings and invite your team members to get started.",
        handoff_type=HandoffType.TASK,
        from_team_id=teams[0].id,
        to_team_id=teams[1].id,
        created_by_id=admin.id,
        priority=Priority.HIGH,
        deadline=datetime.utcnow() + timedelta(days=3),
        tags="setup,configuration"
    )
    
    db.session.add(handoff1)
    db.session.add(handoff2)
    db.session.commit()
    
    print("✅ Demo data created!")
    print("\n📧 Login Credentials:")
    print("   Admin: admin@demo.com / admin123")
    print("   User: john@demo.com / demo123")
    print("\n🚀 HandoffHub is ready!")

if __name__ == "__main__":
    init_database()
