#!/usr/bin/env python
"""Initialisiert die Datenbank beim Deployment"""

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
        from app import User, Team, Organization, Handoff
        
        # Prüfe ob Daten bereits existieren
        existing_orgs = Organization.query.count()
        existing_users = User.query.count()
        existing_handoffs = Handoff.query.count()
        
        print(f"📊 Existing data: {existing_orgs} orgs, {existing_users} users, {existing_handoffs} handoffs")
        
        if existing_orgs == 0 and existing_users == 0:
            print("📝 Creating initial demo data...")
            create_minimal_demo_data()
        else:
            print("ℹ️ Database already contains data, skipping demo data creation")
            print(f"   Organizations: {existing_orgs}")
            print(f"   Users: {existing_users}")
            print(f"   Handoffs: {existing_handoffs}")

def create_minimal_demo_data():
    """Erstellt minimale Demo-Daten für den Start"""
    from app import (Organization, Team, User, Handoff, HandoffStatus, 
                    HandoffType, Priority, db)
    
    try:
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
        
        users = []
        for name, email, team_id, role in demo_users:
            user = User(
                name=name,
                email=email,
                team_id=team_id,
                role=role,
                avatar_color=f"#{secrets.token_hex(3)}"
            )
            user.set_password("demo123")
            users.append(user)
            db.session.add(user)
        
        db.session.flush()
        
        # WICHTIG: Commit vor Handoff-Erstellung, damit reference_id korrekt generiert wird
        db.session.commit()
        
        # Jetzt Handoffs erstellen (nach dem Commit, damit die ID-Generierung funktioniert)
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
        
        # Manuell reference_id setzen falls Probleme
        year = datetime.utcnow().year
        existing_count = Handoff.query.filter(db.extract('year', Handoff.created_at) == year).count()
        handoff1.reference_id = f"HO-{year}-{existing_count + 1:04d}"
        
        db.session.add(handoff1)
        db.session.flush()
        
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
        
        # Manuell reference_id setzen
        handoff2.reference_id = f"HO-{year}-{existing_count + 2:04d}"
        
        db.session.add(handoff2)
        db.session.commit()
        
        print("✅ Demo data created successfully!")
        print("\n📧 Login Credentials:")
        print("   Admin: admin@demo.com / admin123")
        print("   User: john@demo.com / demo123")
        print("\n🚀 HandoffHub is ready!")
        
    except Exception as e:
        print(f"⚠️ Error creating demo data: {e}")
        db.session.rollback()
        
        # Versuche es ohne Handoffs
        try:
            db.session.commit()
            print("✅ Basic data created (without handoffs)")
            print("\n📧 Login Credentials:")
            print("   Admin: admin@demo.com / admin123")
            print("   User: john@demo.com / demo123")
        except:
            print("❌ Failed to create demo data")
            raise

def reset_database():
    """Komplett zurücksetzen falls nötig"""
    with app.app_context():
        print("⚠️ Resetting database...")
        db.drop_all()
        db.create_all()
        print("✅ Database reset complete")
        create_minimal_demo_data()

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "reset":
        reset_database()
    else:
        init_database()
