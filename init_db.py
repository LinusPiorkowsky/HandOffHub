"""
Database initialization script for Railway deployment
Run this once to create all tables and sample data
"""

from app import app, db, User, Team, Organization, Handoff, Priority, HandoffStatus
from datetime import datetime, timedelta

def init_database():
    with app.app_context():
        # Create all tables
        db.create_all()
        print("✅ Database tables created!")
        
        # Check if data already exists
        if Organization.query.first():
            print("⚠️  Database already has data. Skipping initialization.")
            return
        
        # Create sample organization
        org = Organization(name="Demo Company")
        db.session.add(org)
        db.session.flush()
        
        # Create teams
        teams = [
            Team(name="Sales", organization_id=org.id),
            Team(name="Marketing", organization_id=org.id),
            Team(name="Development", organization_id=org.id),
            Team(name="Customer Success", organization_id=org.id),
            Team(name="Finance", organization_id=org.id)
        ]
        
        for team in teams:
            db.session.add(team)
        db.session.flush()
        
        # Create demo users
        demo_users = [
            {"name": "Sarah Sales", "email": "sarah@demo.com", "team_id": teams[0].id},
            {"name": "Mark Marketing", "email": "mark@demo.com", "team_id": teams[1].id},
            {"name": "David Developer", "email": "david@demo.com", "team_id": teams[2].id},
            {"name": "Clara Customer", "email": "clara@demo.com", "team_id": teams[3].id},
            {"name": "Frank Finance", "email": "frank@demo.com", "team_id": teams[4].id}
        ]
        
        users = []
        for user_data in demo_users:
            user = User(
                name=user_data["name"],
                email=user_data["email"],
                team_id=user_data["team_id"]
            )
            user.set_password("demo123")  # Same password for all demo users
            db.session.add(user)
            users.append(user)
        
        db.session.flush()
        
        # Create sample handoffs
        sample_handoffs = [
            {
                "title": "New Enterprise Client Onboarding - TechCorp",
                "description": "Please set up the new enterprise account for TechCorp. They signed for the premium plan. Contact person: John Smith",
                "from_team_id": teams[0].id,  # Sales
                "to_team_id": teams[3].id,     # Customer Success
                "created_by_id": users[0].id,
                "priority": Priority.HIGH,
                "status": HandoffStatus.PENDING,
                "deadline": datetime.utcnow() + timedelta(days=2)
            },
            {
                "title": "Website Banner Update for Q1 Campaign",
                "description": "Need new banners for the Q1 marketing campaign. Dimensions: 1920x600, 728x90, 300x250. Brand guidelines attached in Drive.",
                "from_team_id": teams[1].id,  # Marketing
                "to_team_id": teams[2].id,    # Development
                "created_by_id": users[1].id,
                "priority": Priority.MEDIUM,
                "status": HandoffStatus.IN_PROGRESS,
                "assigned_to_id": users[2].id,
                "started_at": datetime.utcnow() - timedelta(hours=3)
            },
            {
                "title": "Invoice Approval - Vendor ABC",
                "description": "Please approve the attached invoice for Vendor ABC. Amount: $5,400. Budget approved in last quarter.",
                "from_team_id": teams[3].id,  # Customer Success
                "to_team_id": teams[4].id,    # Finance
                "created_by_id": users[3].id,
                "priority": Priority.URGENT,
                "status": HandoffStatus.PENDING,
                "deadline": datetime.utcnow() + timedelta(days=1)
            }
        ]
        
        for handoff_data in sample_handoffs:
            handoff = Handoff(**handoff_data)
            db.session.add(handoff)
        
        # Commit all changes
        db.session.commit()
        
        print("✅ Sample data created successfully!")
        print("\n📧 Demo accounts created:")
        for user_data in demo_users:
            print(f"   Email: {user_data['email']} | Password: demo123")
        print("\n🚀 Your HandoffHub is ready to use!")

if __name__ == "__main__":
    init_database()
