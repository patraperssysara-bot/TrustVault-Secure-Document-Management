
from getpass import getpass
from werkzeug.security import generate_password_hash

from app import app
from database import db, User

with app.app_context():

    username = input("Enter Admin Username: ").strip()
    password = getpass("Enter Admin Password: ")

    existing_user = User.query.filter_by(
        username=username
    ).first()

    if existing_user:
        print("Username already exists. Choose another username.")

    elif not username or not password:
        print("Username and password cannot be empty.")

    else:
        admin = User(
            username=username,
            password=generate_password_hash(password),
            role="admin"
        )

        db.session.add(admin)
        db.session.commit()

        print("Admin account created successfully!")
