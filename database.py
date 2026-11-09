
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)


class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    owner_id = db.Column(
        db.Integer,
        db.ForeignKey('user.id'),
        nullable=False
    )
    category = db.Column(db.String(100))
    upload_date = db.Column(
        db.DateTime,
        default=db.func.current_timestamp()
    )


class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(
        db.Integer,
        db.ForeignKey('document.id'),
        nullable=False
    )
    user_id = db.Column(
        db.Integer,
        db.ForeignKey('user.id'),
        nullable=False
    )
    access_type = db.Column(db.String(10), nullable=False)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    action = db.Column(db.String(100), nullable=False)
    document_id = db.Column(db.Integer)
    timestamp = db.Column(
        db.DateTime,
        default=db.func.current_timestamp()
    )

    previous_hash = db.Column(db.String(64), nullable=True)
    entry_hash = db.Column(db.String(64), nullable=True)


# Stores the private ID-proof file path for an Owner account
class OwnerIDProof(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey('user.id'),
        unique=True,
        nullable=False
    )

    filename = db.Column(db.String(255), nullable=False)

    uploaded_at = db.Column(
        db.DateTime,
        default=db.func.current_timestamp()
    )
