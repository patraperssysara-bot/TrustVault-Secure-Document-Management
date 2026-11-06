
import pytest
import os
import tempfile

from app import app, generate_audit_hash, record_activity
from database import db, User, Document, Permission, AuditLog
from werkzeug.security import generate_password_hash


@pytest.fixture
def client():
    # Create a separate temporary database for testing
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    upload_folder = tempfile.mkdtemp()

    app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///" + db_path,
        "WTF_CSRF_ENABLED": False,
        "UPLOAD_FOLDER": upload_folder
    })

    with app.app_context():
        db.create_all()

        owner = User(
            username="testowner",
            password=generate_password_hash("owner123"),
            role="owner"
        )

        viewer = User(
            username="testviewer",
            password=generate_password_hash("viewer123"),
            role="viewer"
        )

        admin = User(
            username="testadmin",
            password=generate_password_hash("admin123"),
            role="admin"
        )

        db.session.add_all([owner, viewer, admin])
        db.session.commit()

        document = Document(
            filename="sample.pdf",
            owner_id=owner.id,
            category="Testing"
        )

        db.session.add(document)
        db.session.commit()

        with open(
            os.path.join(upload_folder, "1.pdf"),
            "wb"
        ) as file:
            file.write(b"%PDF-1.4 test document")

    with app.test_client() as test_client:
        yield test_client

    with app.app_context():
        db.session.remove()
        db.drop_all()
        db.engine.dispose()

    os.close(db_fd)
    os.unlink(db_path)

    import shutil
    shutil.rmtree(upload_folder, ignore_errors=True)


def login(client, username, password):
    return client.post(
        "/login",
        data={
            "username": username,
            "password": password
        },
        follow_redirects=True
    )


# TEST 1: Viewer cannot download without permission

def test_viewer_cannot_download_without_permission(client):
    login(client, "testviewer", "viewer123")

    response = client.get("/download/1")

    assert response.status_code == 403


# TEST 2: Viewer cannot view without permission

def test_viewer_cannot_view_without_permission(client):
    login(client, "testviewer", "viewer123")

    response = client.get("/view/1")

    assert response.status_code == 403


# TEST 3: Viewer can download with permission

def test_viewer_can_download_with_permission(client):
    with app.app_context():
        viewer = User.query.filter_by(
            username="testviewer"
        ).first()

        db.session.add(Permission(
            document_id=1,
            user_id=viewer.id,
            access_type="read"
        ))
        db.session.commit()

    login(client, "testviewer", "viewer123")

    response = client.get("/download/1")

    assert response.status_code == 200


# TEST 4: Revoked permission blocks download

def test_revoked_permission_blocks_download(client):
    with app.app_context():
        viewer = User.query.filter_by(
            username="testviewer"
        ).first()

        permission = Permission(
            document_id=1,
            user_id=viewer.id,
            access_type="read"
        )

        db.session.add(permission)
        db.session.commit()

        db.session.delete(permission)
        db.session.commit()

    login(client, "testviewer", "viewer123")

    response = client.get("/download/1")

    assert response.status_code == 403


# TEST 5: Viewer cannot access Admin Dashboard

def test_viewer_cannot_open_admin_dashboard(client):
    login(client, "testviewer", "viewer123")

    response = client.get("/admin")

    assert response.status_code == 403


# TEST 6: Owner can download own document

def test_owner_can_download_own_document(client):
    login(client, "testowner", "owner123")

    response = client.get("/download/1")

    assert response.status_code == 200


# TEST 7: Audit hash is generated successfully

def test_audit_hash_generation(client):
    with app.app_context():
        result = record_activity(1, "Test audit activity")

        assert result is True

        log = AuditLog.query.order_by(
            AuditLog.id.desc()
        ).first()

        assert log is not None
        assert log.entry_hash is not None
        assert len(log.entry_hash) == 64


# TEST 8: Audit hash detects record modification

def test_audit_hash_detects_tampering(client):
    with app.app_context():
        record_activity(1, "Original activity")

        log = AuditLog.query.order_by(
            AuditLog.id.desc()
        ).first()

        original_hash = log.entry_hash

        # Change the activity without updating its stored hash
        log.action = "Modified activity"

        calculated_hash = generate_audit_hash(
            log,
            log.previous_hash
        )

        assert calculated_hash != original_hash
