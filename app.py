
import os
import hashlib
import json
import uuid

from functools import wraps
from datetime import datetime, timedelta

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort, send_file
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect

from database import (
    db, User, Document, Permission,
    AuditLog, OwnerIDProof
)


# --------------------------------------------------
# APPLICATION CONFIGURATION
# --------------------------------------------------

app = Flask(__name__)

app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

if not app.config['SECRET_KEY']:
    raise RuntimeError(
        "SECRET_KEY environment variable is not set."
    )

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///trustvault.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024

app.config['UPLOAD_FOLDER'] = os.path.join(
    app.root_path,
    'private_uploads'
)

# Private folder for Owner ID proofs
app.config['ID_PROOF_FOLDER'] = os.path.join(
    app.root_path,
    'private_id_proofs'
)

ALLOWED_EXTENSIONS = {
    'pdf', 'docx', 'txt', 'png', 'jpg', 'jpeg'
}

ALLOWED_ID_PROOF_EXTENSIONS = {
    'pdf', 'png', 'jpg', 'jpeg'
}

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['ID_PROOF_FOLDER'], exist_ok=True)

db.init_app(app)
csrf = CSRFProtect(app)


# --------------------------------------------------
# TAMPER-EVIDENT AUDIT HASHING
# --------------------------------------------------

def generate_audit_hash(log, previous_hash):

    audit_data = {
        'id': log.id,
        'user_id': log.user_id,
        'action': log.action,
        'document_id': log.document_id,
        'timestamp': log.timestamp.isoformat()
    }

    serialized_data = json.dumps(
        audit_data,
        sort_keys=True,
        separators=(',', ':')
    )

    hash_input = previous_hash + serialized_data

    return hashlib.sha256(
        hash_input.encode('utf-8')
    ).hexdigest()


# --------------------------------------------------
# AUDIT LOGGING
# --------------------------------------------------

def record_activity(user_id, action, document_id=None):

    try:

        previous_log = AuditLog.query.filter(
            AuditLog.entry_hash.isnot(None)
        ).order_by(
            AuditLog.id.desc()
        ).first()

        if previous_log:
            previous_hash = previous_log.entry_hash
        else:
            previous_hash = 'GENESIS'

        log = AuditLog(
            user_id=user_id,
            action=action,
            document_id=document_id,
            previous_hash=previous_hash
        )

        db.session.add(log)
        db.session.flush()

        log.entry_hash = generate_audit_hash(
            log,
            previous_hash
        )

        db.session.commit()

        return True

    except Exception:

        db.session.rollback()

        app.logger.exception(
            'Audit record creation failed'
        )

        return False


# --------------------------------------------------
# LOGIN REQUIRED
# --------------------------------------------------

def login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if 'user_id' not in session:

            flash('Please log in first.', 'error')

            return redirect(url_for('login'))

        return function(*args, **kwargs)

    return wrapper


# --------------------------------------------------
# ROLE REQUIRED
# --------------------------------------------------

def role_required(required_role):

    def decorator(function):

        @wraps(function)
        def wrapper(*args, **kwargs):

            if session.get('role') != required_role:
                abort(403)

            return function(*args, **kwargs)

        return wrapper

    return decorator


# --------------------------------------------------
# CHECK FILE EXTENSION
# --------------------------------------------------

def allowed_file(filename):

    return (
        '.' in filename
        and filename.rsplit('.', 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


# --------------------------------------------------
# HOME
# --------------------------------------------------

@app.route('/')
def home():

    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    return redirect(url_for('login'))


# --------------------------------------------------
# REGISTER
# VIEWER: NORMAL REGISTRATION
# OWNER: ID PROOF REQUIRED
# NO ADMIN APPROVAL
# --------------------------------------------------

@app.route('/register', methods=['GET', 'POST'])
def register():

    if request.method == 'POST':

        username = request.form.get(
            'username', ''
        ).strip()

        password = request.form.get(
            'password', ''
        )

        selected_role = request.form.get(
            'role', ''
        ).strip().lower()

        if not username or not password:

            flash(
                'Please enter username and password.',
                'error'
            )

            return redirect(url_for('register'))

        if len(password) < 8:

            flash(
                'Password must be at least 8 characters.',
                'error'
            )

            return redirect(url_for('register'))

        if selected_role not in ['viewer', 'owner']:

            flash(
                'Please select a valid account role.',
                'error'
            )

            return redirect(url_for('register'))

        existing_user = User.query.filter_by(
            username=username
        ).first()

        if existing_user:

            flash(
                'Username already exists.',
                'error'
            )

            return redirect(url_for('register'))

        proof_file = None
        proof_extension = None
        saved_proof_path = None

        # ID proof is compulsory only for Owner registration.
        if selected_role == 'owner':

            proof_file = request.files.get('id_proof')

            if not proof_file or not proof_file.filename:

                flash(
                    'Owner registration requires an ID proof.',
                    'error'
                )

                return redirect(url_for('register'))

            original_name = secure_filename(
                proof_file.filename
            )

            if not original_name or '.' not in original_name:

                flash(
                    'Please upload a valid ID proof.',
                    'error'
                )

                return redirect(url_for('register'))

            proof_extension = original_name.rsplit(
                '.', 1
            )[1].lower()

            if proof_extension not in ALLOWED_ID_PROOF_EXTENSIONS:

                flash(
                    'ID proof must be PDF, PNG, JPG, or JPEG.',
                    'error'
                )

                return redirect(url_for('register'))

        try:

            new_user = User(
                username=username,
                password=generate_password_hash(password),
                role=selected_role
            )

            db.session.add(new_user)
            db.session.flush()

            # Save Owner ID proof with a unique filename.
            if selected_role == 'owner':

                proof_filename = (
                    f'{uuid.uuid4().hex}.{proof_extension}'
                )

                saved_proof_path = os.path.join(
                    app.config['ID_PROOF_FOLDER'],
                    proof_filename
                )

                proof_file.save(saved_proof_path)

                proof_record = OwnerIDProof(
                    user_id=new_user.id,
                    filename=proof_filename
                )

                db.session.add(proof_record)

            db.session.commit()

            if selected_role == 'owner':

                registration_action = (
                    'New owner account registered with ID proof'
                )

            else:

                registration_action = (
                    'New viewer account registered'
                )

            record_activity(
                new_user.id,
                registration_action
            )

            flash(
                'Registration successful. Please log in.',
                'success'
            )

            return redirect(url_for('login'))

        except Exception:

            db.session.rollback()

            # Remove proof if database registration fails.
            if saved_proof_path and os.path.isfile(saved_proof_path):

                try:
                    os.remove(saved_proof_path)

                except OSError:

                    app.logger.exception(
                        'Could not remove incomplete ID proof upload'
                    )

            app.logger.exception(
                'Registration failed'
            )

            flash(
                'Registration failed. Please try again.',
                'error'
            )

            return redirect(url_for('register'))

    return render_template('register.html')


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        username = request.form.get(
            'username', ''
        ).strip()

        password = request.form.get(
            'password', ''
        )

        user = User.query.filter_by(
            username=username
        ).first()

        if user and check_password_hash(
            user.password,
            password
        ):

            session.clear()

            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role

            record_activity(
                user.id,
                'User logged in'
            )

            flash(
                f'Successfully logged in to your account, {user.username}!',
                'success'
            )

            return redirect(url_for('dashboard'))

        else:

            failed_action = (
                f'Failed login attempt for username: {username}'
            )

            record_activity(
                None,
                failed_action
            )

            cutoff_time = (
                datetime.utcnow() - timedelta(minutes=10)
            )

            failed_count = AuditLog.query.filter(
                AuditLog.action == failed_action,
                AuditLog.timestamp >= cutoff_time
            ).count()

            if failed_count == 3:

                record_activity(
                    None,
                    'SUSPICIOUS ACTIVITY: 3 failed login attempts '
                    f'within 10 minutes for username: {username}'
                )

            flash(
                'Incorrect username or password. Please try again.',
                'error'
            )

    return render_template('login.html')


# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

@app.route('/dashboard')
@login_required
def dashboard():

    user = db.session.get(
        User,
        session['user_id']
    )

    if not user:

        session.clear()

        flash(
            'Your session has expired. Please log in again.',
            'error'
        )

        return redirect(url_for('login'))

    return render_template(
        'dashboard.html',
        user=user,
        username=user.username,
        role=user.role
    )


# --------------------------------------------------
# DOCUMENT LIST WITH SEARCH AND FILTERING
# --------------------------------------------------

@app.route('/documents')
@login_required
def documents():

    user_id = session['user_id']
    role = session.get('role')

    search = request.args.get(
        'search', ''
    ).strip()

    category = request.args.get(
        'category', ''
    ).strip()

    owner_name = request.args.get(
        'owner', ''
    ).strip()

    upload_date = request.args.get(
        'date', ''
    ).strip()

    if role == 'owner':

        document_query = Document.query.filter_by(
            owner_id=user_id
        )

    else:

        document_query = Document.query.join(
            Permission,
            Document.id == Permission.document_id
        ).filter(
            Permission.user_id == user_id,
            Permission.access_type.in_(['read', 'edit'])
        )

    if search:

        document_query = document_query.filter(
            db.or_(
                Document.filename.ilike(f'%{search}%'),
                Document.category.ilike(f'%{search}%')
            )
        )

    if category:

        document_query = document_query.filter(
            Document.category.ilike(f'%{category}%')
        )

    if owner_name:

        document_query = document_query.join(
            User,
            Document.owner_id == User.id
        ).filter(
            User.username.ilike(f'%{owner_name}%')
        )

    if upload_date:

        try:

            datetime.strptime(
                upload_date,
                '%Y-%m-%d'
            )

            document_query = document_query.filter(
                db.func.date(Document.upload_date)
                == upload_date
            )

        except ValueError:

            flash(
                'Invalid date format. Please select a valid date.',
                'error'
            )

    user_documents = document_query.order_by(
        Document.id.desc()
    ).all()

    shared_permissions = {}

    if role == 'owner':

        for document in user_documents:

            permissions = Permission.query.filter_by(
                document_id=document.id
            ).all()

            shared_permissions[document.id] = []

            for permission in permissions:

                shared_user = db.session.get(
                    User,
                    permission.user_id
                )

                if shared_user:

                    shared_permissions[document.id].append({
                        'user_id': permission.user_id,
                        'username': shared_user.username,
                        'access_type': permission.access_type
                    })

    return render_template(
        'documents.html',
        documents=user_documents,
        shared_permissions=shared_permissions
    )


# --------------------------------------------------
# UPLOAD DOCUMENT
# --------------------------------------------------

@app.route('/upload', methods=['POST'])
@login_required
@role_required('owner')
def upload():

    uploaded_file = request.files.get('document')

    category = request.form.get(
        'category', ''
    ).strip()

    if not uploaded_file or uploaded_file.filename == '':

        flash(
            'Please select a document.',
            'error'
        )

        return redirect(url_for('documents'))

    if not allowed_file(uploaded_file.filename):

        flash(
            'File type not allowed.',
            'error'
        )

        return redirect(url_for('documents'))

    if not category:

        flash(
            'Please enter a document category.',
            'error'
        )

        return redirect(url_for('documents'))

    filename = secure_filename(
        uploaded_file.filename
    )

    if not filename:

        flash(
            'Invalid filename.',
            'error'
        )

        return redirect(url_for('documents'))

    extension = filename.rsplit('.', 1)[1].lower()

    try:

        document = Document(
            filename=filename,
            owner_id=session['user_id'],
            category=category
        )

        db.session.add(document)
        db.session.flush()

        file_path = os.path.join(
            app.config['UPLOAD_FOLDER'],
            f'{document.id}.{extension}'
        )

        uploaded_file.save(file_path)

        db.session.commit()

        record_activity(
            session['user_id'],
            'Document uploaded',
            document.id
        )

        flash(
            'Document uploaded successfully!',
            'success'
        )

    except Exception:

        db.session.rollback()

        app.logger.exception(
            'Document upload failed'
        )

        flash(
            'Document upload failed. Please try again.',
            'error'
        )

    return redirect(url_for('documents'))


# --------------------------------------------------
# DOCUMENT DOWNLOAD
# --------------------------------------------------

@app.route('/download/<int:document_id>')
@login_required
def download(document_id):

    user_id = session['user_id']

    document = db.session.get(
        Document,
        document_id
    )

    if not document:
        abort(404)

    permission = Permission.query.filter_by(
        document_id=document_id,
        user_id=user_id
    ).first()

    allowed = (
        document.owner_id == user_id
        or (
            permission is not None
            and permission.access_type in ['read', 'edit']
        )
    )

    if not allowed:

        record_activity(
            user_id,
            'Denied document download',
            document_id
        )

        abort(403)

    extension = document.filename.rsplit(
        '.', 1
    )[-1].lower()

    file_path = os.path.join(
        app.config['UPLOAD_FOLDER'],
        f'{document.id}.{extension}'
    )

    if not os.path.isfile(file_path):
        abort(404)

    record_activity(
        user_id,
        'Document downloaded',
        document_id
    )

    return send_file(
        file_path,
        as_attachment=True,
        download_name=document.filename
    )


# --------------------------------------------------
# SECURE DOCUMENT VIEWING
# --------------------------------------------------

@app.route('/view/<int:document_id>')
@login_required
def view_document(document_id):

    user_id = session['user_id']

    document = db.session.get(
        Document,
        document_id
    )

    if not document:
        abort(404)

    permission = Permission.query.filter_by(
        document_id=document_id,
        user_id=user_id
    ).first()

    allowed = (
        document.owner_id == user_id
        or (
            permission is not None
            and permission.access_type in ['read', 'edit']
        )
    )

    if not allowed:

        record_activity(
            user_id,
            'Denied document viewing',
            document_id
        )

        abort(403)

    extension = document.filename.rsplit(
        '.', 1
    )[-1].lower()

    if extension != 'pdf':

        flash(
            'Browser viewing is currently available for PDF files only.',
            'error'
        )

        return redirect(url_for('documents'))

    file_path = os.path.join(
        app.config['UPLOAD_FOLDER'],
        f'{document.id}.{extension}'
    )

    if not os.path.isfile(file_path):
        abort(404)

    record_activity(
        user_id,
        'Document viewed',
        document_id
    )

    response = send_file(
        file_path,
        mimetype='application/pdf',
        as_attachment=False,
        download_name=document.filename
    )

    response.headers['X-Content-Type-Options'] = 'nosniff'

    response.headers['Content-Security-Policy'] = (
        "default-src 'none'; style-src 'unsafe-inline';"
    )

    return response


# --------------------------------------------------
# SHARE DOCUMENT
# --------------------------------------------------

@app.route('/share/<int:document_id>', methods=['POST'])
@login_required
@role_required('owner')
def share_document(document_id):

    user_id = session['user_id']

    document = db.session.get(
        Document,
        document_id
    )

    if not document or document.owner_id != user_id:
        abort(403)

    username = request.form.get(
        'username', ''
    ).strip()

    access_type = request.form.get(
        'access_type', ''
    ).lower()

    if not username or access_type not in ['read', 'edit']:

        flash(
            'Please enter a valid username and permission.',
            'error'
        )

        return redirect(url_for('documents'))

    target_user = User.query.filter_by(
        username=username
    ).first()

    if not target_user:

        flash(
            'User not found.',
            'error'
        )

        return redirect(url_for('documents'))

    if target_user.role != 'viewer':

        flash(
            'You can share documents only with Viewer accounts.',
            'error'
        )

        return redirect(url_for('documents'))

    if target_user.id == user_id:

        flash(
            'You cannot share a document with yourself.',
            'error'
        )

        return redirect(url_for('documents'))

    permission = Permission.query.filter_by(
        document_id=document_id,
        user_id=target_user.id
    ).first()

    if permission:

        permission.access_type = access_type

    else:

        permission = Permission(
            document_id=document_id,
            user_id=target_user.id,
            access_type=access_type
        )

        db.session.add(permission)

    db.session.commit()

    record_activity(
        user_id,
        'Document permission granted or updated',
        document_id
    )

    flash(
        'Document shared successfully!',
        'success'
    )

    return redirect(url_for('documents'))


# --------------------------------------------------
# REVOKE DOCUMENT ACCESS
# --------------------------------------------------

@app.route(
    '/revoke/<int:document_id>/<int:target_user_id>',
    methods=['POST']
)
@login_required
@role_required('owner')
def revoke_access(document_id, target_user_id):

    user_id = session['user_id']

    document = db.session.get(
        Document,
        document_id
    )

    if not document or document.owner_id != user_id:
        abort(403)

    permission = Permission.query.filter_by(
        document_id=document_id,
        user_id=target_user_id
    ).first()

    if permission:

        db.session.delete(permission)
        db.session.commit()

        record_activity(
            user_id,
            'Document access revoked',
            document_id
        )

        flash(
            'Access revoked successfully!',
            'success'
        )

    else:

        flash(
            'No permission found for this user.',
            'error'
        )

    return redirect(url_for('documents'))


# --------------------------------------------------
# ADMIN DASHBOARD
# --------------------------------------------------

@app.route('/admin')
@login_required
@role_required('admin')
def admin():

    logs = AuditLog.query.order_by(
        AuditLog.timestamp.desc()
    ).all()

    previous_hash = 'GENESIS'
    integrity_valid = True
    verified_count = 0

    hashed_logs = AuditLog.query.filter(
        AuditLog.entry_hash.isnot(None)
    ).order_by(
        AuditLog.id.asc()
    ).all()

    for log in hashed_logs:

        if log.previous_hash != previous_hash:

            integrity_valid = False
            break

        calculated_hash = generate_audit_hash(
            log,
            previous_hash
        )

        if calculated_hash != log.entry_hash:

            integrity_valid = False
            break

        previous_hash = log.entry_hash
        verified_count += 1

    return render_template(
        'admin.html',
        logs=logs,
        integrity_valid=integrity_valid,
        verified_count=verified_count
    )


# --------------------------------------------------
# OWNER PAGE
# --------------------------------------------------

@app.route('/owner')
@login_required
@role_required('owner')
def owner():

    return redirect(url_for('documents'))


# --------------------------------------------------
# VIEWER PAGE
# --------------------------------------------------

@app.route('/viewer')
@login_required
@role_required('viewer')
def viewer():

    return redirect(url_for('documents'))


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route('/logout', methods=['POST'])
@login_required
def logout():

    user_id = session['user_id']

    record_activity(
        user_id,
        'User logged out'
    )

    session.clear()

    flash(
        'You have been logged out.',
        'success'
    )

    return redirect(url_for('login'))


# --------------------------------------------------
# ERROR HANDLERS
# --------------------------------------------------

@app.errorhandler(403)
def forbidden(error):

    return (
        '403 Forbidden - You are not authorized to access this resource.',
        403
    )


@app.errorhandler(404)
def not_found(error):

    return (
        '404 - Document or page not found.',
        404
    )


@app.errorhandler(413)
def file_too_large(error):

    return (
        'File too large. Maximum allowed size is 10 MB.',
        413
    )


# --------------------------------------------------
# CREATE DATABASE AND START APPLICATION
# --------------------------------------------------

with app.app_context():

    db.create_all()

    admin_username = os.environ.get('ADMIN_USERNAME')
    admin_password = os.environ.get('ADMIN_PASSWORD')

    if admin_username and admin_password:

        existing_admin = User.query.filter_by(
            username=admin_username
        ).first()

        if existing_admin is None:

            admin = User(
                username=admin_username,
                password=generate_password_hash(admin_password),
                role='admin'
            )

            db.session.add(admin)
            db.session.commit()

            app.logger.info(
                "Initial admin account created."
            )

        elif existing_admin.role != 'admin':

            app.logger.error(
                "Admin bootstrap username already belongs to another role."
            )


# --------------------------------------------------
# RUN APPLICATION
# --------------------------------------------------

if __name__ == '__main__':
    app.run(debug=False)
