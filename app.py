from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt
from datetime import timedelta
import os
import logging
from logging.handlers import RotatingFileHandler

# Initialize Flask app
app = Flask(__name__)

# Set instance folder to be inside the app directory
basedir = os.path.abspath(os.path.dirname(__file__))
app.instance_path = os.path.join(basedir, 'instance')

# ===== SECURITY CONFIGURATION =====
# Generate a secure secret key: python -c 'import secrets; print(secrets.token_hex(32))'
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Database configuration - Create DB in the instance folder inside app directory
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(app.instance_path, "firstapp.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Session Management & CSRF Protection (Task 3)
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookie over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to session cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # Session expires after 1 hour
app.config['SESSION_COOKIE_NAME'] = 'secure_session'  # Custom cookie name

# WTForms CSRF Protection
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = None  # Token doesn't expire (or set a time limit)
app.config['WTF_CSRF_SSL_STRICT'] = True  # Require HTTPS for CSRF protection

# Security headers
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0  # Disable caching for security

# Initialize extensions
db = SQLAlchemy(app)
csrf = CSRFProtect(app)  # Enable CSRF protection globally
bcrypt = Bcrypt(app)

# ===== SECURE ERROR HANDLING & LOGGING (Task 4) =====
# Configure logging
if not app.debug:
    # Create logs directory in app folder if it doesn't exist
    logs_dir = os.path.join(basedir, 'logs')
    if not os.path.exists(logs_dir):
        os.mkdir(logs_dir)
    
    # File handler with rotation
    file_handler = RotatingFileHandler(
        os.path.join(logs_dir, 'flask_app.log'),
        maxBytes=10240000,  # 10MB
        backupCount=10
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Flask CRUD App startup')

# Import forms after app initialization
from forms import UserForm, RegistrationForm, LoginForm

# ===== DATABASE MODELS =====
class User(db.Model):
    """User model for CRUD operations"""
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(20), nullable=False)

    def __repr__(self):
        return f'<User {self.first_name} {self.last_name}>'


class Account(db.Model):
    """Account model for authentication with secure password storage (Task 5)"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0)
    account_locked = db.Column(db.Boolean, default=False)
    
    def set_password(self, password):
        """Hash password using bcrypt"""
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        """Verify password against hash"""
        return bcrypt.check_password_hash(self.password_hash, password)
    
    def increment_failed_login(self):
        """Track failed login attempts for account lockout"""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:  # Lock after 5 failed attempts
            self.account_locked = True
        db.session.commit()
    
    def reset_failed_login(self):
        """Reset failed login attempts on successful login"""
        self.failed_login_attempts = 0
        self.account_locked = False
        db.session.commit()
    
    def __repr__(self):
        return f'<Account {self.username}>'

# ===== ROUTES WITH SECURE INPUT HANDLING (Task 1) =====
@app.route('/')
def index():
    """Display all users"""
    form = UserForm()  # Create form instance for the template
    try:
        # Using SQLAlchemy ORM - parameterized by default (Task 2)
        users = User.query.all()
        return render_template('index.html', users=users, form=form)
    except Exception as e:
        app.logger.error(f'Error fetching users: {str(e)}')
        flash('Error loading users. Please try again.', 'danger')
        return render_template('index.html', users=[], form=form)


@app.route('/add', methods=['POST'])
def add():
    """Add new user with validated input"""
    form = UserForm()
    
    # Validate form with CSRF protection and input validation
    if form.validate_on_submit():
        try:
            # Create new user with sanitized data from form
            new_user = User(
                first_name=form.first_name.data.strip(),
                last_name=form.last_name.data.strip(),
                email=form.email.data.strip().lower(),
                phone=form.phone.data.strip()
            )
            
            db.session.add(new_user)
            db.session.commit()
            flash('User added successfully!', 'success')
            app.logger.info(f'User added: {new_user.email}')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error adding user: {str(e)}')
            flash('Error adding user. Please try again.', 'danger')
    else:
        # Display validation errors
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{field}: {error}', 'danger')
    
    return redirect(url_for('index'))


@app.route('/delete/<int:id>', methods=['POST'])  # Changed to POST for security
def delete(id):
    """Delete user by ID"""
    try:
        # Using SQLAlchemy ORM - parameterized query (Task 2)
        user = User.query.get_or_404(id)
        
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully!', 'success')
        app.logger.info(f'User deleted: {user.email}')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error deleting user: {str(e)}')
        flash('Error deleting user. Please try again.', 'danger')
    
    return redirect(url_for('index'))


@app.route('/update/<int:id>', methods=['GET', 'POST'])
def update(id):
    """Update user with validated input"""
    # Using SQLAlchemy ORM - parameterized query (Task 2)
    user = User.query.get_or_404(id)
    form = UserForm(obj=user)
    
    if request.method == 'POST' and form.validate_on_submit():
        try:
            # Update with sanitized data from form
            user.first_name = form.first_name.data.strip()
            user.last_name = form.last_name.data.strip()
            user.email = form.email.data.strip().lower()
            user.phone = form.phone.data.strip()
            
            db.session.commit()
            flash('User updated successfully!', 'success')
            app.logger.info(f'User updated: {user.email}')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error updating user: {str(e)}')
            flash('Error updating user. Please try again.', 'danger')
    elif request.method == 'POST':
        # Display validation errors
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{field}: {error}', 'danger')
    
    return render_template('update.html', user=user, form=form)


# ===== AUTHENTICATION ROUTES (Task 5 - Secure Password Storage) =====
@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration with secure password hashing"""
    form = RegistrationForm()
    
    if form.validate_on_submit():
        try:
            # Check if username or email already exists
            if Account.query.filter_by(username=form.username.data).first():
                flash('Username already exists. Please choose a different one.', 'danger')
                return render_template('register.html', form=form)
            
            if Account.query.filter_by(email=form.email.data.lower()).first():
                flash('Email already registered. Please use a different email.', 'danger')
                return render_template('register.html', form=form)
            
            # Create new account with hashed password
            new_account = Account(
                username=form.username.data.strip(),
                email=form.email.data.strip().lower()
            )
            new_account.set_password(form.password.data)
            
            db.session.add(new_account)
            db.session.commit()
            
            flash('Registration successful! You can now log in.', 'success')
            app.logger.info(f'New account registered: {new_account.username}')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error during registration: {str(e)}')
            flash('Error during registration. Please try again.', 'danger')
    elif request.method == 'POST':
        # Display validation errors
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{error}', 'danger')
    
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login with password verification"""
    form = LoginForm()
    
    if form.validate_on_submit():
        try:
            account = Account.query.filter_by(username=form.username.data).first()
            
            # Check if account exists
            if not account:
                flash('Invalid username or password.', 'danger')
                app.logger.warning(f'Failed login attempt for non-existent user: {form.username.data}')
                return render_template('login.html', form=form)
            
            # Check if account is locked
            if account.account_locked:
                flash('Account is locked due to too many failed login attempts. Please contact support.', 'danger')
                app.logger.warning(f'Login attempt on locked account: {account.username}')
                return render_template('login.html', form=form)
            
            # Verify password
            if account.check_password(form.password.data):
                # Successful login
                account.reset_failed_login()
                session.permanent = True
                session['user_id'] = account.id
                session['username'] = account.username
                flash(f'Welcome back, {account.username}!', 'success')
                app.logger.info(f'Successful login: {account.username}')
                return redirect(url_for('index'))
            else:
                # Failed login
                account.increment_failed_login()
                flash('Invalid username or password.', 'danger')
                app.logger.warning(f'Failed login attempt for user: {account.username}')
        except Exception as e:
            app.logger.error(f'Error during login: {str(e)}')
            flash('Error during login. Please try again.', 'danger')
    
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    """User logout - clear session"""
    username = session.get('username', 'Unknown')
    session.clear()
    flash('You have been logged out successfully.', 'info')
    app.logger.info(f'User logged out: {username}')
    return redirect(url_for('login'))


# ===== CUSTOM ERROR HANDLERS (Task 4 - Secure Error Handling) =====
@app.errorhandler(400)
def bad_request(error):
    """Handle 400 Bad Request errors"""
    app.logger.error(f'Bad Request: {error}')
    return render_template('errors/400.html'), 400


@app.errorhandler(403)
def forbidden(error):
    """Handle 403 Forbidden errors"""
    app.logger.error(f'Forbidden: {error}')
    return render_template('errors/403.html'), 403


@app.errorhandler(404)
def not_found(error):
    """Handle 404 Not Found errors"""
    app.logger.warning(f'Not Found: {request.url}')
    return render_template('errors/404.html'), 404


@app.errorhandler(500)
def internal_server_error(error):
    """Handle 500 Internal Server Error"""
    db.session.rollback()  # Rollback any failed transactions
    app.logger.error(f'Internal Server Error: {error}')
    return render_template('errors/500.html'), 500


@app.errorhandler(Exception)
def handle_exception(error):
    """Handle all other exceptions"""
    db.session.rollback()
    app.logger.error(f'Unhandled Exception: {error}', exc_info=True)
    # In production, don't expose error details to users
    return render_template('errors/500.html'), 500


# ===== SECURITY HEADERS MIDDLEWARE =====
@app.after_request
def set_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # Content Security Policy
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src 'self' https://cdn.jsdelivr.net;"
    return response


if __name__ == '__main__':
    # Create instance directory if it doesn't exist
    if not os.path.exists(app.instance_path):
        os.makedirs(app.instance_path)
    
    with app.app_context():
        db.create_all()
    
    # IMPORTANT: Set DEBUG = False in production!
    # Use environment variable to control debug mode
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    # Note: In production, use a proper WSGI server like Gunicorn or uWSGI
    # and set up HTTPS with a reverse proxy like Nginx
    app.run(debug=debug_mode, host='127.0.0.1', port=5000)