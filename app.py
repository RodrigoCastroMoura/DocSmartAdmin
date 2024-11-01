from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
import requests
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Initialize Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# API endpoints
API_BASE_URL = "https://document-manager-api-rodrigocastromo.replit.app/api"
AUTH_ENDPOINTS = {
    'login': f"{API_BASE_URL}/auth/login",
    'logout': f"{API_BASE_URL}/auth/logout",
    'refresh': f"{API_BASE_URL}/auth/refresh"
}

class User:
    def __init__(self, user_data):
        self.id = user_data.get('user_id')
        self.email = user_data.get('email')
        self.role = user_data.get('role')
        self.permissions = user_data.get('permissions', [])
        self.is_authenticated = True
        self.is_active = True
        self.is_anonymous = False

    def get_id(self):
        return str(self.id)

@login_manager.user_loader
def load_user(user_id):
    if 'access_token' not in session:
        return None
    
    # You might want to validate the token here
    try:
        headers = {'Authorization': f'Bearer {session["access_token"]}'}
        response = requests.post(AUTH_ENDPOINTS['refresh'], headers=headers)
        if response.status_code == 200:
            token_data = response.json()
            return User(token_data)
    except Exception as e:
        print(f"Error refreshing token: {e}")
    return None

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        identifier = request.form.get('identifier')
        password = request.form.get('password')
        
        if not identifier or not password:
            flash('Please provide both identifier and password', 'error')
            return render_template('login.html')
        
        try:
            response = requests.post(AUTH_ENDPOINTS['login'], json={
                'identifier': identifier,
                'password': password
            })
            
            if response.status_code == 200:
                data = response.json()
                session['access_token'] = data.get('access_token')
                user = User(data)
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid credentials', 'error')
        except Exception as e:
            print(f"Login error: {e}")
            flash('An error occurred during login', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    try:
        if 'access_token' in session:
            headers = {'Authorization': f'Bearer {session["access_token"]}'}
            requests.post(AUTH_ENDPOINTS['logout'], headers=headers)
            session.pop('access_token', None)
    except Exception as e:
        print(f"Logout error: {e}")
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/departments')
@login_required
def departments():
    return render_template('departments.html')

@app.route('/categories')
@login_required
def categories():
    return render_template('categories.html')

@app.route('/documents')
@login_required
def documents():
    return render_template('documents.html')

@app.route('/users')
@login_required
def users():
    return render_template('users.html')
