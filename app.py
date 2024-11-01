from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify
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

API_ENDPOINTS = {
    'departments': f"{API_BASE_URL}/departments",
    'categories': f"{API_BASE_URL}/categories",
    'documents': f"{API_BASE_URL}/documents",
    'users': f"{API_BASE_URL}/users"
}

class User:
    def __init__(self, user_data):
        self.id = user_data.get('id') or user_data.get('user_id')
        self.name = user_data.get('name')
        self.email = user_data.get('email')
        self.role = user_data.get('role')
        self.permissions = user_data.get('permissions', [])
        self.company_id = user_data.get('company_id')
        self.is_authenticated = True
        self.is_active = True
        self.is_anonymous = False

    def get_id(self):
        return str(self.id)

def get_auth_headers():
    return {'Authorization': f'Bearer {session.get("access_token")}'}

def api_request(method, url, data=None):
    try:
        headers = get_auth_headers()
        response = requests.request(method, url, headers=headers, json=data)
        return response.json() if response.status_code in [200, 201] else None
    except Exception as e:
        print(f"API request error: {e}")
        return None

@login_manager.user_loader
def load_user(user_id):
    if 'access_token' not in session:
        return None
    
    try:
        headers = {'Authorization': f'Bearer {session["access_token"]}'}
        response = requests.post(AUTH_ENDPOINTS['refresh'], headers=headers)
        if response.status_code == 200:
            data = response.json()
            session['access_token'] = data.get('access_token')
            return User(data.get('user', {}))
    except Exception as e:
        print(f"Error refreshing token: {e}")
    return None

# Authentication routes
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
                session['refresh_token'] = data.get('refresh_token')
                user = User(data.get('user', {}))
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
            session.pop('refresh_token', None)
    except Exception as e:
        print(f"Logout error: {e}")
    logout_user()
    return redirect(url_for('login'))

# Department routes
@app.route('/departments')
@login_required
def departments():
    departments_data = api_request('GET', API_ENDPOINTS['departments']) or []
    return render_template('departments.html', departments=departments_data)

@app.route('/departments/create', methods=['POST'])
@login_required
def create_department():
    data = request.get_json()
    result = api_request('POST', API_ENDPOINTS['departments'], data)
    return jsonify(result) if result else ('Error creating department', 500)

@app.route('/departments/<department_id>', methods=['PUT'])
@login_required
def update_department(department_id):
    data = request.get_json()
    result = api_request('PUT', f"{API_ENDPOINTS['departments']}/{department_id}", data)
    return jsonify(result) if result else ('Error updating department', 500)

@app.route('/departments/<department_id>', methods=['DELETE'])
@login_required
def delete_department(department_id):
    result = api_request('DELETE', f"{API_ENDPOINTS['departments']}/{department_id}")
    return jsonify({'success': True}) if result else ('Error deleting department', 500)

# Category routes
@app.route('/categories')
@login_required
def categories():
    categories_data = api_request('GET', API_ENDPOINTS['categories']) or []
    return render_template('categories.html', categories=categories_data)

@app.route('/categories/create', methods=['POST'])
@login_required
def create_category():
    data = request.get_json()
    result = api_request('POST', API_ENDPOINTS['categories'], data)
    return jsonify(result) if result else ('Error creating category', 500)

@app.route('/categories/<category_id>', methods=['PUT'])
@login_required
def update_category(category_id):
    data = request.get_json()
    result = api_request('PUT', f"{API_ENDPOINTS['categories']}/{category_id}", data)
    return jsonify(result) if result else ('Error updating category', 500)

@app.route('/categories/<category_id>', methods=['DELETE'])
@login_required
def delete_category(category_id):
    result = api_request('DELETE', f"{API_ENDPOINTS['categories']}/{category_id}")
    return jsonify({'success': True}) if result else ('Error deleting category', 500)

# Document routes
@app.route('/documents')
@login_required
def documents():
    documents_data = api_request('GET', API_ENDPOINTS['documents']) or []
    return render_template('documents.html', documents=documents_data)

@app.route('/documents/create', methods=['POST'])
@login_required
def create_document():
    data = request.get_json()
    result = api_request('POST', API_ENDPOINTS['documents'], data)
    return jsonify(result) if result else ('Error creating document', 500)

@app.route('/documents/<document_id>', methods=['PUT'])
@login_required
def update_document(document_id):
    data = request.get_json()
    result = api_request('PUT', f"{API_ENDPOINTS['documents']}/{document_id}", data)
    return jsonify(result) if result else ('Error updating document', 500)

@app.route('/documents/<document_id>', methods=['DELETE'])
@login_required
def delete_document(document_id):
    result = api_request('DELETE', f"{API_ENDPOINTS['documents']}/{document_id}")
    return jsonify({'success': True}) if result else ('Error deleting document', 500)

# User routes
@app.route('/users')
@login_required
def users():
    users_data = api_request('GET', API_ENDPOINTS['users']) or []
    return render_template('users.html', users=users_data)

@app.route('/users/create', methods=['POST'])
@login_required
def create_user():
    data = request.get_json()
    result = api_request('POST', API_ENDPOINTS['users'], data)
    return jsonify(result) if result else ('Error creating user', 500)

@app.route('/users/<user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
    data = request.get_json()
    result = api_request('PUT', f"{API_ENDPOINTS['users']}/{user_id}", data)
    return jsonify(result) if result else ('Error updating user', 500)

@app.route('/users/<user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    result = api_request('DELETE', f"{API_ENDPOINTS['users']}/{user_id}")
    return jsonify({'success': True}) if result else ('Error deleting user', 500)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')
