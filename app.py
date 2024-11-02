from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify, send_file
from functools import wraps
import requests
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.urandom(24)

# API endpoints
API_BASE_URL = "https://document-manager-api-rodrigocastromo.replit.app/api"
LOGIN_URL = f"{API_BASE_URL}/auth/login"
LOGOUT_URL = f"{API_BASE_URL}/auth/logout"
REFRESH_URL = f"{API_BASE_URL}/auth/refresh"

# CRUD endpoints
DEPARTMENTS_URL = f"{API_BASE_URL}/departments"
CATEGORIES_URL = f"{API_BASE_URL}/categories"
DOCUMENTS_URL = f"{API_BASE_URL}/documents"
USERS_URL = f"{API_BASE_URL}/users"

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'access_token' not in session:
            return redirect(url_for('login'))
            
        # Check if token needs refresh
        try:
            headers = {'Authorization': f'Bearer {session["access_token"]}'}
            response = requests.post(REFRESH_URL, headers=headers)
            if response.status_code == 200:
                data = response.json()
                session['access_token'] = data['access_token']
                session['refresh_token'] = data['refresh_token']
        except:
            return redirect(url_for('login'))
            
        return f(*args, **kwargs)
    return decorated_function

def get_auth_headers():
    return {'Authorization': f'Bearer {session["access_token"]}'}

@app.route('/')
def index():
    if 'access_token' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'access_token' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        identifier = request.form.get('identifier')
        password = request.form.get('password')
        
        if not identifier or not password:
            flash('Please provide both identifier and password', 'error')
            return render_template('login.html')
        
        try:
            response = requests.post(LOGIN_URL, json={
                'identifier': identifier,
                'password': password
            })
            
            if response.status_code == 200:
                data = response.json()
                session['access_token'] = data['access_token']
                session['refresh_token'] = data['refresh_token']
                session['user'] = data['user']
                session['company_id'] = data['user'].get('company_id')
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
        headers = get_auth_headers()
        requests.post(LOGOUT_URL, headers=headers)
    except Exception as e:
        print(f"Logout error: {e}")
    
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

# Users CRUD routes
@app.route('/users')
@login_required
def users():
    try:
        headers = get_auth_headers()
        company_id = session.get('company_id')
        if not company_id:
            flash('Company ID not found', 'error')
            return render_template('users.html', users=[])

        response = requests.get(
            f"{USERS_URL}/companies/{company_id}/users",
            headers=headers,
            timeout=10  # Add timeout to prevent hanging
        )
        
        if response.status_code == 200:
            users_data = response.json().get('users', [])
            return render_template('users.html', users=users_data)
        else:
            error_msg = response.json().get('error', 'Failed to fetch users')
            flash(error_msg, 'error')
            return render_template('users.html', users=[])
            
    except requests.Timeout:
        flash('Request timed out while fetching users', 'error')
        return render_template('users.html', users=[])
    except Exception as e:
        print(f"Error fetching users: {e}")
        flash('Error loading users', 'error')
        return render_template('users.html', users=[])

@app.route('/api/users', methods=['GET', 'POST'])
@login_required
def user_api():
    headers = get_auth_headers()
    company_id = session.get('company_id')

    if not company_id:
        return jsonify({'error': 'Company ID not found'}), 400
    
    try:
        if request.method == 'GET':
            response = requests.get(
                f"{USERS_URL}/companies/{company_id}/users",
                headers=headers,
                timeout=10
            )
            if response.status_code == 200:
                return jsonify(response.json().get('users', [])), 200
            return jsonify({'error': response.json().get('error', 'Failed to fetch users')}), response.status_code
        
        elif request.method == 'POST':
            data = request.json
            required_fields = ['name', 'email', 'role']
            
            # Validate required fields
            missing_fields = [field for field in required_fields if not data.get(field)]
            if missing_fields:
                return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400
            
            data['company_id'] = company_id
            response = requests.post(
                USERS_URL, 
                headers=headers, 
                json=data,
                timeout=10
            )
            
            if response.status_code == 201:
                return jsonify(response.json()), 201
            return jsonify({'error': response.json().get('error', 'Failed to create user')}), response.status_code
            
    except requests.Timeout:
        return jsonify({'error': 'Request timed out'}), 504
    except Exception as e:
        print(f"Error in user API: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

@app.route('/api/users/<user_id>', methods=['PUT', 'DELETE'])
@login_required
def user_detail_api(user_id):
    headers = get_auth_headers()
    company_id = session.get('company_id')

    if not company_id:
        return jsonify({'error': 'Company ID not found'}), 400
    
    try:
        if request.method == 'PUT':
            data = request.json
            required_fields = ['name', 'email', 'role']
            
            # Validate required fields
            missing_fields = [field for field in required_fields if not data.get(field)]
            if missing_fields:
                return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400
            
            data['company_id'] = company_id
            response = requests.put(
                f"{USERS_URL}/{user_id}",
                headers=headers,
                json=data,
                timeout=10
            )
            
            if response.status_code == 200:
                return jsonify(response.json()), 200
            return jsonify({'error': response.json().get('error', 'Failed to update user')}), response.status_code
            
        elif request.method == 'DELETE':
            response = requests.delete(
                f"{USERS_URL}/{user_id}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 204:
                return '', 204
            return jsonify({'error': response.json().get('error', 'Failed to delete user')}), response.status_code
            
    except requests.Timeout:
        return jsonify({'error': 'Request timed out'}), 504
    except Exception as e:
        print(f"Error in user detail API: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
