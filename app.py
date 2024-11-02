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
    return {
        'Authorization': f'Bearer {session["access_token"]}',
        'Content-Type': 'application/json'
    }

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
                error_msg = response.json().get('error', 'Invalid credentials')
                flash(error_msg, 'error')
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
            headers=headers
        )
        
        if response.status_code == 200:
            users_data = response.json()
        else:
            error_msg = response.json().get('error', 'Failed to fetch users')
            flash(error_msg, 'error')
            users_data = []
            
        return render_template('users.html', users=users_data)
    except requests.RequestException as e:
        print(f"Network error fetching users: {e}")
        flash('Network error while loading users', 'error')
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
    
    if request.method == 'GET':
        try:
            response = requests.get(
                f"{USERS_URL}/companies/{company_id}/users",
                headers=headers,
                timeout=10  # Add timeout
            )
            
            if response.status_code == 200:
                return jsonify(response.json()), 200
            else:
                error_msg = response.json().get('error', 'Failed to fetch users')
                return jsonify({'error': error_msg}), response.status_code
                
        except requests.Timeout:
            return jsonify({'error': 'Request timed out'}), 504
        except requests.RequestException as e:
            print(f"Network error fetching users: {e}")
            return jsonify({'error': 'Network error occurred'}), 503
        except Exception as e:
            print(f"Error fetching users: {e}")
            return jsonify({'error': 'Internal server error'}), 500
    
    elif request.method == 'POST':
        try:
            data = request.json
            if not data:
                return jsonify({'error': 'Invalid request data'}), 400
                
            data['company_id'] = company_id
            response = requests.post(
                USERS_URL,
                headers=headers,
                json=data,
                timeout=10
            )
            
            if response.status_code in [200, 201]:
                return jsonify(response.json()), response.status_code
            else:
                error_msg = response.json().get('error', 'Failed to create user')
                return jsonify({'error': error_msg}), response.status_code
                
        except requests.Timeout:
            return jsonify({'error': 'Request timed out'}), 504
        except requests.RequestException as e:
            print(f"Network error creating user: {e}")
            return jsonify({'error': 'Network error occurred'}), 503
        except Exception as e:
            print(f"Error creating user: {e}")
            return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/users/<user_id>', methods=['PUT', 'DELETE'])
@login_required
def user_detail_api(user_id):
    headers = get_auth_headers()
    company_id = session.get('company_id')

    if not company_id:
        return jsonify({'error': 'Company ID not found'}), 400
    
    if request.method == 'PUT':
        try:
            data = request.json
            if not data:
                return jsonify({'error': 'Invalid request data'}), 400
                
            data['company_id'] = company_id
            response = requests.put(
                f"{USERS_URL}/{user_id}",
                headers=headers,
                json=data,
                timeout=10
            )
            
            if response.status_code == 200:
                return jsonify(response.json()), 200
            else:
                error_msg = response.json().get('error', 'Failed to update user')
                return jsonify({'error': error_msg}), response.status_code
                
        except requests.Timeout:
            return jsonify({'error': 'Request timed out'}), 504
        except requests.RequestException as e:
            print(f"Network error updating user: {e}")
            return jsonify({'error': 'Network error occurred'}), 503
        except Exception as e:
            print(f"Error updating user: {e}")
            return jsonify({'error': 'Internal server error'}), 500
            
    elif request.method == 'DELETE':
        try:
            response = requests.delete(
                f"{USERS_URL}/{user_id}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code in [200, 204]:
                return '', response.status_code
            else:
                error_msg = response.json().get('error', 'Failed to delete user')
                return jsonify({'error': error_msg}), response.status_code
                
        except requests.Timeout:
            return jsonify({'error': 'Request timed out'}), 504
        except requests.RequestException as e:
            print(f"Network error deleting user: {e}")
            return jsonify({'error': 'Network error occurred'}), 503
        except Exception as e:
            print(f"Error deleting user: {e}")
            return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
