from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify, Response
from functools import wraps
import requests
import os
import json
import time
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.permanent_session_lifetime = 3600  # 1 hour session lifetime

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
DOCUMENT_TYPES_URL = f"{API_BASE_URL}/document_types"

# Request timeout in seconds
REQUEST_TIMEOUT = 10

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'access_token' not in session:
            return redirect(url_for('login'))
        
        if 'token_expiry' in session and session['token_expiry'] < time.time():
            try:
                headers = {'Authorization': f'Bearer {session["access_token"]}'}
                response = requests.post(REFRESH_URL, headers=headers, timeout=REQUEST_TIMEOUT)
                if response.status_code == 200:
                    data = response.json()
                    session['access_token'] = data['access_token']
                    session['refresh_token'] = data['refresh_token']
                    session['token_expiry'] = time.time() + 3600  # Set token expiry to 1 hour
                else:
                    session.clear()
                    return redirect(url_for('login'))
            except Exception as e:
                print(f"Token refresh error: {e}")
                session.clear()
                return redirect(url_for('login'))
            
        return f(*args, **kwargs)
    return decorated_function

def get_auth_headers():
    return {
        'Authorization': f'Bearer {session.get("access_token")}',
        'accept': 'application/json'
    }

def handle_api_error(response, default_error="An error occurred"):
    """Handle API error responses and return appropriate error message"""
    try:
        error_data = response.json()
        if isinstance(error_data, dict):
            # Check different error message formats
            if 'error' in error_data:
                return error_data['error']
            if 'message' in error_data:
                return error_data['message']
            if 'detail' in error_data:
                return error_data['detail']
            if 'errors' in error_data and isinstance(error_data['errors'], list):
                return '; '.join(error_data['errors'])
            # Handle nested error objects
            if 'data' in error_data and isinstance(error_data['data'], dict):
                if 'error' in error_data['data']:
                    return error_data['data']['error']
                if 'message' in error_data['data']:
                    return error_data['data']['message']
            # Try to get any error-like key
            for key in error_data:
                if isinstance(error_data[key], str) and ('error' in key.lower() or 'message' in key.lower()):
                    return error_data[key]
        return default_error
    except (ValueError, AttributeError):
        try:
            return response.text or default_error
        except:
            return default_error

def handle_api_request(response, error_msg="Operation failed", empty_response=None):
    """Generic handler for API responses"""
    try:
        if response.status_code == 401:
            session.clear()  # Clear session on authentication failure
            return jsonify({'error': 'Authentication failed. Please log in again.'}), 401
        elif response.status_code == 403:
            return jsonify({'error': 'Access forbidden. You do not have permission to perform this action.'}), 403
        elif response.status_code == 404:
            if empty_response is not None:
                return jsonify(empty_response), 200
            return jsonify({'error': 'Resource not found'}), 404
        elif not response.ok:
            error_message = handle_api_error(response, error_msg)
            return jsonify({'error': error_message}), response.status_code

        try:
            if response.status_code == 204:  # No content
                return '', 204
            
            data = response.json()
            if not data and empty_response is not None:
                return jsonify(empty_response), 200
            return jsonify(data), 200
        except ValueError as e:
            print(f"JSON decode error: {e}")
            return jsonify({'error': 'Invalid JSON response from server'}), 500
    except Exception as e:
        print(f"API request error: {str(e)}")
        return jsonify({'error': error_msg}), 500

# Basic routes
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
            response = requests.post(
                LOGIN_URL,
                json={'identifier': identifier, 'password': password},
                timeout=REQUEST_TIMEOUT
            )
            
            if response.status_code == 200:
                data = response.json()
                session.permanent = True
                session['access_token'] = data['access_token']
                session['refresh_token'] = data['refresh_token']
                session['user'] = data['user']
                session['company_id'] = data['user'].get('company_id')
                session['token_expiry'] = time.time() + 3600  # Set token expiry to 1 hour
                return redirect(url_for('dashboard'))
            else:
                error_message = handle_api_error(response, 'Invalid credentials')
                flash(error_message, 'error')
        except requests.Timeout:
            flash('Login request timed out. Please try again.', 'error')
        except requests.ConnectionError:
            flash('Could not connect to the server. Please try again later.', 'error')
        except Exception as e:
            print(f"Login error: {e}")
            flash('An error occurred during login', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    try:
        headers = get_auth_headers()
        requests.post(LOGOUT_URL, headers=headers, timeout=REQUEST_TIMEOUT)
    except Exception as e:
        print(f"Logout error: {e}")
    
    session.clear()
    return redirect(url_for('login'))

# Page routes
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

@app.route('/document_types')
@login_required
def document_types():
    return render_template('document_types.html')

@app.route('/users')
@login_required
def users():
    return render_template('users.html')

# API Routes
@app.route('/api/departments')
@login_required
def departments_api():
    headers = get_auth_headers()
    company_id = session.get('company_id')
    
    if not company_id:
        return jsonify({'error': 'Company ID not found in session'}), 400
    
    try:
        response = requests.get(
            f"{DEPARTMENTS_URL}/companies/{company_id}/departments",
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )
        return handle_api_request(response, 'Failed to fetch departments', {'departments': []})
    except requests.Timeout:
        print("Timeout error fetching departments")
        return jsonify({'error': 'Request timed out. Please try again.'}), 504
    except requests.ConnectionError:
        print("Connection error fetching departments")
        return jsonify({'error': 'Failed to connect to server. Please check your connection.'}), 503
    except Exception as e:
        print(f"Error fetching departments: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

@app.route('/api/departments/<department_id>', methods=['DELETE'])
@login_required
def delete_department(department_id):
    headers = get_auth_headers()
    company_id = session.get('company_id')
    
    if not company_id:
        return jsonify({'error': 'Company ID not found in session'}), 400
    
    try:
        response = requests.delete(
            f"{DEPARTMENTS_URL}/companies/{company_id}/departments/{department_id}",
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )
        
        if response.status_code == 404:
            return jsonify({'error': 'Department not found'}), 404
        elif response.status_code == 403:
            return jsonify({'error': 'You do not have permission to delete this department'}), 403
        elif response.status_code == 409:
            return jsonify({'error': 'Cannot delete department with associated categories or documents'}), 409
        
        return handle_api_request(response, 'Failed to delete department')
    except requests.Timeout:
        print("Timeout error deleting department")
        return jsonify({'error': 'Request timed out. Please try again.'}), 504
    except requests.ConnectionError:
        print("Connection error deleting department")
        return jsonify({'error': 'Failed to connect to server. Please check your connection.'}), 503
    except Exception as e:
        print(f"Error deleting department: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

@app.route('/api/users')
@login_required
def users_api():
    headers = get_auth_headers()
    company_id = session.get('company_id')
    
    if not company_id:
        return jsonify({'error': 'Company ID not found in session'}), 400
    
    try:
        response = requests.get(
            f"{USERS_URL}/companies/{company_id}/users",
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )
        
        return handle_api_request(response, 'Failed to fetch users', {'users': []})
    except requests.Timeout:
        print("Timeout error fetching users")
        return jsonify({'error': 'Request timed out. Please try again.'}), 504
    except requests.ConnectionError:
        print("Connection error fetching users")
        return jsonify({'error': 'Failed to connect to server. Please check your connection.'}), 503
    except Exception as e:
        print(f"Error fetching users: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

@app.route('/api/users/<user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    headers = get_auth_headers()
    company_id = session.get('company_id')
    
    if not company_id:
        return jsonify({'error': 'Company ID not found in session'}), 400
    
    try:
        response = requests.delete(
            f"{USERS_URL}/companies/{company_id}/users/{user_id}",
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )
        
        return handle_api_request(response, 'Failed to delete user')
    except requests.Timeout:
        print("Timeout error deleting user")
        return jsonify({'error': 'Request timed out. Please try again.'}), 504
    except requests.ConnectionError:
        print("Connection error deleting user")
        return jsonify({'error': 'Failed to connect to server. Please check your connection.'}), 503
    except Exception as e:
        print(f"Error deleting user: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

@app.route('/api/users', methods=['POST'])
@login_required
def create_user():
    headers = get_auth_headers()
    company_id = session.get('company_id')
    
    if not company_id:
        return jsonify({'error': 'Company ID not found in session'}), 400
    
    try:
        data = request.json
        data['company_id'] = company_id
        
        response = requests.post(
            f"{USERS_URL}/companies/{company_id}/users",
            headers=headers,
            json=data,
            timeout=REQUEST_TIMEOUT
        )
        
        return handle_api_request(response, 'Failed to create user')
    except requests.Timeout:
        print("Timeout error creating user")
        return jsonify({'error': 'Request timed out. Please try again.'}), 504
    except requests.ConnectionError:
        print("Connection error creating user")
        return jsonify({'error': 'Failed to connect to server. Please check your connection.'}), 503
    except Exception as e:
        print(f"Error creating user: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

@app.route('/api/users/<user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
    headers = get_auth_headers()
    company_id = session.get('company_id')
    
    if not company_id:
        return jsonify({'error': 'Company ID not found in session'}), 400
    
    try:
        data = request.json
        data['company_id'] = company_id
        
        response = requests.put(
            f"{USERS_URL}/companies/{company_id}/users/{user_id}",
            headers=headers,
            json=data,
            timeout=REQUEST_TIMEOUT
        )
        
        return handle_api_request(response, 'Failed to update user')
    except requests.Timeout:
        print("Timeout error updating user")
        return jsonify({'error': 'Request timed out. Please try again.'}), 504
    except requests.ConnectionError:
        print("Connection error updating user")
        return jsonify({'error': 'Failed to connect to server. Please check your connection.'}), 503
    except Exception as e:
        print(f"Error updating user: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
