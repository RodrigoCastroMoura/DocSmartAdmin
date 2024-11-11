from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify
from functools import wraps
import requests
import os
import json
import time
from werkzeug.utils import secure_filename
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.permanent_session_lifetime = 3600  # 1 hour session lifetime

# API endpoints
API_BASE_URL = os.getenv('API_BASE_URL')
if not API_BASE_URL:
    raise ValueError("API_BASE_URL environment variable is required")

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
REQUEST_TIMEOUT = 30

def refresh_token():
    """Attempt to refresh the access token"""
    try:
        headers = {'Authorization': f'Bearer {session.get("refresh_token")}'}
        response = requests.post(REFRESH_URL, headers=headers, timeout=REQUEST_TIMEOUT)
        
        if response.ok:
            data = response.json()
            session['access_token'] = data['access_token']
            session['refresh_token'] = data['refresh_token']
            session['token_expiry'] = time.time() + 3600
            return True
    except Exception as e:
        logger.error(f"Token refresh error: {e}")
    return False

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'access_token' not in session:
            return redirect(url_for('login'))
        
        if 'token_expiry' in session and session['token_expiry'] < time.time():
            if not refresh_token():
                session.clear()
                flash('Your session has expired. Please log in again.', 'error')
                return redirect(url_for('login'))
            
        return f(*args, **kwargs)
    return decorated_function

def get_auth_headers():
    """Get authentication headers with proper error handling"""
    token = session.get('access_token')
    if not token:
        raise ValueError('No access token found')
    
    return {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

def handle_api_error(response, default_error="An error occurred"):
    """Enhanced API error handling"""
    try:
        if response.status_code == 401:
            if refresh_token():
                return 'Token refreshed, please retry the operation'
            return 'Authentication failed'
        
        error_data = response.json()
        if isinstance(error_data, dict):
            return error_data.get('error') or error_data.get('message') or default_error
        return default_error
    except Exception as e:
        logger.error(f"Error parsing API response: {e}")
        return default_error

def handle_api_response(response, error_message="Operation failed"):
    """Enhanced API response handler with proper error handling"""
    try:
        if response.status_code == 401:
            if refresh_token():
                return jsonify({'error': 'Please retry the operation'}), 401
            return jsonify({'error': 'Authentication failed'}), 401
        elif response.status_code == 403:
            return jsonify({'error': 'Access forbidden'}), 403
        elif response.status_code == 404:
            return jsonify({'error': 'Resource not found'}), 404
        elif not response.ok:
            error = handle_api_error(response, error_message)
            return jsonify({'error': error}), response.status_code
        
        try:
            return response.json()
        except ValueError:
            if response.status_code == 204:
                return '', 204
            return jsonify({'error': 'Invalid JSON response'}), 500
            
    except Exception as e:
        logger.error(f"Error handling API response: {e}")
        return jsonify({'error': error_message}), 500

# Route handlers
@app.route('/')
def index():
    if 'access_token' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = {
            'identifier': request.form.get('identifier'),
            'password': request.form.get('password')
        }
        
        try:
            response = requests.post(LOGIN_URL, json=data, timeout=REQUEST_TIMEOUT)
            if response.ok:
                auth_data = response.json()
                session['access_token'] = auth_data['access_token']
                session['refresh_token'] = auth_data['refresh_token']
                session['token_expiry'] = time.time() + 3600
                session['user'] = auth_data.get('user', {})
                return redirect(url_for('dashboard'))
            else:
                error = handle_api_error(response, 'Invalid credentials')
                flash(error, 'error')
        except requests.Timeout:
            flash('Request timed out', 'error')
        except requests.ConnectionError:
            flash('Failed to connect to server', 'error')
        except Exception as e:
            logger.error(f"Login error: {e}")
            flash('An unexpected error occurred', 'error')
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'access_token' in session:
        try:
            headers = get_auth_headers()
            requests.post(LOGOUT_URL, headers=headers, timeout=REQUEST_TIMEOUT)
        except Exception as e:
            logger.error(f"Logout error: {e}")
    session.clear()
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

@app.route('/document_types')
@login_required
def document_types():
    return render_template('document_types.html')

# API Routes
@app.route('/api/users')
@login_required
def get_users():
    headers = get_auth_headers()
    try:
        response = requests.get(USERS_URL, headers=headers, timeout=REQUEST_TIMEOUT)
        return handle_api_response(response, error_message='Failed to fetch users')
    except requests.Timeout:
        return jsonify({'error': 'Request timed out'}), 504
    except requests.ConnectionError:
        return jsonify({'error': 'Failed to connect to server'}), 503
    except Exception as e:
        logger.error(f"Error fetching users: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

@app.route('/api/document_types')
@login_required
def get_document_types():
    headers = get_auth_headers()
    try:
        response = requests.get(DOCUMENT_TYPES_URL, headers=headers, timeout=REQUEST_TIMEOUT)
        return handle_api_response(response, error_message='Failed to fetch document types')
    except requests.Timeout:
        return jsonify({'error': 'Request timed out'}), 504
    except requests.ConnectionError:
        return jsonify({'error': 'Failed to connect to server'}), 503
    except Exception as e:
        logger.error(f"Error fetching document types: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

@app.route('/api/departments')
@login_required
def get_departments():
    headers = get_auth_headers()
    try:
        response = requests.get(DEPARTMENTS_URL, headers=headers, timeout=REQUEST_TIMEOUT)
        return handle_api_response(response, error_message='Failed to fetch departments')
    except requests.Timeout:
        return jsonify({'error': 'Request timed out'}), 504
    except requests.ConnectionError:
        return jsonify({'error': 'Failed to connect to server'}), 503
    except Exception as e:
        logger.error(f"Error fetching departments: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

@app.route('/api/categories')
@login_required
def get_categories():
    headers = get_auth_headers()
    try:
        response = requests.get(CATEGORIES_URL, headers=headers, timeout=REQUEST_TIMEOUT)
        return handle_api_response(response, error_message='Failed to fetch categories')
    except requests.Timeout:
        return jsonify({'error': 'Request timed out'}), 504
    except requests.ConnectionError:
        return jsonify({'error': 'Failed to connect to server'}), 503
    except Exception as e:
        logger.error(f"Error fetching categories: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

@app.route('/api/categories/departments/<department_id>/categories')
@login_required
def get_department_categories(department_id):
    headers = get_auth_headers()
    try:
        response = requests.get(
            f"{CATEGORIES_URL}/departments/{department_id}/categories",
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )
        return handle_api_response(response, error_message='Failed to fetch categories')
    except requests.Timeout:
        return jsonify({'error': 'Request timed out'}), 504
    except requests.ConnectionError:
        return jsonify({'error': 'Failed to connect to server'}), 503
    except Exception as e:
        logger.error(f"Error fetching department categories: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

@app.route('/api/document_types/categories/<category_id>/types')
@login_required
def get_category_document_types(category_id):
    headers = get_auth_headers()
    try:
        response = requests.get(
            f"{DOCUMENT_TYPES_URL}/categories/{category_id}/types",
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )
        return handle_api_response(response, error_message='Failed to fetch document types')
    except requests.Timeout:
        return jsonify({'error': 'Request timed out'}), 504
    except requests.ConnectionError:
        return jsonify({'error': 'Failed to connect to server'}), 503
    except Exception as e:
        logger.error(f"Error fetching category document types: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
