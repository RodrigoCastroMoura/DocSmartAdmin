from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify
from functools import wraps
import requests
import os
import json
import time
from werkzeug.utils import secure_filename
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

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
        'accept': 'application/json',
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

@app.route('/')
def index():
    if 'access_token' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/departments/<department_id>/categories')
@login_required
def department_categories(department_id):
    headers = get_auth_headers()
    try:
        # Get department details
        logger.info(f"Fetching department details for ID: {department_id}")
        dept_response = requests.get(
            f"{DEPARTMENTS_URL}/{department_id}",
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )
        if not dept_response.ok:
            logger.error(f"Failed to fetch department: {dept_response.status_code}")
            flash('Department not found', 'error')
            return redirect(url_for('departments'))
        
        department = dept_response.json()
        
        # Get categories for the department
        logger.info(f"Fetching categories for department ID: {department_id}")
        categories_response = requests.get(
            f"{CATEGORIES_URL}/departments/{department_id}/categories",
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )
        
        if categories_response.ok:
            data = categories_response.json()
            categories = data.get('categories', [])
            logger.info(f"Successfully fetched {len(categories)} categories")
        else:
            logger.error(f"Failed to fetch categories: {categories_response.status_code}")
            categories = []
            flash('Error loading categories', 'error')
        
        return render_template('department_categories.html',
                             department=department,
                             categories=categories)
    except requests.Timeout:
        logger.error("Request timed out while fetching department categories")
        flash('Request timed out', 'error')
    except requests.ConnectionError:
        logger.error("Connection error while fetching department categories")
        flash('Failed to connect to server', 'error')
    except Exception as e:
        logger.error(f"Unexpected error in department_categories: {e}")
        flash('An unexpected error occurred', 'error')
    
    return redirect(url_for('departments'))

@app.route('/api/departments/<department_id>/categories')
@login_required
def department_categories_api(department_id):
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

@app.route('/api/categories', methods=['POST'])
@login_required
def create_category():
    headers = get_auth_headers()
    try:
        data = request.get_json()
        response = requests.post(
            CATEGORIES_URL,
            headers=headers,
            json=data,
            timeout=REQUEST_TIMEOUT
        )
        return handle_api_response(response, error_message='Failed to create category')
    except requests.Timeout:
        return jsonify({'error': 'Request timed out'}), 504
    except requests.ConnectionError:
        return jsonify({'error': 'Failed to connect to server'}), 503
    except Exception as e:
        logger.error(f"Error creating category: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

@app.route('/api/categories/<category_id>', methods=['PUT'])
@login_required
def update_category(category_id):
    headers = get_auth_headers()
    try:
        data = request.get_json()
        response = requests.put(
            f"{CATEGORIES_URL}/{category_id}",
            headers=headers,
            json=data,
            timeout=REQUEST_TIMEOUT
        )
        return handle_api_response(response, error_message='Failed to update category')
    except requests.Timeout:
        return jsonify({'error': 'Request timed out'}), 504
    except requests.ConnectionError:
        return jsonify({'error': 'Failed to connect to server'}), 503
    except Exception as e:
        logger.error(f"Error updating category: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

@app.route('/api/categories/<category_id>', methods=['DELETE'])
@login_required
def delete_category(category_id):
    headers = get_auth_headers()
    try:
        response = requests.delete(
            f"{CATEGORIES_URL}/{category_id}",
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )
        return handle_api_response(response, error_message='Failed to delete category')
    except requests.Timeout:
        return jsonify({'error': 'Request timed out'}), 504
    except requests.ConnectionError:
        return jsonify({'error': 'Failed to connect to server'}), 503
    except Exception as e:
        logger.error(f"Error deleting category: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
