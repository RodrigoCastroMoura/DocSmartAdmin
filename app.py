from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify, Response
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
DOCUMENT_TYPES_URL = f"{API_BASE_URL}/document_types"

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
        except Exception as e:
            print(f"Token refresh error: {e}")
            return redirect(url_for('login'))
            
        return f(*args, **kwargs)
    return decorated_function

def get_auth_headers():
    return {
        'Authorization': f'Bearer {session["access_token"]}',
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

def validate_json_response(response, expected_type=None):
    """Validate JSON response and optionally check its type"""
    try:
        data = response.json()
        if expected_type and not isinstance(data, expected_type):
            return None, f'Invalid response format, expected {expected_type.__name__}'
        return data, None
    except ValueError:
        return None, 'Invalid JSON response from server'

def handle_api_error(response, default_message):
    """Helper function to handle API error responses"""
    try:
        data = response.json()
        error_message = data.get('error', default_message)
    except ValueError:
        error_message = default_message
    return jsonify({'error': error_message}), response.status_code

# Restored route handlers for categories, departments, documents, etc.
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
                error_data = response.json()
                flash(error_data.get('error', 'Invalid credentials'), 'error')
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

# Restored API routes for categories and other resources
@app.route('/api/categories')
@login_required
def categories_api():
    headers = get_auth_headers()
    company_id = session.get('company_id')
    
    if not company_id:
        return jsonify({'error': 'Company ID not found in session'}), 400
    
    try:
        response = requests.get(
            f"{CATEGORIES_URL}/companies/{company_id}/categories",
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 401:
            return jsonify({'error': 'Authentication failed'}), 401
        elif response.status_code == 403:
            return jsonify({'error': 'Access forbidden'}), 403
        elif response.status_code == 404:
            return jsonify({'categories': []}), 200
        
        try:
            data = response.json()
            if not isinstance(data, dict) or 'categories' not in data:
                return jsonify({'error': 'Invalid response format'}), 500
            return data, 200
        except ValueError:
            return jsonify({'error': 'Invalid JSON response from server'}), 500
            
    except requests.Timeout:
        return jsonify({'error': 'Request timed out'}), 504
    except requests.ConnectionError:
        return jsonify({'error': 'Failed to connect to server'}), 503
    except Exception as e:
        print(f"Error fetching categories: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

@app.route('/api/categories', methods=['POST'])
@login_required
def create_category():
    if not request.is_json:
        return jsonify({'error': 'Invalid content type, expected application/json'}), 400
        
    headers = get_auth_headers()
    company_id = session.get('company_id')
    
    if not company_id:
        return jsonify({'error': 'Company ID not found in session'}), 400
    
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        if 'name' not in data or 'department_id' not in data:
            return jsonify({'error': 'Name and department_id are required'}), 400
        
        # Validate name
        name = data['name'].strip()
        if len(name) < 3:
            return jsonify({'error': 'Name must be at least 3 characters long'}), 400
        if len(name) > 50:
            return jsonify({'error': 'Name must not exceed 50 characters'}), 400
            
        # Validate department_id
        if not data['department_id']:
            return jsonify({'error': 'Department ID cannot be empty'}), 400
            
        data['company_id'] = company_id
        response = requests.post(
            CATEGORIES_URL,
            headers=headers,
            json=data,
            timeout=10
        )
        
        if response.status_code == 201:
            try:
                return response.json(), 201
            except ValueError:
                return jsonify({'error': 'Invalid response format from server'}), 500
        
        if response.status_code == 404:
            return jsonify({'error': 'Department not found'}), 404
        elif response.status_code == 409:
            return jsonify({'error': 'Category name already exists in this department'}), 409
            
        return handle_api_error(response, 'Failed to create category')
    except requests.Timeout:
        return jsonify({'error': 'Request timed out'}), 504
    except requests.ConnectionError:
        return jsonify({'error': 'Failed to connect to server'}), 503
    except ValueError as e:
        return jsonify({'error': 'Invalid data format'}), 400
    except Exception as e:
        print(f"Error creating category: {e}")
        return jsonify({'error': 'Failed to create category'}), 500

@app.route('/api/categories/<category_id>', methods=['PUT', 'DELETE'])
@login_required
def category_detail_api(category_id):
    if not category_id:
        return jsonify({'error': 'Category ID is required'}), 400

    headers = get_auth_headers()
    
    if request.method == 'PUT':
        # Validate content type
        if not request.is_json:
            return jsonify({'error': 'Invalid content type, expected application/json'}), 400
        
        try:
            # Validate request data
            data = request.json
            if not data:
                return jsonify({'error': 'No data provided'}), 400
            
            if 'name' not in data:
                return jsonify({'error': 'Name is required'}), 400
            
            # Validate name
            name = data['name'].strip()
            if len(name) < 3:
                return jsonify({'error': 'Name must be at least 3 characters long'}), 400
            if len(name) > 50:
                return jsonify({'error': 'Name must not exceed 50 characters'}), 400
            
            # Prepare update data
            update_data = {'name': name}
            if 'department_id' in data:
                if not data['department_id']:
                    return jsonify({'error': 'Department ID cannot be empty'}), 400
                update_data['department_id'] = data['department_id']
            
            # Make API request
            response = requests.put(
                f"{CATEGORIES_URL}/{category_id}",
                headers=headers,
                json=update_data,
                timeout=10
            )
            
            # Handle response
            if response.status_code == 200:
                data, error = validate_json_response(response, dict)
                if error:
                    return jsonify({'error': error}), 500
                return jsonify(data), 200
                
            # Handle specific error cases
            if response.status_code == 404:
                return jsonify({'error': 'Category not found'}), 404
            elif response.status_code == 409:
                return jsonify({'error': 'Category name already exists in this department'}), 409
            
            return handle_api_error(response, 'Failed to update category')
            
        except requests.Timeout:
            print("Timeout error updating category")
            return jsonify({'error': 'Request timed out'}), 504
        except requests.ConnectionError:
            print("Connection error updating category")
            return jsonify({'error': 'Failed to connect to server'}), 503
        except ValueError as e:
            print(f"Invalid JSON data: {e}")
            return jsonify({'error': 'Invalid data format'}), 400
        except Exception as e:
            print(f"Error updating category: {e}")
            return jsonify({'error': 'Failed to update category'}), 500
            
    elif request.method == 'DELETE':
        try:
            response = requests.delete(
                f"{CATEGORIES_URL}/{category_id}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 204:
                return '', 204
            
            # Handle specific error cases
            if response.status_code == 404:
                return jsonify({'error': 'Category not found'}), 404
            elif response.status_code == 409:
                return jsonify({'error': 'Cannot delete category with associated documents'}), 409
            
            return handle_api_error(response, 'Failed to delete category')
        except requests.Timeout:
            print("Timeout error deleting category")
            return jsonify({'error': 'Request timed out'}), 504
        except requests.ConnectionError:
            print("Connection error deleting category")
            return jsonify({'error': 'Failed to connect to server'}), 503
        except Exception as e:
            print(f"Error deleting category: {e}")
            return jsonify({'error': 'Failed to delete category'}), 500

# Remaining routes would be exactly the same as in the original code...

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)