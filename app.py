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
    """Get authentication headers with current access token"""
    return {
        'Authorization': f'Bearer {session.get("access_token")}',
        'Content-Type': 'application/json',
        'accept': 'application/json'
    }

def handle_api_error(response, default_error="An error occurred"):
    """Handle API error responses and return appropriate error message"""
    try:
        error_data = response.json()
        error_message = error_data.get('error') or error_data.get('message')
        if error_message:
            return error_message
        return default_error
    except Exception:
        return default_error

def log_api_response(response, context="API Response"):
    """Log API response details for debugging"""
    try:
        print(f"{context} Status: {response.status_code}")
        response_data = response.json() if response.content else None
        print(f"{context} Data: {response_data}")
        return response_data
    except Exception as e:
        print(f"Error parsing {context}: {str(e)}")
        return None

# View routes
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

# Main routes
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

# API routes with improved error handling
@app.route('/api/documents')
@login_required
def documents_api():
    headers = get_auth_headers()
    company_id = session.get('company_id')
    
    if not company_id:
        return jsonify({'error': 'Company ID not found in session'}), 400
    
    try:
        # Validate and parse query parameters
        try:
            page = int(request.args.get('page', 1))
            per_page = int(request.args.get('per_page', 10))
            if page < 1 or per_page < 1:
                return jsonify({'error': 'Invalid pagination parameters'}), 400
        except ValueError:
            return jsonify({'error': 'Invalid pagination format'}), 400
            
        # Build query parameters
        params = {
            'page': page,
            'per_page': per_page,
            'department_id': request.args.get('department_id'),
            'category_id': request.args.get('category_id'),
            'document_type_id': request.args.get('document_type_id'),
            'user_id': request.args.get('user_id'),
            'company_id': company_id
        }
        # Remove None values
        params = {k: v for k, v in params.items() if v is not None}
        
        print(f"Fetching documents with params: {params}")  # Debug log
        try:
            response = requests.get(
                f"{DOCUMENTS_URL}/companies/{company_id}/documents",
                headers=headers,
                params=params,
                timeout=REQUEST_TIMEOUT
            )
            
            response_data = log_api_response(response, "Documents API")
            
            if response.status_code == 401:
                return jsonify({'error': 'Authentication failed'}), 401
            elif response.status_code == 403:
                return jsonify({'error': 'Access forbidden'}), 403
            elif response.status_code == 404:
                return jsonify({
                    'documents': [],
                    'total': 0,
                    'page': page,
                    'per_page': per_page,
                    'total_pages': 1
                }), 200
                
            if not response.ok:
                error_message = handle_api_error(response, 'Failed to fetch documents')
                return jsonify({'error': error_message}), response.status_code
                
            if not isinstance(response_data, dict) or 'documents' not in response_data:
                print(f"Invalid response format: {response_data}")
                return jsonify({'error': 'Invalid response format from server'}), 500
                
            print(f"Successfully fetched {len(response_data['documents'])} documents")
            return jsonify(response_data), 200
            
        except requests.Timeout:
            print("Timeout error fetching documents")
            return jsonify({
                'error': 'Request timed out. Please try again.',
                'documents': [],
                'total': 0,
                'page': page,
                'per_page': per_page,
                'total_pages': 1
            }), 504
        except requests.ConnectionError:
            print("Connection error fetching documents")
            return jsonify({
                'error': 'Could not connect to server. Please try again later.',
                'documents': [],
                'total': 0,
                'page': page,
                'per_page': per_page,
                'total_pages': 1
            }), 503
        except Exception as e:
            print(f"API request failed: {str(e)}")
            return jsonify({
                'error': f'Failed to fetch documents: {str(e)}',
                'documents': [],
                'total': 0,
                'page': page,
                'per_page': per_page,
                'total_pages': 1
            }), 500
            
    except Exception as e:
        print(f"Error fetching documents: {str(e)}")
        return jsonify({
            'error': 'An unexpected error occurred',
            'documents': [],
            'total': 0,
            'page': 1,
            'per_page': 10,
            'total_pages': 1
        }), 500

@app.route('/api/categories', methods=['POST'])
@login_required
def create_category():
    headers = get_auth_headers()
    company_id = session.get('company_id')
    
    if not company_id:
        return jsonify({'error': 'Company ID not found in session'}), 400
    
    try:
        # Parse and validate request data
        try:
            data = request.get_json()
            print(f"Received category creation request: {data}")
            
            if not data:
                return jsonify({'error': 'No data provided'}), 400
                
            if not isinstance(data, dict):
                return jsonify({'error': 'Invalid request format'}), 400
                
            # Validate required fields
            if 'name' not in data:
                return jsonify({'error': 'Category name is required'}), 400
                
            if not data['name'] or not isinstance(data['name'], str):
                return jsonify({'error': 'Invalid category name'}), 400
                
            if 'department_id' not in data:
                return jsonify({'error': 'Department ID is required'}), 400
                
            if not data['department_id']:
                return jsonify({'error': 'Department ID cannot be empty'}), 400
                
            # Clean and prepare data
            data['name'] = data['name'].strip()
            data['company_id'] = company_id
            
            print(f"Sending category creation request: {data}")
            response = requests.post(
                CATEGORIES_URL,
                headers=headers,
                json=data,
                timeout=REQUEST_TIMEOUT
            )
            
            response_data = log_api_response(response, "Category Creation")
            
            if response.status_code == 201:
                print("Category created successfully")
                return response.json(), 201
                
            error_message = handle_api_error(response, 'Failed to create category')
            return jsonify({'error': error_message}), response.status_code
            
        except requests.Timeout:
            error_msg = 'Request timed out. Please try again.'
            print(f"Timeout error creating category: {error_msg}")
            return jsonify({'error': error_msg}), 504
        except requests.ConnectionError:
            error_msg = 'Could not connect to server. Please try again later.'
            print(f"Connection error creating category: {error_msg}")
            return jsonify({'error': error_msg}), 503
        except Exception as e:
            error_msg = f'Error processing request: {str(e)}'
            print(f"Error creating category: {error_msg}")
            return jsonify({'error': error_msg}), 400
            
    except Exception as e:
        error_msg = f'Unexpected error: {str(e)}'
        print(f"Error creating category: {error_msg}")
        return jsonify({'error': error_msg}), 500

@app.route('/api/categories/<category_id>', methods=['PUT', 'DELETE'])
@login_required
def category_detail(category_id):
    headers = get_auth_headers()
    
    if request.method == 'PUT':
        try:
            data = request.get_json()
            if not data or 'name' not in data or not data['name'].strip():
                return jsonify({'error': 'Valid category name is required'}), 400
                
            data['name'] = data['name'].strip()
            print(f"Updating category {category_id} with data: {data}")
            
            response = requests.put(
                f"{CATEGORIES_URL}/{category_id}",
                headers=headers,
                json=data,
                timeout=REQUEST_TIMEOUT
            )
            
            response_data = log_api_response(response, "Category Update")
            
            if response.status_code == 200:
                print("Category updated successfully")
                return response.json(), 200
                
            error_message = handle_api_error(response, 'Failed to update category')
            return jsonify({'error': error_message}), response.status_code
            
        except (requests.Timeout, requests.ConnectionError) as e:
            print(f"Network error updating category: {str(e)}")
            return jsonify({'error': 'Network error. Please try again.'}), 503
        except Exception as e:
            print(f"Error updating category: {str(e)}")
            return jsonify({'error': str(e)}), 500
            
    elif request.method == 'DELETE':
        try:
            print(f"Deleting category {category_id}")
            response = requests.delete(
                f"{CATEGORIES_URL}/{category_id}",
                headers=headers,
                timeout=REQUEST_TIMEOUT
            )
            
            response_data = log_api_response(response, "Category Delete")
            
            if response.status_code == 204:
                print("Category deleted successfully")
                return '', 204
                
            error_message = handle_api_error(response, 'Failed to delete category')
            return jsonify({'error': error_message}), response.status_code
            
        except (requests.Timeout, requests.ConnectionError) as e:
            print(f"Network error deleting category: {str(e)}")
            return jsonify({'error': 'Network error. Please try again.'}), 503
        except Exception as e:
            print(f"Error deleting category: {str(e)}")
            return jsonify({'error': str(e)}), 500

@app.route('/api/categories/departments/<department_id>/categories')
@login_required
def department_categories_api(department_id):
    headers = get_auth_headers()
    try:
        print(f"Fetching categories for department {department_id}")
        response = requests.get(
            f"{CATEGORIES_URL}/departments/{department_id}/categories",
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )
        
        response_data = log_api_response(response, "Department Categories")
        
        if response.status_code == 401:
            return jsonify({'error': 'Authentication failed'}), 401
        elif response.status_code == 403:
            return jsonify({'error': 'Access forbidden'}), 403
        elif response.status_code == 404:
            return jsonify({'categories': []}), 200
            
        if not response.ok:
            error_message = handle_api_error(response, 'Failed to fetch categories')
            return jsonify({'error': error_message}), response.status_code
            
        if not isinstance(response_data, dict):
            print(f"Invalid response format: {response_data}")
            return jsonify({'categories': []}), 200
            
        print(f"Successfully fetched categories")
        return jsonify(response_data), 200
        
    except (requests.Timeout, requests.ConnectionError) as e:
        print(f"Network error fetching categories: {str(e)}")
        return jsonify({
            'error': 'Network error. Please try again.',
            'categories': []
        }), 503
    except Exception as e:
        print(f"Error fetching categories: {str(e)}")
        return jsonify({
            'error': 'An unexpected error occurred',
            'categories': []
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
