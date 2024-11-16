from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify, Response, send_file
from functools import wraps
import requests
import os
import json
import time
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.permanent_session_lifetime = 3600  # 1 hour session lifetime

# Configure upload folder
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'txt', 'jpg', 'jpeg', 'png'}

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
REQUEST_TIMEOUT = 30  # Increased timeout for better reliability

def refresh_token():
    """Attempt to refresh the access token with enhanced error handling"""
    try:
        if 'refresh_token' not in session:
            print("No refresh token found in session")
            return False
            
        headers = {'Authorization': f'Bearer {session.get("refresh_token")}'}
        response = requests.post(
            REFRESH_URL, 
            headers=headers, 
            timeout=REQUEST_TIMEOUT,
            verify=True  # Ensure SSL verification
        )
        
        if response.ok:
            data = response.json()
            session['access_token'] = data['access_token']
            session['refresh_token'] = data['refresh_token']
            session['token_expiry'] = time.time() + 3600
            return True
        else:
            print(f"Token refresh failed with status: {response.status_code}")
            return False
            
    except requests.Timeout:
        print("Token refresh timeout")
    except requests.ConnectionError:
        print("Token refresh connection error")
    except requests.RequestException as e:
        print(f"Token refresh request error: {str(e)}")
    except Exception as e:
        print(f"Token refresh error: {str(e)}")
    return False

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'access_token' not in session:
            return redirect(url_for('login'))
        
        # Check token expiration
        if 'token_expiry' in session:
            current_time = time.time()
            expiry_time = session.get('token_expiry', 0)
            
            # Refresh token if it's expired or about to expire in the next 5 minutes
            if current_time >= (expiry_time - 300):
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

def get_multipart_headers():
    """Get headers for multipart form data requests"""
    token = session.get('access_token')
    if not token:
        raise ValueError('No access token found')
    
    return {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json'
    }

def handle_api_error(response, default_error="An error occurred"):
    """Enhanced API error handling with detailed logging"""
    try:
        if response.status_code == 401:
            # Try to refresh token on authentication failure
            if refresh_token():
                return 'Token refreshed, please retry the operation'
            return 'Authentication failed, please login again'
        
        if not response.ok:
            try:
                error_data = response.json()
                if isinstance(error_data, dict):
                    error_msg = error_data.get('error') or error_data.get('message') or default_error
                    print(f"API Error: {error_msg}")
                    return error_msg
            except json.JSONDecodeError:
                error_msg = f"Server error: {response.status_code}"
                print(f"API Error: {error_msg}")
                return error_msg
            
            print(f"API Error: {default_error}")
            return default_error
            
    except Exception as e:
        error_msg = f"Error parsing API response: {str(e)}"
        print(error_msg)
        return default_error

def handle_api_response(response, success_code=200, error_message="Operation failed"):
    """Enhanced API response handler with proper error handling and logging"""
    try:
        if response.status_code == 401:
            if refresh_token():
                return jsonify({'error': 'Please retry the operation'}), 401
            return jsonify({'error': 'Authentication failed, please login again'}), 401
        elif response.status_code == 403:
            return jsonify({'error': 'Access forbidden'}), 403
        elif response.status_code == 404:
            return jsonify({'error': 'Resource not found'}), 404
        elif not response.ok:
            error = handle_api_error(response, error_message)
            return jsonify({'error': error}), response.status_code
        
        try:
            if response.status_code == 204:
                return '', 204
            return response.json(), success_code
        except json.JSONDecodeError:
            if response.status_code == 204:
                return '', 204
            error_msg = 'Invalid JSON response'
            print(f"API Error: {error_msg}")
            return jsonify({'error': error_msg}), 500
            
    except Exception as e:
        error_msg = f"Error handling API response: {str(e)}"
        print(error_msg)
        return jsonify({'error': error_message}), 500

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
        return handle_api_response(response, error_message='Failed to fetch departments')
    except requests.Timeout:
        return jsonify({'error': 'Request timed out'}), 504
    except requests.ConnectionError:
        return jsonify({'error': 'Failed to connect to server'}), 503
    except Exception as e:
        print(f"Error fetching departments: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

@app.route('/api/categories/departments/<department_id>/categories')
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
        print(f"Error fetching department categories: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

@app.route('/api/document_types/categories/<category_id>/types')
@login_required
def category_document_types_api(category_id):
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
        print(f"Error fetching category document types: {e}")
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
        return handle_api_response(response, error_message='Failed to fetch users')
    except requests.Timeout:
        return jsonify({'error': 'Request timed out'}), 504
    except requests.ConnectionError:
        return jsonify({'error': 'Failed to connect to server'}), 503
    except Exception as e:
        print(f"Error fetching users: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

@app.route('/api/documents')
@login_required
def documents_api():
    headers = get_auth_headers()
    company_id = session.get('company_id')
    
    if not company_id:
        return jsonify({'error': 'Company ID not found in session'}), 400
    
    try:
        params = {
            'page': request.args.get('page', 1),
            'per_page': request.args.get('per_page', 10),
            'department_id': request.args.get('department_id'),
            'category_id': request.args.get('category_id'),
            'document_type_id': request.args.get('document_type_id'),
            'user_id': request.args.get('user_id')
        }
        
        # Remove None values
        params = {k: v for k, v in params.items() if v is not None}
        
        response = requests.get(
            f"{DOCUMENTS_URL}/companies/{company_id}/documents",
            headers=headers,
            params=params,
            timeout=REQUEST_TIMEOUT
        )
        return handle_api_response(response, error_message='Failed to fetch documents')
    except requests.Timeout:
        return jsonify({'error': 'Request timed out'}), 504
    except requests.ConnectionError:
        return jsonify({'error': 'Failed to connect to server'}), 503
    except Exception as e:
        print(f"Error fetching documents: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

@app.route('/api/documents', methods=['POST'])
@login_required
def create_document():
    headers = get_multipart_headers()  # Use multipart headers for file uploads
    company_id = session.get('company_id')
    
    if not company_id:
        return jsonify({'error': 'Company ID not found in session'}), 400
    
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
            
        file = request.files['file']
        if not file.filename:
            return jsonify({'error': 'No file selected'}), 400
            
        # Build form data
        form_data = {
            'company_id': company_id,
            'titulo': request.form.get('titulo'),
            'department_id': request.form.get('department_id'),
            'category_id': request.form.get('category_id'),
            'document_type_id': request.form.get('document_type_id'),
            'user_id': request.form.get('user_id')
        }
        
        # Validate required fields
        required_fields = ['titulo', 'department_id', 'category_id', 'document_type_id', 'user_id']
        missing_fields = [field for field in required_fields if not form_data.get(field)]
        if missing_fields:
            return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400
            
        # Create files dictionary with proper file object
        files = {'file': (secure_filename(file.filename), file, file.content_type)}
        
        response = requests.post(
            DOCUMENTS_URL,
            headers=headers,
            data=form_data,
            files=files,
            timeout=REQUEST_TIMEOUT * 2  # Double timeout for file upload
        )
        return handle_api_response(response, success_code=201, error_message='Failed to create document')
    except requests.Timeout:
        return jsonify({'error': 'Request timed out'}), 504
    except requests.ConnectionError:
        return jsonify({'error': 'Failed to connect to server'}), 503
    except Exception as e:
        print(f"Error creating document: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

@app.route('/api/documents/<document_id>', methods=['DELETE'])
@login_required
def delete_document(document_id):
    headers = get_auth_headers()
    try:
        response = requests.delete(
            f"{DOCUMENTS_URL}/{document_id}",
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )
        
        if response.status_code == 204:
            return '', 204
            
        return handle_api_response(response, error_message='Failed to delete document')
    except requests.Timeout:
        return jsonify({'error': 'Request timed out'}), 504
    except requests.ConnectionError:
        return jsonify({'error': 'Failed to connect to server'}), 503
    except Exception as e:
        print(f"Error deleting document: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

if __name__ == "__main__":
    # Ensure upload folder exists
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.run(host="0.0.0.0", port=5000, debug=True)