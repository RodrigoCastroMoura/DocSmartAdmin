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
REQUEST_TIMEOUT = 30  # Increased timeout for better reliability

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
    """Get authentication headers with proper content type"""
    return {
        'Authorization': f'Bearer {session.get("access_token")}',
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

def handle_api_error(response, default_error="An error occurred"):
    """Handle API error responses and return appropriate error message"""
    try:
        error_data = response.json()
        if isinstance(error_data, dict):
            return error_data.get('error', default_error)
        return default_error
    except Exception as e:
        print(f"Error parsing error response: {e}")
        return default_error

def normalize_response(data, default_key='items'):
    """Normalize API response to consistent format"""
    try:
        if data is None:
            print(f"normalize_response: data is None, returning empty {default_key}")
            return {default_key: []}
        
        print(f"normalize_response input: {data}, type: {type(data)}")
        
        if isinstance(data, list):
            print(f"normalize_response: data is list with {len(data)} items")
            return {default_key: data}
        
        if isinstance(data, dict):
            if default_key in data:
                if isinstance(data[default_key], list):
                    print(f"normalize_response: using existing {default_key} list")
                    return data
                print(f"normalize_response: converting {default_key} to list")
                return {default_key: [data[default_key]] if data[default_key] else []}
            
            # If there's no default_key but the dict has data, treat it as a single item
            print(f"normalize_response: wrapping dict as single item")
            return {default_key: [data] if data else []}
        
        print(f"normalize_response: unhandled data type, returning empty {default_key}")
        return {default_key: []}
    except Exception as e:
        print(f"Error in normalize_response: {e}")
        return {default_key: []}

@app.route('/api/users')
@login_required
def users_api():
    headers = get_auth_headers()
    company_id = session.get('company_id')
    
    if not company_id:
        print("users_api: No company_id in session")
        return jsonify({'error': 'Company ID not found in session'}), 400
    
    try:
        print(f"Fetching users with company_id: {company_id}")
        response = requests.get(
            f"{USERS_URL}/users",
            headers=headers,
            params={'company_id': company_id},
            timeout=REQUEST_TIMEOUT
        )
        
        print(f"Users API response status: {response.status_code}")
        
        if not response.ok:
            if response.status_code in [401, 403]:
                print("users_api: Authentication failed")
                return jsonify({'error': 'Authentication failed'}), response.status_code
            error_message = handle_api_error(response, 'Failed to fetch users')
            print(f"users_api error: {error_message}")
            return jsonify({'error': error_message}), response.status_code
        
        data = response.json()
        print(f"Raw users response: {data}")
        
        if isinstance(data, dict) and 'users' in data:
            return jsonify(data), 200
        elif isinstance(data, list):
            return jsonify({'users': data}), 200
        else:
            return jsonify({'users': [data] if data else []}), 200
            
    except requests.exceptions.Timeout:
        print("users_api: Request timed out")
        return jsonify({'error': 'Request timed out'}), 504
    except requests.exceptions.ConnectionError:
        print("users_api: Connection error")
        return jsonify({'error': 'Connection error'}), 502
    except Exception as e:
        print(f"Error in users_api: {str(e)}")
        return jsonify({'users': []}), 200

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
    finally:
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
        print(f"Fetching departments for company: {company_id}")
        response = requests.get(
            f"{DEPARTMENTS_URL}/companies/{company_id}/departments",
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )
        
        if not response.ok:
            if response.status_code in [401, 403]:
                return jsonify({'error': 'Authentication failed'}), response.status_code
            error_message = handle_api_error(response, 'Failed to fetch departments')
            return jsonify({'error': error_message}), response.status_code
            
        data = response.json()
        normalized_data = normalize_response(data, 'departments')
        print(f"Departments response: {normalized_data}")
        return jsonify(normalized_data['departments']), 200
    except Exception as e:
        print(f"Error fetching departments: {e}")
        return jsonify({'departments': []}), 200

@app.route('/api/categories/departments/<department_id>/categories')
@login_required
def department_categories_api(department_id):
    headers = get_auth_headers()
    company_id = session.get('company_id')
    
    if not company_id:
        return jsonify({'error': 'Company ID not found in session'}), 400
    
    try:
        print(f"Fetching categories for department: {department_id}")
        response = requests.get(
            f"{CATEGORIES_URL}/departments/{department_id}/categories",
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )
        
        if not response.ok:
            if response.status_code in [401, 403]:
                return jsonify({'error': 'Authentication failed'}), response.status_code
            error_message = handle_api_error(response, 'Failed to fetch categories')
            return jsonify({'error': error_message}), response.status_code
            
        data = normalize_response(response.json(), 'categories')
        print(f"Categories response: {data}")
        return jsonify(data), 200
    except Exception as e:
        print(f"Error fetching categories: {e}")
        return jsonify({'categories': []}), 200

@app.route('/api/document_types')
@login_required
def document_types_api():
    headers = get_auth_headers()
    company_id = session.get('company_id')
    
    if not company_id:
        print("document_types_api: No company_id in session")
        return jsonify({'error': 'Company ID not found in session'}), 400
    
    try:
        print(f"Fetching document types with company_id: {company_id}")
        response = requests.get(
            f"{DOCUMENT_TYPES_URL}/types",
            headers=headers,
            params={'company_id': company_id},
            timeout=REQUEST_TIMEOUT
        )
        
        print(f"Document types API response status: {response.status_code}")
        
        if not response.ok:
            if response.status_code in [401, 403]:
                print("document_types_api: Authentication failed")
                return jsonify({'error': 'Authentication failed'}), response.status_code
            error_message = handle_api_error(response, 'Failed to fetch document types')
            print(f"document_types_api error: {error_message}")
            return jsonify({'error': error_message}), response.status_code
            
        data = response.json()
        print(f"Raw document types response: {data}")
        
        if isinstance(data, dict) and 'document_types' in data:
            return jsonify(data), 200
        elif isinstance(data, list):
            return jsonify({'document_types': data}), 200
        else:
            return jsonify({'document_types': [data] if data else []}), 200
            
    except requests.exceptions.Timeout:
        print("document_types_api: Request timed out")
        return jsonify({'error': 'Request timed out'}), 504
    except requests.exceptions.ConnectionError:
        print("document_types_api: Connection error")
        return jsonify({'error': 'Connection error'}), 502
    except Exception as e:
        print(f"Error in document_types_api: {str(e)}")
        return jsonify({'document_types': []}), 200

@app.route('/api/documents')
@login_required
def documents_api():
    headers = get_auth_headers()
    company_id = session.get('company_id')
    
    if not company_id:
        return jsonify({'error': 'Company ID not found in session'}), 400
    
    try:
        # Parse and validate pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        page = max(1, page)
        per_page = max(1, min(100, per_page))
        
        # Build query parameters
        params = {
            'page': page,
            'per_page': per_page,
            'company_id': company_id
        }
        
        # Add optional filters with validation
        for param in ['department_id', 'category_id', 'document_type_id', 'user_id']:
            value = request.args.get(param)
            if value and value.strip():
                params[param] = value.strip()
        
        print(f"Fetching documents with params: {params}")
        response = requests.get(
            f"{DOCUMENTS_URL}/companies/{company_id}/documents",
            headers=headers,
            params=params,
            timeout=REQUEST_TIMEOUT
        )
        
        if not response.ok:
            if response.status_code in [401, 403]:
                return jsonify({'error': 'Authentication failed'}), response.status_code
            error_message = handle_api_error(response, 'Failed to fetch documents')
            print(f"Documents API error: {error_message}")
            return jsonify({'error': error_message}), response.status_code
        
        data = response.json()
        print(f"Documents API response: {data}")
        
        # Normalize document response
        normalized_data = normalize_response(data, 'documents')
        documents = normalized_data.get('documents', [])
        
        result = {
            'documents': documents,
            'total': len(documents),
            'page': page,
            'per_page': per_page,
            'total_pages': max(1, (len(documents) + per_page - 1) // per_page)
        }
        
        # If the API returned pagination info, use it
        if isinstance(data, dict):
            result.update({
                'total': data.get('total', result['total']),
                'page': data.get('page', result['page']),
                'per_page': data.get('per_page', result['per_page']),
                'total_pages': max(1, data.get('total_pages',
                    (data.get('total', 0) + per_page - 1) // per_page))
            })
        
        return jsonify(result), 200
        
    except requests.exceptions.Timeout:
        print("documents_api: Request timed out")
        return jsonify({
            'error': 'Request timed out',
            'documents': [],
            'total': 0,
            'page': page,
            'per_page': per_page,
            'total_pages': 1
        }), 504
    except requests.exceptions.ConnectionError:
        print("documents_api: Connection error")
        return jsonify({
            'error': 'Connection error',
            'documents': [],
            'total': 0,
            'page': page,
            'per_page': per_page,
            'total_pages': 1
        }), 502
    except Exception as e:
        print(f"Error in documents_api: {str(e)}")
        return jsonify({
            'documents': [],
            'total': 0,
            'page': page,
            'per_page': per_page,
            'total_pages': 1
        }), 200

@app.route('/api/documents', methods=['POST'])
@login_required
def create_document():
    headers = get_auth_headers()
    company_id = session.get('company_id')
    
    if not company_id:
        return jsonify({'error': 'Company ID not found in session'}), 400
        
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
            
        file = request.files['file']
        if not file or not file.filename:
            return jsonify({'error': 'No file selected'}), 400
            
        # Handle file upload
        filename = secure_filename(file.filename)
        
        # Create form data with all required fields
        form_data = {
            'titulo': request.form.get('titulo'),
            'document_type_id': request.form.get('document_type_id'),
            'category_id': request.form.get('category_id'),
            'user_id': request.form.get('user_id'),
            'company_id': company_id
        }
        
        # Validate required fields
        if not all([form_data['titulo'], form_data['document_type_id'], 
                   form_data['category_id'], form_data['user_id']]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Create multipart form-data request
        files = {
            'file': (filename, file.stream, file.content_type)
        }
        
        # Remove content-type from headers for multipart request
        upload_headers = {k: v for k, v in headers.items() 
                        if k.lower() != 'content-type'}
        
        # Make request to create document
        print(f"Creating document with data: {form_data}")
        response = requests.post(
            f"{DOCUMENTS_URL}/companies/{company_id}/documents",
            headers=upload_headers,
            data=form_data,
            files=files,
            timeout=REQUEST_TIMEOUT
        )
        
        if not response.ok:
            error_message = handle_api_error(response, 'Failed to create document')
            print(f"Document creation error: {error_message}")
            return jsonify({'error': error_message}), response.status_code
            
        try:
            result = response.json()
            print(f"Document created successfully: {result}")
            return jsonify(result), 201
        except ValueError as e:
            print(f"Error parsing create document response: {e}")
            return jsonify({'error': 'Invalid response format'}), 500
        
    except requests.exceptions.RequestException as e:
        print(f"Network error creating document: {e}")
        return jsonify({'error': 'Network error - please try again'}), 500
    except Exception as e:
        print(f"Error creating document: {e}")
        return jsonify({'error': 'Failed to create document'}), 500

@app.route('/api/documents/<document_id>', methods=['DELETE'])
@login_required
def delete_document(document_id):
    headers = get_auth_headers()
    company_id = session.get('company_id')
    
    if not company_id:
        return jsonify({'error': 'Company ID not found in session'}), 400
    
    try:
        print(f"Deleting document: {document_id}")
        response = requests.delete(
            f"{DOCUMENTS_URL}/companies/{company_id}/documents/{document_id}",
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )
        
        if not response.ok:
            if response.status_code in [401, 403]:
                return jsonify({'error': 'Authentication failed'}), response.status_code
            error_message = handle_api_error(response, 'Failed to delete document')
            print(f"Document deletion error: {error_message}")
            return jsonify({'error': error_message}), response.status_code
            
        return jsonify({'message': 'Document deleted successfully'}), 200
        
    except requests.exceptions.Timeout:
        print(f"Timeout deleting document: {document_id}")
        return jsonify({'error': 'Request timed out'}), 504
    except requests.exceptions.ConnectionError:
        print(f"Connection error deleting document: {document_id}")
        return jsonify({'error': 'Connection error'}), 502
    except Exception as e:
        print(f"Error deleting document: {e}")
        return jsonify({'error': 'Failed to delete document'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)