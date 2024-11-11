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
        return error_data.get('error', default_error)
    except:
        return default_error

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

# Basic routes
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

@app.route('/departments/<department_id>/categories')
@login_required
def department_categories(department_id):
    headers = get_auth_headers()
    company_id = session.get('company_id')
    
    try:
        # Get department details
        dept_response = requests.get(
            f"{DEPARTMENTS_URL}/{department_id}",
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )
        
        if not dept_response.ok:
            flash('Department not found', 'error')
            return redirect(url_for('departments'))
            
        department = dept_response.json()
        
        # Get categories for department
        cat_response = requests.get(
            f"{CATEGORIES_URL}/departments/{department_id}/categories",
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )
        
        categories = []
        if cat_response.ok:
            data = cat_response.json()
            categories = data.get('categories', [])
        
        return render_template(
            'department_categories.html',
            department=department,
            categories=categories
        )
    except Exception as e:
        print(f"Error loading department categories: {e}")
        flash('Error loading department categories', 'error')
        return redirect(url_for('departments'))

@app.route('/categories/<category_id>/document_types')
@login_required
def category_document_types(category_id):
    headers = get_auth_headers()
    company_id = session.get('company_id')
    
    try:
        # Get category details
        cat_response = requests.get(
            f"{CATEGORIES_URL}/{category_id}",
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )
        
        if not cat_response.ok:
            flash('Category not found', 'error')
            return redirect(url_for('categories'))
            
        category = cat_response.json()
        
        # Get document types for category
        types_response = requests.get(
            f"{DOCUMENT_TYPES_URL}/categories/{category_id}/types",
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )
        
        document_types = []
        if types_response.ok:
            document_types = types_response.json()
        
        return render_template(
            'category_document_types.html',
            category=category,
            document_types=document_types
        )
    except Exception as e:
        print(f"Error loading category document types: {e}")
        flash('Error loading category document types', 'error')
        return redirect(url_for('categories'))

# API routes with proper error handling
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
        
        if response.status_code == 401:
            return jsonify({'error': 'Authentication failed'}), 401
        elif response.status_code == 403:
            return jsonify({'error': 'Access forbidden'}), 403
        elif response.status_code == 404:
            return jsonify([]), 200
        elif not response.ok:
            error_message = handle_api_error(response, 'Failed to fetch departments')
            return jsonify({'error': error_message}), response.status_code
            
        data = response.json()
        if not isinstance(data, list):
            return jsonify({'error': 'Invalid response format'}), 500
            
        return jsonify(data), 200
    except requests.Timeout:
        print("Timeout error fetching departments")
        return jsonify({'error': 'Request timed out'}), 504
    except requests.ConnectionError:
        print("Connection error fetching departments")
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
        
        if response.status_code == 401:
            return jsonify({'error': 'Authentication failed'}), 401
        elif response.status_code == 403:
            return jsonify({'error': 'Access forbidden'}), 403
        elif response.status_code == 404:
            return jsonify({'categories': []}), 200
        elif not response.ok:
            error_message = handle_api_error(response, 'Failed to fetch categories')
            return jsonify({'error': error_message}), response.status_code
            
        return response.json(), 200
    except requests.Timeout:
        print("Timeout error fetching department categories")
        return jsonify({'error': 'Request timed out'}), 504
    except requests.ConnectionError:
        print("Connection error fetching department categories")
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
        
        if response.status_code == 401:
            return jsonify({'error': 'Authentication failed'}), 401
        elif response.status_code == 403:
            return jsonify({'error': 'Access forbidden'}), 403
        elif response.status_code == 404:
            return jsonify({'document_types': []}), 200
        elif not response.ok:
            error_message = handle_api_error(response, 'Failed to fetch document types')
            return jsonify({'error': error_message}), response.status_code
        
        data = response.json()
        if not isinstance(data, list):
            return jsonify({'document_types': []}), 200
        
        return jsonify({'document_types': data}), 200
    except requests.Timeout:
        print("Timeout error fetching category document types")
        return jsonify({'error': 'Request timed out'}), 504
    except requests.ConnectionError:
        print("Connection error fetching category document types")
        return jsonify({'error': 'Failed to connect to server'}), 503
    except Exception as e:
        print(f"Error fetching category document types: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

@app.route('/api/document_types')
@login_required
def document_types_api():
    headers = get_auth_headers()
    company_id = session.get('company_id')
    
    if not company_id:
        return jsonify({'error': 'Company ID not found in session'}), 400
    
    try:
        response = requests.get(
            f"{DOCUMENT_TYPES_URL}/companies/{company_id}/types",
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )
        
        if response.status_code == 401:
            return jsonify({'error': 'Authentication failed'}), 401
        elif response.status_code == 403:
            return jsonify({'error': 'Access forbidden'}), 403
        elif response.status_code == 404:
            return jsonify({'document_types': []}), 200
        elif not response.ok:
            error_message = handle_api_error(response, 'Failed to fetch document types')
            return jsonify({'error': error_message}), response.status_code
            
        data = response.json()
        if not isinstance(data, list):
            return jsonify({'document_types': []}), 200
            
        return jsonify({'document_types': data}), 200
    except requests.Timeout:
        print("Timeout error fetching document types")
        return jsonify({'error': 'Request timed out'}), 504
    except requests.ConnectionError:
        print("Connection error fetching document types")
        return jsonify({'error': 'Failed to connect to server'}), 503
    except Exception as e:
        print(f"Error fetching document types: {e}")
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
        
        if response.status_code == 401:
            return jsonify({'error': 'Authentication failed'}), 401
        elif response.status_code == 403:
            return jsonify({'error': 'Access forbidden'}), 403
        elif response.status_code == 404:
            return jsonify({'users': []}), 200
        elif not response.ok:
            error_message = handle_api_error(response, 'Failed to fetch users')
            return jsonify({'error': error_message}), response.status_code
            
        return response.json(), 200
    except requests.Timeout:
        print("Timeout error fetching users")
        return jsonify({'error': 'Request timed out'}), 504
    except requests.ConnectionError:
        print("Connection error fetching users")
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
        # Get query parameters for filtering
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
        
        if response.status_code == 401:
            return jsonify({'error': 'Authentication failed'}), 401
        elif response.status_code == 403:
            return jsonify({'error': 'Access forbidden'}), 403
        elif response.status_code == 404:
            return jsonify({
                'documents': [],
                'total': 0,
                'page': int(params.get('page', 1)),
                'per_page': int(params.get('per_page', 10)),
                'total_pages': 0
            }), 200
        elif not response.ok:
            error_message = handle_api_error(response, 'Failed to fetch documents')
            return jsonify({'error': error_message}), response.status_code
            
        return response.json(), 200
    except requests.Timeout:
        print("Timeout error fetching documents")
        return jsonify({'error': 'Request timed out'}), 504
    except requests.ConnectionError:
        print("Connection error fetching documents")
        return jsonify({'error': 'Failed to connect to server'}), 503
    except Exception as e:
        print(f"Error fetching documents: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

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
            
        files = {
            'file': (secure_filename(file.filename), file.stream, file.content_type)
        }
        
        response = requests.post(
            DOCUMENTS_URL,
            headers=headers,
            data=form_data,
            files=files,
            timeout=REQUEST_TIMEOUT * 2  # Double timeout for file upload
        )
        
        if not response.ok:
            error_message = handle_api_error(response, 'Failed to create document')
            return jsonify({'error': error_message}), response.status_code
            
        return response.json(), 201
    except requests.Timeout:
        print("Timeout error creating document")
        return jsonify({'error': 'Request timed out'}), 504
    except requests.ConnectionError:
        print("Connection error creating document")
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
            
        error_message = handle_api_error(response, 'Failed to delete document')
        return jsonify({'error': error_message}), response.status_code
    except requests.Timeout:
        print("Timeout error deleting document")
        return jsonify({'error': 'Request timed out'}), 504
    except requests.ConnectionError:
        print("Connection error deleting document")
        return jsonify({'error': 'Failed to connect to server'}), 503
    except Exception as e:
        print(f"Error deleting document: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
