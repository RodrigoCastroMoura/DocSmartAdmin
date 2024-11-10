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

@app.route('/document_types/<type_id>/documents')
@login_required
def document_type_documents(type_id):
    headers = get_auth_headers()
    
    try:
        # Get document type details
        type_response = requests.get(
            f"{DOCUMENT_TYPES_URL}/{type_id}",
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )
        
        if not type_response.ok:
            error_message = handle_api_error(type_response, 'Document type not found')
            flash(error_message, 'error')
            return redirect(url_for('document_types'))
            
        document_type = type_response.json()
        
        return render_template(
            'document_type_documents.html',
            document_type=document_type
        )
    except requests.Timeout:
        flash('Request timed out. Please try again.', 'error')
    except requests.ConnectionError:
        flash('Could not connect to the server. Please try again later.', 'error')
    except Exception as e:
        print(f"Error loading document type documents: {e}")
        flash('Error loading document type documents', 'error')
        return redirect(url_for('document_types'))

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

# Main routes
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/departments')
@login_required
def departments():
    return render_template('departments.html')

@app.route('/departments/<department_id>/categories')
@login_required
def department_categories(department_id):
    headers = get_auth_headers()
    
    try:
        # Get department details
        dept_response = requests.get(
            f"{DEPARTMENTS_URL}/{department_id}",
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )
        
        if not dept_response.ok:
            error_message = handle_api_error(dept_response, 'Department not found')
            flash(error_message, 'error')
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
        elif cat_response.status_code == 404:
            flash('No categories found for this department', 'info')
        else:
            error_message = handle_api_error(cat_response, 'Error loading categories')
            flash(error_message, 'error')
        
        return render_template(
            'department_categories.html',
            department=department,
            categories=categories
        )
    except requests.Timeout:
        flash('Request timed out. Please try again.', 'error')
    except requests.ConnectionError:
        flash('Could not connect to the server. Please try again later.', 'error')
    except Exception as e:
        print(f"Error loading department categories: {e}")
        flash('Error loading department categories', 'error')
    
    return redirect(url_for('departments'))

@app.route('/categories/<category_id>/document_types')
@login_required
def category_document_types(category_id):
    headers = get_auth_headers()
    
    try:
        # Get category details
        cat_response = requests.get(
            f"{CATEGORIES_URL}/{category_id}",
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )
        
        if not cat_response.ok:
            error_message = handle_api_error(cat_response, 'Category not found')
            flash(error_message, 'error')
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
        elif types_response.status_code == 404:
            flash('No document types found for this category', 'info')
        else:
            error_message = handle_api_error(types_response, 'Error loading document types')
            flash(error_message, 'error')
        
        return render_template(
            'category_document_types.html',
            category=category,
            document_types=document_types
        )
    except requests.Timeout:
        flash('Request timed out. Please try again.', 'error')
    except requests.ConnectionError:
        flash('Could not connect to the server. Please try again later.', 'error')
    except Exception as e:
        print(f"Error loading category document types: {e}")
        flash('Error loading category document types', 'error')
    
    return redirect(url_for('categories'))

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
        params = {
            'page': request.args.get('page', 1),
            'per_page': request.args.get('per_page', 10),
            'department_id': request.args.get('department_id'),
            'category_id': request.args.get('category_id'),
            'document_type_id': request.args.get('document_type_id'),
            'user_id': request.args.get('user_id'),
            'cpf': request.args.get('cpf'),
            'company_id': company_id
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
                'page': 1,
                'per_page': 10,
                'total_pages': 1
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
        # Get form data
        titulo = request.form.get('titulo')
        user_id = request.form.get('user_id')
        document_type_id = request.form.get('document_type_id')
        file = request.files.get('file')
        
        if not all([titulo, user_id, document_type_id, file]):
            return jsonify({'error': 'Missing required fields'}), 400
            
        # Create form data with file
        form_data = {
            'titulo': titulo,
            'user_id': user_id,
            'document_type_id': document_type_id,
            'company_id': company_id
        }
        
        files = {
            'file': (secure_filename(file.filename), file, file.content_type)
        }
        
        # Make request to API
        response = requests.post(
            DOCUMENTS_URL,
            headers=headers,
            data=form_data,
            files=files,
            timeout=REQUEST_TIMEOUT
        )
        
        if response.status_code == 201:
            return response.json(), 201
            
        error_message = handle_api_error(response, 'Failed to create document')
        return jsonify({'error': error_message}), response.status_code
    except requests.Timeout:
        print("Timeout error creating document")
        return jsonify({'error': 'Request timed out'}), 504
    except requests.ConnectionError:
        print("Connection error creating document")
        return jsonify({'error': 'Failed to connect to server'}), 503
    except Exception as e:
        print(f"Error creating document: {e}")
        return jsonify({'error': 'Failed to create document'}), 500

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

@app.route('/api/document_types', methods=['POST'])
@login_required
def create_document_type():
    headers = get_auth_headers()
    company_id = session.get('company_id')
    
    if not company_id:
        return jsonify({'error': 'Company ID not found in session'}), 400
        
    try:
        data = request.json
        if not data or not data.get('name') or not data.get('category_id'):
            return jsonify({'error': 'Name and category_id are required'}), 400
            
        data['company_id'] = company_id
        response = requests.post(
            DOCUMENT_TYPES_URL,
            headers=headers,
            json=data,
            timeout=REQUEST_TIMEOUT
        )
        
        if response.status_code == 201:
            return response.json(), 201
            
        error_message = handle_api_error(response, 'Failed to create document type')
        return jsonify({'error': error_message}), response.status_code
    except requests.Timeout:
        print("Timeout error creating document type")
        return jsonify({'error': 'Request timed out'}), 504
    except requests.ConnectionError:
        print("Connection error creating document type")
        return jsonify({'error': 'Failed to connect to server'}), 503
    except Exception as e:
        print(f"Error creating document type: {e}")
        return jsonify({'error': 'Failed to create document type'}), 500

@app.route('/api/document_types/<type_id>', methods=['PUT', 'DELETE'])
@login_required
def document_type_detail_api(type_id):
    headers = get_auth_headers()
    
    if request.method == 'PUT':
        try:
            data = request.json
            if not data or not data.get('name'):
                return jsonify({'error': 'Name is required'}), 400
                
            response = requests.put(
                f"{DOCUMENT_TYPES_URL}/{type_id}",
                headers=headers,
                json=data,
                timeout=REQUEST_TIMEOUT
            )
            
            if response.status_code == 200:
                return response.json(), 200
                
            error_message = handle_api_error(response, 'Failed to update document type')
            return jsonify({'error': error_message}), response.status_code
        except requests.Timeout:
            print("Timeout error updating document type")
            return jsonify({'error': 'Request timed out'}), 504
        except requests.ConnectionError:
            print("Connection error updating document type")
            return jsonify({'error': 'Failed to connect to server'}), 503
        except Exception as e:
            print(f"Error updating document type: {e}")
            return jsonify({'error': 'Failed to update document type'}), 500
            
    elif request.method == 'DELETE':
        try:
            response = requests.delete(
                f"{DOCUMENT_TYPES_URL}/{type_id}",
                headers=headers,
                timeout=REQUEST_TIMEOUT
            )
            
            if response.status_code == 204:
                return '', 204
                
            error_message = handle_api_error(response, 'Failed to delete document type')
            return jsonify({'error': error_message}), response.status_code
        except requests.Timeout:
            print("Timeout error deleting document type")
            return jsonify({'error': 'Request timed out'}), 504
        except requests.ConnectionError:
            print("Connection error deleting document type")
            return jsonify({'error': 'Failed to connect to server'}), 503
        except Exception as e:
            print(f"Error deleting document type: {e}")
            return jsonify({'error': 'Failed to delete document type'}), 500

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
            return jsonify([]), 200
        elif not response.ok:
            error_message = handle_api_error(response, 'Failed to fetch document types')
            return jsonify({'error': error_message}), response.status_code
            
        return response.json(), 200
    except requests.Timeout:
        print("Timeout error fetching category document types")
        return jsonify({'error': 'Request timed out'}), 504
    except requests.ConnectionError:
        print("Connection error fetching category document types")
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
