from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify, send_file, Response
from functools import wraps
import requests
import os
import json
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
        except:
            return redirect(url_for('login'))
            
        return f(*args, **kwargs)
    return decorated_function

def get_auth_headers():
    return {
        'Authorization': f'Bearer {session["access_token"]}',
        'accept': 'application/json'
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
    headers = get_auth_headers()
    company_id = session.get('company_id')
    try:
        departments_response = requests.get(
            f"{DEPARTMENTS_URL}/companies/{company_id}/departments",
            headers=headers
        )
        departments = departments_response.json() if departments_response.ok else []
        return render_template('categories.html', departments=departments)
    except Exception as e:
        print(f"Error loading departments: {e}")
        return render_template('categories.html', departments=[])

@app.route('/documents')
@login_required
def documents():
    headers = get_auth_headers()
    company_id = session.get('company_id')
    try:
        departments_response = requests.get(
            f"{DEPARTMENTS_URL}/companies/{company_id}/departments",
            headers=headers
        )
        departments = departments_response.json() if departments_response.ok else []
        return render_template('documents.html', departments=departments)
    except Exception as e:
        print(f"Error loading form data: {e}")
        return render_template('documents.html', departments=[])

@app.route('/document_types')
@login_required
def document_types():
    return render_template('document_types.html')

@app.route('/users')
@login_required
def users():
    return render_template('users.html')

@app.route('/api/document_types', methods=['GET', 'POST'])
@login_required
def document_type_api():
    headers = get_auth_headers()
    company_id = session.get('company_id')
    
    if request.method == 'GET':
        try:
            response = requests.get(
                f'{DOCUMENT_TYPES_URL}/companies/{company_id}/document_types',
                headers=headers
            )
            
            if response.status_code == 204:
                return jsonify({
                    'types': [],
                    'total': 0,
                    'page': 1,
                    'per_page': 10,
                    'total_pages': 0
                }), 200  # Return 200 even for empty results
            
            if response.ok:
                data = response.json()
                return jsonify({
                    'types': data.get('types', []),
                    'total': data.get('total', 0),
                    'page': data.get('page', 1),
                    'per_page': data.get('per_page', 10),
                    'total_pages': data.get('total_pages', 0)
                }), 200
                
            return jsonify({'error': 'Failed to fetch document types', 'types': []}), response.status_code
            
        except Exception as e:
            print(f'Error fetching document types: {e}')
            return jsonify({
                'error': 'Failed to fetch document types',
                'types': []
            }), 500
            
    elif request.method == 'POST':
        try:
            data = request.json
            if not data:
                return jsonify({'error': 'No data provided'}), 400
                
            if not data.get('name'):
                return jsonify({'error': 'Name is required'}), 400
                
            data['company_id'] = company_id
            response = requests.post(
                DOCUMENT_TYPES_URL,
                headers=headers,
                json=data
            )
            
            if response.status_code == 201:
                return response.json(), 201
            
            error_data = response.json()
            return jsonify({'error': error_data.get('error', 'Failed to create document type')}), response.status_code
            
        except Exception as e:
            print(f'Error creating document type: {e}')
            return jsonify({'error': 'Failed to create document type'}), 500

@app.route('/api/document_types/<type_id>', methods=['PUT', 'DELETE'])
@login_required
def document_type_detail_api(type_id):
    headers = get_auth_headers()
    company_id = session.get('company_id')
    
    if request.method == 'PUT':
        try:
            data = request.json
            if not data:
                return jsonify({'error': 'No data provided'}), 400
                
            if not data.get('name'):
                return jsonify({'error': 'Name is required'}), 400
                
            data['company_id'] = company_id
            response = requests.put(
                f'{DOCUMENT_TYPES_URL}/{type_id}',
                headers=headers,
                json=data
            )
            
            if response.status_code == 200:
                return response.json(), 200
                
            error_data = response.json()
            return jsonify({'error': error_data.get('error', 'Failed to update document type')}), response.status_code
            
        except Exception as e:
            print(f'Error updating document type: {e}')
            return jsonify({'error': 'Failed to update document type'}), 500
            
    elif request.method == 'DELETE':
        try:
            response = requests.delete(
                f'{DOCUMENT_TYPES_URL}/{type_id}',
                headers=headers
            )
            if response.status_code == 204:
                return '', 204
                
            error_data = response.json()
            return jsonify({'error': error_data.get('error', 'Failed to delete document type')}), response.status_code
            
        except Exception as e:
            print(f'Error deleting document type: {e}')
            return jsonify({'error': 'Failed to delete document type'}), 500

@app.route('/api/documents', methods=['GET', 'POST'])
@login_required
def document_api():
    headers = get_auth_headers()
    company_id = session.get('company_id')
    
    if request.method == 'GET':
        try:
            params = {
                'page': request.args.get('page', 1),
                'per_page': request.args.get('per_page', 10)
            }
            response = requests.get(
                f"{DOCUMENTS_URL}/companies/{company_id}/documents",
                headers=headers,
                params=params
            )
            
            if response.status_code == 204:
                return jsonify({
                    'documents': [], 
                    'total': 0, 
                    'page': params['page'], 
                    'per_page': params['per_page'], 
                    'total_pages': 0
                }), 200
            
            if response.ok:
                data = response.json()
                return jsonify(data), 200
                
            error_data = response.json()
            return jsonify({
                'error': error_data.get('error', 'Failed to fetch documents'),
                'documents': []
            }), response.status_code
            
        except Exception as e:
            print(f"Error fetching documents: {e}")
            return jsonify({
                'error': 'Failed to fetch documents',
                'documents': []
            }), 500
            
    elif request.method == 'POST':
        try:
            # Input validation
            if 'file' not in request.files:
                return jsonify({'error': 'No file provided'}), 400
                
            file = request.files['file']
            if file.filename == '':
                return jsonify({'error': 'No file selected'}), 400

            # Required fields validation
            required_fields = ['titulo', 'category_id', 'department_id', 'user_id', 'document_type_id']
            missing_fields = [field for field in required_fields if not request.form.get(field)]
            if missing_fields:
                return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400

            # File type validation
            allowed_extensions = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'txt', 'jpg', 'jpeg', 'png'}
            if not '.' in file.filename or file.filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
                return jsonify({'error': 'Invalid file type'}), 400

            # Secure filename and prepare file data
            secure_name = secure_filename(file.filename)
            files = {'file': (secure_name, file, file.content_type)}
            
            # Prepare form data
            data = {
                'titulo': request.form.get('titulo'),
                'category_id': request.form.get('category_id'),
                'department_id': request.form.get('department_id'),
                'user_id': request.form.get('user_id'),
                'document_type_id': request.form.get('document_type_id'),
                'company_id': company_id
            }
            
            # Remove content-type from headers for multipart form data
            upload_headers = {k: v for k, v in headers.items() if k.lower() != 'content-type'}
            
            # Make API request
            response = requests.post(
                DOCUMENTS_URL,
                headers=upload_headers,
                data=data,
                files=files
            )
            
            # Return appropriate status code
            if response.status_code == 201:
                return response.json(), 201
                
            error_data = response.json()
            return jsonify({'error': error_data.get('error', 'Failed to create document')}), response.status_code
                
        except requests.exceptions.RequestException as e:
            print(f"Network error while creating document: {e}")
            return jsonify({'error': 'Network error occurred while uploading document'}), 503
        except Exception as e:
            print(f"Error creating document: {e}")
            return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/documents/<document_id>', methods=['DELETE'])
@login_required
def document_detail_api(document_id):
    headers = get_auth_headers()
    
    try:
        response = requests.delete(
            f"{DOCUMENTS_URL}/{document_id}",
            headers=headers
        )
        
        if response.status_code == 204:
            return '', 204
            
        error_data = response.json()
        return jsonify({'error': error_data.get('error', 'Failed to delete document')}), response.status_code
            
    except Exception as e:
        print(f"Error deleting document: {e}")
        return jsonify({'error': 'Failed to delete document'}), 500

@app.route('/api/documents/<document_id>/download')
@login_required
def download_document(document_id):
    headers = get_auth_headers()
    try:
        response = requests.get(
            f"{DOCUMENTS_URL}/{document_id}/download",
            headers=headers,
            stream=True
        )
        
        if response.status_code == 404:
            return jsonify({'error': 'Document not found'}), 404
        elif response.status_code != 200:
            error_data = response.json()
            return jsonify({'error': error_data.get('error', 'Failed to download document')}), response.status_code
            
        content_type = response.headers.get('content-type', 'application/octet-stream')
        filename = response.headers.get('content-disposition', '').split('filename=')[-1].strip('"')
            
        def generate():
            for chunk in response.iter_content(chunk_size=8192):
                yield chunk
                    
        download_response = Response(generate(), content_type=content_type)
        download_response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        return download_response
            
    except Exception as e:
        print(f"Error downloading document: {e}")
        return jsonify({'error': 'Failed to download document'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
