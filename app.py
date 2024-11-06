from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify
from functools import wraps
import requests
import os

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

@app.route('/api/documents', methods=['GET', 'POST'])
@login_required
def documents_api():
    headers = get_auth_headers()
    company_id = session.get('company_id')
    
    if request.method == 'GET':
        try:
            params = {
                'page': request.args.get('page', 1),
                'per_page': request.args.get('per_page', 10)
            }

            # Add filter parameters if provided
            filter_params = ['department_id', 'category_id', 'document_type_id', 'user_id']
            for param in filter_params:
                if request.args.get(param):
                    params[param] = request.args.get(param)

            response = requests.get(
                f'{DOCUMENTS_URL}/companies/{company_id}/documents',
                headers=headers,
                params=params
            )
            return response.json(), response.status_code
        except Exception as e:
            print(f'Error fetching documents: {e}')
            return jsonify({
                'documents': [],
                'total': 0,
                'page': 1,
                'per_page': 10,
                'total_pages': 1
            }), 500
            
    elif request.method == 'POST':
        try:
            file = request.files.get('file')
            if not file:
                return jsonify({'error': 'No file provided'}), 400
                
            form_data = request.form
            if not form_data:
                return jsonify({'error': 'No form data provided'}), 400
                
            required_fields = ['titulo', 'category_id', 'department_id', 'user_id', 'document_type_id']
            missing_fields = [field for field in required_fields if not form_data.get(field)]
            if missing_fields:
                return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400
                
            files = {'file': (file.filename, file)}
            data = {
                'titulo': form_data.get('titulo'),
                'category_id': form_data.get('category_id'),
                'department_id': form_data.get('department_id'),
                'user_id': form_data.get('user_id'),
                'document_type_id': form_data.get('document_type_id'),
                'company_id': company_id
            }
            
            response = requests.post(
                DOCUMENTS_URL,
                headers={'Authorization': headers['Authorization']},
                files=files,
                data=data
            )
            
            if response.status_code == 201:
                return response.json(), 201
            return response.json(), response.status_code
        except Exception as e:
            print(f"Error creating document: {e}")
            return jsonify({'error': 'Failed to create document'}), 500

@app.route('/api/documents/<document_id>', methods=['DELETE'])
@login_required
def document_detail_api(document_id):
    headers = get_auth_headers()
    
    if request.method == 'DELETE':
        try:
            response = requests.delete(
                f"{DOCUMENTS_URL}/{document_id}",
                headers=headers
            )
            if response.status_code == 204:
                return '', 204
            return response.json(), response.status_code
        except Exception as e:
            print(f"Error deleting document: {e}")
            return jsonify({'error': 'Failed to delete document'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
