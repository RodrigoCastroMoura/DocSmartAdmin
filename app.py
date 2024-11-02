from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify, send_file
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
    return {'Authorization': f'Bearer {session["access_token"]}'}

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
                flash('Invalid credentials', 'error')
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

# Department CRUD routes
@app.route('/departments')
@login_required
def departments():
    try:
        headers = get_auth_headers()
        company_id = session.get('company_id')
        if not company_id:
            flash('Company ID not found', 'error')
            return render_template('departments.html', departments=[])

        response = requests.get(
            f"{DEPARTMENTS_URL}/companies/{company_id}/departments",
            headers=headers
        )
        departments_data = response.json() if response.status_code == 200 else []
        return render_template('departments.html', departments=departments_data)
    except Exception as e:
        print(f"Error fetching departments: {e}")
        flash('Error loading departments', 'error')
        return render_template('departments.html', departments=[])

@app.route('/api/departments', methods=['GET', 'POST'])
@login_required
def department_api():
    headers = get_auth_headers()
    company_id = session.get('company_id')
    
    if not company_id:
        return jsonify({'error': 'Company ID not found'}), 400
    
    if request.method == 'GET':
        try:
            response = requests.get(
                f"{DEPARTMENTS_URL}/companies/{company_id}/departments",
                headers=headers
            )
            return jsonify(response.json()), response.status_code
        except Exception as e:
            print(f"Error fetching departments: {e}")
            return jsonify({'error': 'Failed to fetch departments'}), 500
    
    elif request.method == 'POST':
        try:
            data = request.json
            data['company_id'] = company_id
            response = requests.post(DEPARTMENTS_URL, headers=headers, json=data)
            return jsonify(response.json()), response.status_code
        except Exception as e:
            print(f"Error creating department: {e}")
            return jsonify({'error': 'Failed to create department'}), 500

@app.route('/api/departments/<department_id>', methods=['PUT', 'DELETE'])
@login_required
def department_detail_api(department_id):
    headers = get_auth_headers()
    company_id = session.get('company_id')
    
    if not company_id:
        return jsonify({'error': 'Company ID not found'}), 400
    
    if request.method == 'PUT':
        try:
            data = request.json
            data['company_id'] = company_id
            response = requests.put(
                f"{DEPARTMENTS_URL}/{department_id}",
                headers=headers,
                json=data
            )
            return jsonify(response.json()), response.status_code
        except Exception as e:
            print(f"Error updating department: {e}")
            return jsonify({'error': 'Failed to update department'}), 500
            
    elif request.method == 'DELETE':
        try:
            response = requests.delete(
                f"{DEPARTMENTS_URL}/{department_id}",
                headers=headers
            )
            return '', response.status_code
        except Exception as e:
            print(f"Error deleting department: {e}")
            return jsonify({'error': 'Failed to delete department'}), 500

# Categories CRUD routes
@app.route('/categories')
@login_required
def categories():
    try:
        headers = get_auth_headers()
        company_id = session.get('company_id')
        if not company_id:
            flash('Company ID not found', 'error')
            return render_template('categories.html', categories=[])

        # Get departments for the dropdown
        departments_response = requests.get(
            f"{DEPARTMENTS_URL}/companies/{company_id}/departments",
            headers=headers
        )
        departments = departments_response.json() if departments_response.status_code == 200 else []

        # Get categories
        categories_response = requests.get(
            f"{CATEGORIES_URL}/companies/{company_id}/categories",
            headers=headers
        )
        categories_data = categories_response.json() if categories_response.status_code == 200 else []
        
        return render_template('categories.html', 
                             categories=categories_data,
                             departments=departments)
    except Exception as e:
        print(f"Error loading categories: {e}")
        flash('Error loading categories', 'error')
        return render_template('categories.html', categories=[], departments=[])

@app.route('/api/categories', methods=['GET', 'POST'])
@login_required
def category_api():
    headers = get_auth_headers()
    company_id = session.get('company_id')

    if not company_id:
        return jsonify({'error': 'Company ID not found'}), 400
    
    if request.method == 'GET':
        try:
            response = requests.get(
                f"{CATEGORIES_URL}/companies/{company_id}/categories",
                headers=headers
            )
            return jsonify(response.json()), response.status_code
        except Exception as e:
            print(f"Error fetching categories: {e}")
            return jsonify({'error': 'Failed to fetch categories'}), 500
    
    elif request.method == 'POST':
        try:
            data = request.json
            data['company_id'] = company_id
            response = requests.post(CATEGORIES_URL, headers=headers, json=data)
            return jsonify(response.json()), response.status_code
        except Exception as e:
            print(f"Error creating category: {e}")
            return jsonify({'error': 'Failed to create category'}), 500

@app.route('/api/categories/<category_id>', methods=['PUT', 'DELETE'])
@login_required
def category_detail_api(category_id):
    headers = get_auth_headers()
    company_id = session.get('company_id')

    if not company_id:
        return jsonify({'error': 'Company ID not found'}), 400
    
    if request.method == 'PUT':
        try:
            data = request.json
            data['company_id'] = company_id
            response = requests.put(
                f"{CATEGORIES_URL}/{category_id}",
                headers=headers,
                json=data
            )
            return jsonify(response.json()), response.status_code
        except Exception as e:
            print(f"Error updating category: {e}")
            return jsonify({'error': 'Failed to update category'}), 500
            
    elif request.method == 'DELETE':
        try:
            response = requests.delete(
                f"{CATEGORIES_URL}/{category_id}",
                headers=headers
            )
            return '', response.status_code
        except Exception as e:
            print(f"Error deleting category: {e}")
            return jsonify({'error': 'Failed to delete category'}), 500

# Documents CRUD routes
@app.route('/documents')
@login_required
def documents():
    try:
        headers = get_auth_headers()
        company_id = session.get('company_id')
        if not company_id:
            flash('Company ID not found', 'error')
            return render_template('documents.html', documents=[])

        response = requests.get(
            f"{DOCUMENTS_URL}/companies/{company_id}/documents",
            headers=headers
        )
        documents_data = response.json() if response.status_code == 200 else []
        return render_template('documents.html', documents=documents_data)
    except Exception as e:
        print(f"Error fetching documents: {e}")
        flash('Error loading documents', 'error')
        return render_template('documents.html', documents=[])

@app.route('/api/documents', methods=['POST'])
@login_required
def create_document():
    try:
        headers = get_auth_headers()
        company_id = session.get('company_id')
        if not company_id:
            return jsonify({'error': 'Company ID not found'}), 400

        files = {'file': (request.files['file'].filename, request.files['file'])}
        data = {
            'name': request.form['name'],
            'type': request.form['type'],
            'department_id': request.form['department_id'],
            'category_id': request.form['category_id'],
            'company_id': company_id
        }
        response = requests.post(DOCUMENTS_URL, headers=headers, data=data, files=files)
        return jsonify(response.json()), response.status_code
    except Exception as e:
        print(f"Error creating document: {e}")
        return jsonify({'error': 'Failed to create document'}), 500

@app.route('/api/documents/<document_id>', methods=['PUT', 'DELETE'])
@login_required
def document_detail_api(document_id):
    headers = get_auth_headers()
    company_id = session.get('company_id')

    if not company_id:
        return jsonify({'error': 'Company ID not found'}), 400
    
    if request.method == 'PUT':
        try:
            data = request.json
            data['company_id'] = company_id
            response = requests.put(
                f"{DOCUMENTS_URL}/{document_id}",
                headers=headers,
                json=data
            )
            return jsonify(response.json()), response.status_code
        except Exception as e:
            print(f"Error updating document: {e}")
            return jsonify({'error': 'Failed to update document'}), 500
            
    elif request.method == 'DELETE':
        try:
            response = requests.delete(
                f"{DOCUMENTS_URL}/{document_id}",
                headers=headers
            )
            return '', response.status_code
        except Exception as e:
            print(f"Error deleting document: {e}")
            return jsonify({'error': 'Failed to delete document'}), 500

@app.route('/api/documents/<document_id>/download')
@login_required
def download_document(document_id):
    try:
        headers = get_auth_headers()
        response = requests.get(f"{DOCUMENTS_URL}/{document_id}/download", headers=headers, stream=True)
        
        if response.status_code == 200:
            filename = response.headers.get('Content-Disposition', '').split('filename=')[-1].strip('"')
            return send_file(
                response.raw,
                download_name=filename,
                as_attachment=True,
                mimetype=response.headers.get('Content-Type')
            )
        return '', response.status_code
    except Exception as e:
        print(f"Error downloading document: {e}")
        return jsonify({'error': 'Failed to download document'}), 500

# Users CRUD routes
@app.route('/users')
@login_required
def users():
    try:
        headers = get_auth_headers()
        company_id = session.get('company_id')
        if not company_id:
            flash('Company ID not found', 'error')
            return render_template('users.html', users=[])

        response = requests.get(
            f"{USERS_URL}/companies/{company_id}/users",
            headers=headers
        )
        users_data = response.json() if response.status_code == 200 else []
        return render_template('users.html', users=users_data)
    except Exception as e:
        print(f"Error fetching users: {e}")
        flash('Error loading users', 'error')
        return render_template('users.html', users=[])

@app.route('/api/users', methods=['GET', 'POST'])
@login_required
def user_api():
    headers = get_auth_headers()
    company_id = session.get('company_id')

    if not company_id:
        return jsonify({'error': 'Company ID not found'}), 400
    
    if request.method == 'GET':
        try:
            response = requests.get(
                f"{USERS_URL}/companies/{company_id}/users",
                headers=headers
            )
            return jsonify(response.json()), response.status_code
        except Exception as e:
            print(f"Error fetching users: {e}")
            return jsonify({'error': 'Failed to fetch users'}), 500
    
    elif request.method == 'POST':
        try:
            data = request.json
            data['company_id'] = company_id
            response = requests.post(USERS_URL, headers=headers, json=data)
            return jsonify(response.json()), response.status_code
        except Exception as e:
            print(f"Error creating user: {e}")
            return jsonify({'error': 'Failed to create user'}), 500

@app.route('/api/users/<user_id>', methods=['PUT', 'DELETE'])
@login_required
def user_detail_api(user_id):
    headers = get_auth_headers()
    company_id = session.get('company_id')

    if not company_id:
        return jsonify({'error': 'Company ID not found'}), 400
    
    if request.method == 'PUT':
        try:
            data = request.json
            data['company_id'] = company_id
            response = requests.put(
                f"{USERS_URL}/{user_id}",
                headers=headers,
                json=data
            )
            return jsonify(response.json()), response.status_code
        except Exception as e:
            print(f"Error updating user: {e}")
            return jsonify({'error': 'Failed to update user'}), 500
            
    elif request.method == 'DELETE':
        try:
            response = requests.delete(
                f"{USERS_URL}/{user_id}",
                headers=headers
            )
            return '', response.status_code
        except Exception as e:
            print(f"Error deleting user: {e}")
            return jsonify({'error': 'Failed to delete user'}), 500