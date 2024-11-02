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

@app.route('/users')
@login_required
def users():
    return render_template('users.html')

@app.route('/api/users', methods=['GET', 'POST'])
@login_required
def user_api():
    try:
        headers = get_auth_headers()
        company_id = session.get('company_id')
        
        if not company_id:
            return jsonify({'error': 'Company ID not found'}), 400
            
        if request.method == 'GET':
            response = requests.get(
                f"{USERS_URL}/companies/{company_id}/users",
                headers=headers
            )
            response.raise_for_status()
            return jsonify(response.json()), 200
            
        elif request.method == 'POST':
            data = request.json
            data['company_id'] = company_id
            response = requests.post(USERS_URL, headers=headers, json=data)
            response.raise_for_status()
            return jsonify(response.json()), 201
            
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

@app.route('/api/users/<user_id>', methods=['PUT', 'DELETE'])
@login_required
def user_detail_api(user_id):
    try:
        headers = get_auth_headers()
        company_id = session.get('company_id')
        
        if not company_id:
            return jsonify({'error': 'Company ID not found'}), 400
            
        if request.method == 'PUT':
            data = request.json
            data['company_id'] = company_id
            response = requests.put(
                f"{USERS_URL}/{user_id}",
                headers=headers,
                json=data
            )
            response.raise_for_status()
            return jsonify(response.json()), 200
            
        elif request.method == 'DELETE':
            response = requests.delete(
                f"{USERS_URL}/{user_id}",
                headers=headers
            )
            response.raise_for_status()
            return '', 204
            
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

@app.route('/api/departments', methods=['GET', 'POST'])
@login_required
def department_api():
    try:
        headers = get_auth_headers()
        company_id = session.get('company_id')
        
        if not company_id:
            return jsonify({'error': 'Company ID not found'}), 400
            
        if request.method == 'GET':
            response = requests.get(
                f"{DEPARTMENTS_URL}/companies/{company_id}/departments",
                headers=headers
            )
            response.raise_for_status()
            return jsonify(response.json()), 200
            
        elif request.method == 'POST':
            data = request.json
            data['company_id'] = company_id
            response = requests.post(DEPARTMENTS_URL, headers=headers, json=data)
            response.raise_for_status()
            return jsonify(response.json()), 201
            
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
