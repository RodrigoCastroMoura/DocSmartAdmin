from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import db, User, Department, Category, Document
import os
from datetime import datetime
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///admin.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'

# Ensure upload directory exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Initialize database and create tables
db.init_app(app)
with app.app_context():
    try:
        print("Creating database tables...")
        db.create_all()
        
        # Create default admin user if not exists
        if not User.query.filter_by(email='admin@example.com').first():
            print("Creating default admin user...")
            admin = User(
                username='Admin',
                email='admin@example.com',
                role='admin'
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print("Default admin user created successfully!")
        else:
            print("Default admin user already exists.")
    except Exception as e:
        print(f"Error during database initialization: {e}")
        raise

# Initialize Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Authentication routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email or not password:
            flash('Please provide both email and password', 'error')
            return render_template('login.html')
        
        try:
            user = User.query.filter_by(email=email).first()
            if user and user.check_password(password):
                login_user(user)
                return redirect(url_for('dashboard'))
            flash('Invalid email or password', 'error')
        except Exception as e:
            print(f"Login error: {e}")
            flash('An error occurred during login', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Dashboard route
@app.route('/dashboard')
@login_required
def dashboard():
    stats = {
        'total_users': User.query.count(),
        'total_documents': Document.query.count(),
        'total_departments': Department.query.count(),
        'total_categories': Category.query.count()
    }
    return render_template('dashboard.html', stats=stats)

# Department routes
@app.route('/departments')
@login_required
def departments():
    departments = Department.query.all()
    return render_template('departments.html', departments=departments)

@app.route('/departments/add', methods=['POST'])
@login_required
def add_department():
    if not current_user.role == 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        data = request.get_json()
        if not data.get('name'):
            return jsonify({'error': 'Department name is required'}), 400
            
        department = Department(
            name=data['name'],
            description=data.get('description', '')
        )
        db.session.add(department)
        db.session.commit()
        return jsonify({'message': 'Department added successfully', 'id': department.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/departments/<int:id>', methods=['PUT'])
@login_required
def update_department(id):
    if not current_user.role == 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    department = Department.query.get_or_404(id)
    try:
        data = request.get_json()
        if not data.get('name'):
            return jsonify({'error': 'Department name is required'}), 400
            
        department.name = data.get('name', department.name)
        department.description = data.get('description', department.description)
        db.session.commit()
        return jsonify({'message': 'Department updated successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/departments/<int:id>', methods=['DELETE'])
@login_required
def delete_department(id):
    if not current_user.role == 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    department = Department.query.get_or_404(id)
    try:
        if len(department.users) > 0:
            return jsonify({'error': 'Cannot delete department with associated users'}), 400
        if len(department.documents) > 0:
            return jsonify({'error': 'Cannot delete department with associated documents'}), 400
            
        db.session.delete(department)
        db.session.commit()
        return jsonify({'message': 'Department deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

# Category routes
@app.route('/categories')
@login_required
def categories():
    categories = Category.query.all()
    return render_template('categories.html', categories=categories)

@app.route('/categories/add', methods=['POST'])
@login_required
def add_category():
    if not current_user.role == 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        data = request.get_json()
        if not data.get('name'):
            return jsonify({'error': 'Category name is required'}), 400
            
        category = Category(
            name=data['name'],
            description=data.get('description', '')
        )
        db.session.add(category)
        db.session.commit()
        return jsonify({'message': 'Category added successfully', 'id': category.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/categories/<int:id>', methods=['PUT'])
@login_required
def update_category(id):
    if not current_user.role == 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    category = Category.query.get_or_404(id)
    try:
        data = request.get_json()
        if not data.get('name'):
            return jsonify({'error': 'Category name is required'}), 400
            
        category.name = data.get('name', category.name)
        category.description = data.get('description', category.description)
        db.session.commit()
        return jsonify({'message': 'Category updated successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/categories/<int:id>', methods=['DELETE'])
@login_required
def delete_category(id):
    if not current_user.role == 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    category = Category.query.get_or_404(id)
    try:
        if len(category.documents) > 0:
            return jsonify({'error': 'Cannot delete category with associated documents'}), 400
            
        db.session.delete(category)
        db.session.commit()
        return jsonify({'message': 'Category deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

# Document routes
@app.route('/documents')
@login_required
def documents():
    documents = Document.query.all()
    categories = Category.query.all()
    departments = Department.query.all()
    return render_template('documents.html', 
                         documents=documents,
                         categories=categories,
                         departments=departments)

@app.route('/documents/add', methods=['POST'])
@login_required
def add_document():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
            
        if not request.form.get('title'):
            return jsonify({'error': 'Document title is required'}), 400
        
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        document = Document(
            title=request.form['title'],
            description=request.form.get('description', ''),
            filename=filename,
            file_path=file_path,
            mime_type=file.content_type,
            user_id=current_user.id,
            department_id=request.form['department_id'],
            category_id=request.form['category_id']
        )
        db.session.add(document)
        db.session.commit()
        return jsonify({'message': 'Document uploaded successfully', 'id': document.id})
    except Exception as e:
        db.session.rollback()
        if os.path.exists(file_path):
            os.remove(file_path)
        return jsonify({'error': str(e)}), 400

@app.route('/documents/<int:id>', methods=['PUT'])
@login_required
def update_document(id):
    document = Document.query.get_or_404(id)
    if document.user_id != current_user.id and current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        data = request.get_json()
        if not data.get('title'):
            return jsonify({'error': 'Document title is required'}), 400
            
        document.title = data.get('title', document.title)
        document.description = data.get('description', document.description)
        document.department_id = data.get('department_id', document.department_id)
        document.category_id = data.get('category_id', document.category_id)
        document.updated_at = datetime.utcnow()
        db.session.commit()
        return jsonify({'message': 'Document updated successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/documents/<int:id>', methods=['DELETE'])
@login_required
def delete_document(id):
    document = Document.query.get_or_404(id)
    if document.user_id != current_user.id and current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        if document.file_path and os.path.exists(document.file_path):
            os.remove(document.file_path)
        db.session.delete(document)
        db.session.commit()
        return jsonify({'message': 'Document deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

# User routes
@app.route('/users')
@login_required
def users():
    if not current_user.role == 'admin':
        flash('Unauthorized access', 'error')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    departments = Department.query.all()
    return render_template('users.html', users=users, departments=departments)

@app.route('/users/<int:id>', methods=['GET'])
@login_required
def get_user(id):
    if not current_user.role == 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
        
    user = User.query.get_or_404(id)
    return jsonify({
        'username': user.username,
        'email': user.email,
        'department_id': user.department_id,
        'role': user.role,
        'status': user.status
    })

@app.route('/users/add', methods=['POST'])
@login_required
def add_user():
    if not current_user.role == 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        data = request.get_json()
        if not data.get('username'):
            return jsonify({'error': 'Username is required'}), 400
        if not data.get('email'):
            return jsonify({'error': 'Email is required'}), 400
        if not data.get('password'):
            return jsonify({'error': 'Password is required'}), 400
            
        # Check if email already exists
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'error': 'Email already exists'}), 400
            
        user = User(
            username=data['username'],
            email=data['email'],
            department_id=data.get('department_id'),
            role=data.get('role', 'user'),
            status=data.get('status', True)
        )
        user.set_password(data['password'])
        db.session.add(user)
        db.session.commit()
        return jsonify({'message': 'User added successfully', 'id': user.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/users/<int:id>', methods=['PUT'])
@login_required
def update_user(id):
    if not current_user.role == 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    user = User.query.get_or_404(id)
    try:
        data = request.get_json()
        if not data.get('username'):
            return jsonify({'error': 'Username is required'}), 400
        if not data.get('email'):
            return jsonify({'error': 'Email is required'}), 400
            
        # Check if email already exists and it's not the same user
        existing_user = User.query.filter_by(email=data['email']).first()
        if existing_user and existing_user.id != id:
            return jsonify({'error': 'Email already exists'}), 400
            
        user.username = data.get('username', user.username)
        user.email = data.get('email', user.email)
        user.department_id = data.get('department_id')
        user.role = data.get('role', user.role)
        user.status = data.get('status', user.status)
        
        if 'password' in data and data['password']:
            user.set_password(data['password'])
            
        db.session.commit()
        return jsonify({'message': 'User updated successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/users/<int:id>', methods=['DELETE'])
@login_required
def delete_user(id):
    if not current_user.role == 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    if id == current_user.id:
        return jsonify({'error': 'Cannot delete your own account'}), 400
    
    user = User.query.get_or_404(id)
    try:
        # Check if user has associated documents
        if len(user.documents) > 0:
            return jsonify({'error': 'Cannot delete user with associated documents'}), 400
            
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'User deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400
