from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import db, User, Department, Category, Document
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///admin.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

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
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    name = request.form.get('name')
    description = request.form.get('description')
    
    if not name:
        return jsonify({'error': 'Name is required'}), 400
    
    try:
        department = Department(name=name, description=description)
        db.session.add(department)
        db.session.commit()
        return jsonify({'message': 'Department added successfully', 'id': department.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/departments/<int:id>', methods=['PUT'])
@login_required
def update_department(id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    department = Department.query.get_or_404(id)
    data = request.get_json()
    
    try:
        if 'name' in data:
            department.name = data['name']
        if 'description' in data:
            department.description = data['description']
        db.session.commit()
        return jsonify({'message': 'Department updated successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/departments/<int:id>', methods=['DELETE'])
@login_required
def delete_department(id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    department = Department.query.get_or_404(id)
    try:
        db.session.delete(department)
        db.session.commit()
        return jsonify({'message': 'Department deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# Category routes
@app.route('/categories')
@login_required
def categories():
    categories = Category.query.all()
    return render_template('categories.html', categories=categories)

@app.route('/categories/add', methods=['POST'])
@login_required
def add_category():
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    name = request.form.get('name')
    description = request.form.get('description')
    
    if not name:
        return jsonify({'error': 'Name is required'}), 400
    
    try:
        category = Category(name=name, description=description)
        db.session.add(category)
        db.session.commit()
        return jsonify({'message': 'Category added successfully', 'id': category.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/categories/<int:id>', methods=['PUT'])
@login_required
def update_category(id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    category = Category.query.get_or_404(id)
    data = request.get_json()
    
    try:
        if 'name' in data:
            category.name = data['name']
        if 'description' in data:
            category.description = data['description']
        db.session.commit()
        return jsonify({'message': 'Category updated successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/categories/<int:id>', methods=['DELETE'])
@login_required
def delete_category(id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    category = Category.query.get_or_404(id)
    try:
        db.session.delete(category)
        db.session.commit()
        return jsonify({'message': 'Category deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# Document routes
@app.route('/documents')
@login_required
def documents():
    documents = Document.query.all()
    return render_template('documents.html', documents=documents)

@app.route('/documents/add', methods=['POST'])
@login_required
def add_document():
    title = request.form.get('title')
    description = request.form.get('description')
    department_id = request.form.get('department_id')
    category_id = request.form.get('category_id')
    
    if not title:
        return jsonify({'error': 'Title is required'}), 400
    
    try:
        document = Document(
            title=title,
            description=description,
            department_id=department_id,
            category_id=category_id,
            uploaded_by=current_user.id
        )
        db.session.add(document)
        db.session.commit()
        return jsonify({'message': 'Document added successfully', 'id': document.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/documents/<int:id>', methods=['PUT'])
@login_required
def update_document(id):
    document = Document.query.get_or_404(id)
    
    if document.uploaded_by != current_user.id and current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    
    try:
        if 'title' in data:
            document.title = data['title']
        if 'description' in data:
            document.description = data['description']
        if 'department_id' in data:
            document.department_id = data['department_id']
        if 'category_id' in data:
            document.category_id = data['category_id']
        document.updated_at = datetime.utcnow()
        db.session.commit()
        return jsonify({'message': 'Document updated successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/documents/<int:id>', methods=['DELETE'])
@login_required
def delete_document(id):
    document = Document.query.get_or_404(id)
    
    if document.uploaded_by != current_user.id and current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        db.session.delete(document)
        db.session.commit()
        return jsonify({'message': 'Document deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# User routes
@app.route('/users')
@login_required
def users():
    if current_user.role != 'admin':
        flash('Unauthorized access', 'error')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    departments = Department.query.all()
    return render_template('users.html', users=users, departments=departments)

@app.route('/users/add', methods=['POST'])
@login_required
def add_user():
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    department_id = request.form.get('department_id')
    role = request.form.get('role', 'user')
    
    if not all([username, email, password]):
        return jsonify({'error': 'All fields are required'}), 400
    
    try:
        user = User(
            username=username,
            email=email,
            department_id=department_id,
            role=role
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return jsonify({'message': 'User added successfully', 'id': user.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/users/<int:id>', methods=['PUT'])
@login_required
def update_user(id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    user = User.query.get_or_404(id)
    data = request.get_json()
    
    try:
        if 'username' in data:
            user.username = data['username']
        if 'email' in data:
            user.email = data['email']
        if 'password' in data:
            user.set_password(data['password'])
        if 'department_id' in data:
            user.department_id = data['department_id']
        if 'role' in data:
            user.role = data['role']
        if 'status' in data:
            user.status = data['status']
        db.session.commit()
        return jsonify({'message': 'User updated successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/users/<int:id>', methods=['DELETE'])
@login_required
def delete_user(id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    if id == current_user.id:
        return jsonify({'error': 'Cannot delete yourself'}), 400
    
    user = User.query.get_or_404(id)
    try:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'User deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
