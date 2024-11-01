from flask import Flask, render_template

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/departments')
def departments():
    return render_template('departments.html')

@app.route('/categories')
def categories():
    return render_template('categories.html')

@app.route('/documents')
def documents():
    return render_template('documents.html')

@app.route('/users')
def users():
    return render_template('users.html')
