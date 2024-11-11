from flask import url_for

def test_login_page(client):
    """Test that login page loads correctly"""
    response = client.get('/login')
    assert response.status_code == 200
    assert b'login' in response.data.lower()

def test_unauthorized_access(client):
    """Test that protected routes redirect to login when not authenticated"""
    response = client.get('/dashboard')
    assert response.status_code == 302
    assert '/login' in response.location

def test_invalid_login(client):
    """Test login with invalid credentials"""
    response = client.post('/login', data={
        'identifier': 'invalid@test.com',
        'password': 'wrongpassword'
    })
    assert response.status_code == 200
    assert b'error' in response.data.lower()
