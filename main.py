from app import app, departments, categories, documents, users, dashboard, login, logout, index

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
