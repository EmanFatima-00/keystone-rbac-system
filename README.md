Authentication & Role-Based Access Control System

A responsive web application developed .

Features

- User registration, login, and logout
- Secure password hashing
- Three roles: Admin, Manager, and Normal User
- Role-based permissions and protected routes
- User profile management
- Admin and Manager dashboards
- SQLite database integration
- Responsive dark-themed UI

Technologies

- Python
- FastAPI
- HTML, CSS, JavaScript
- SQLite

Run Locally

Install dependencies:

pip install fastapi uvicorn python-multipart itsdangerous bcrypt

Start the application:

uvicorn main:app --reload

Open "http://127.0.0.1:8000" in your browser.

API documentation: "http://127.0.0.1:8000/docs"
