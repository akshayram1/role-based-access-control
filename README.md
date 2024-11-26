# Streamlit RBAC System

## Overview
A Role-Based Access Control (RBAC) web application built with Streamlit, MongoDB, and JWT authentication.

## Features
- User registration with role assignment
- Secure login with JWT authentication
- Role-based access control
- Admin dashboard for user role management
- Comprehensive audit logging system

## Screenshots
### Login Page
![Login Screen](/screenshots/login.png)
### Login Dashboard
![Login ](/screenshots/login2.png)
### Moderator Dashboard
![moderator ](/screenshots/moderator.png)

### Admin Dashboard
![Admin Dashboard](/screenshots/admin.png)

### User Logs
![User Logs](/screenshots/user_logs.png)
### Flow Diagram
![Flow Diagram](/screenshots/flowdiagram.png)

## Prerequisites
- Python 3.8+
- MongoDB
- Streamlit
- Required Python packages:
  - streamlit
  - pymongo
  - bcrypt
  - pyjwt
  - python-dotenv

## Installation
1. Clone the repository
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Create a `.env` file with:
   ```
   MONGO_URI=your_mongodb_connection_string
   JWT_SECRET_KEY=your_secret_key
   ```

## Roles
- **User**: Can view own login logs
- **Moderator**: Can view all system logs
- **Admin**: Can manage user roles and view all logs

## Security Features
- Password hashing with bcrypt
- JWT token-based authentication
- Role-based access control
- Comprehensive event logging

## Running the Application
```
streamlit run app.py
```

## Environment Variables
- `MONGO_URI`: MongoDB connection string
- `JWT_SECRET_KEY`: Secret key for JWT token generation

## Logging
- Captures login attempts
- Tracks user actions
- Supports different log visibility based on user role

## Contributing
1. Fork the repository
2. Create a feature branch
3. Commit changes
4. Push to the branch
5. Create a pull request
