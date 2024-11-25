import streamlit as st
from pymongo import MongoClient
import bcrypt
import jwt
import datetime
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()
MONGO_URI = os.getenv("MONGO_URI")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")

# MongoDB connection
client = MongoClient(MONGO_URI)
db = client["rbac_system"]
users_col = db["users"]
logs_col = db["logs"]

# Configure logging
import logging
logging.basicConfig(format="%(asctime)s - %(levelname)s - %(message)s", level=logging.INFO)

# Helper functions
def hash_password(password):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode("utf-8"), hashed)


def create_token(username, role):
    payload = {
        "username": username,
        "role": role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm="HS256")


def decode_token(token):
    try:
        return jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        st.error("Session expired. Please log in again.")
        return None
    except jwt.InvalidTokenError:
        st.error("Invalid token.")
        return None


def log_event(user, action, resource=None, status="success", details=None):
    log_entry = {
        "user": user,
        "action": action,
        "resource": resource,
        "status": status,
        "details": details,
        "timestamp": datetime.datetime.utcnow()
    }
    logs_col.insert_one(log_entry)
    logging.info(f"User: {user}, Action: {action}, Resource: {resource}, Status: {status}, Details: {details}")


# Authorization decorator
def authorize(required_roles):
    def wrapper(func):
        def wrapped(*args, **kwargs):
            token = st.session_state.get("token")
            if not token:
                st.error("Access denied. Please log in.")
                return

            decoded = decode_token(token)
            if decoded and decoded["role"] in required_roles:
                return func(*args, **kwargs)
            else:
                st.error("Access denied. Insufficient permissions.")
        return wrapped
    return wrapper


# App logic
def register_user():
    st.subheader("Register User")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    role = st.selectbox("Role", ["user", "moderator", "admin"])
    if st.button("Register"):
        if users_col.find_one({"username": username}):
            st.error("Username already exists.")
        else:
            hashed_password = hash_password(password)
            users_col.insert_one({"username": username, "password": hashed_password, "role": role})
            log_event("system", "register_user", resource=username, details=f"Role assigned: {role}")
            st.success("User registered successfully!")


def login_user():
    st.subheader("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        user = users_col.find_one({"username": username})
        if user and verify_password(password, user["password"]):
            token = create_token(username, user["role"])
            st.session_state["token"] = token
            st.session_state["role"] = user["role"]  # Save role in session state
            log_event(username, "login")
            st.success("Logged in successfully!")

            # Redirect to the dashboard
            st.rerun()  # Use st.rerun() instead of st.experimental_rerun()
        else:
            log_event(username, "login", status="failed", details="Invalid credentials")
            st.error("Invalid username or password.")



def admin_dashboard():
    st.subheader("Admin Dashboard")
    admin_action = st.selectbox("Admin Actions", ["Manage Roles", "View Logs"])
    if admin_action == "Manage Roles":
        manage_roles()
    elif admin_action == "View Logs":
        view_logs()


def manage_roles():
    st.subheader("Manage User Roles")
    users = list(users_col.find({}, {"username": 1, "role": 1, "_id": 0}))
    for user in users:
        if user["role"] in ["user", "moderator"]:  # Only allow changing roles for user and moderator
            st.write(f"Username: {user['username']}, Role: {user['role']}")
            if st.button(f"Change Role for {user['username']}"):
                new_role = st.selectbox(
                    f"Select New Role for {user['username']}",
                    ["user", "moderator"],
                    key=user["username"]
                )
                update_role(user["username"], new_role)


def update_role(username, new_role):
    result = users_col.update_one({"username": username}, {"$set": {"role": new_role}})
    if result.modified_count > 0:
        log_event("admin", "update_role", resource=username, details=f"Changed role to {new_role}")
        st.success(f"Updated {username}'s role to {new_role}.")
    else:
        log_event("admin", "update_role", resource=username, status="failed", details="No changes made")
        st.error(f"Failed to update role for {username}.")


def view_logs():
    st.subheader("Audit Trail")
    token = st.session_state["token"]
    decoded = decode_token(token)

    if decoded["role"] == "user":
        query = {"user": decoded["username"], "action": "login"}  # Users can only see their login logs
    else:
        query = {}  # Admins and moderators can see all logs

    limit = st.number_input("Number of Logs to Display", min_value=1, value=10)
    logs_cursor = logs_col.find(query).sort("timestamp", -1).limit(limit)
    
    # Convert logs to a DataFrame for better display
    logs_list = []
    for log in logs_cursor:
        logs_list.append({
            "User": log["user"],
            "Action": log["action"],
            "Resource": log.get("resource", "N/A"),
            "Status": log["status"],
            "Details": log.get("details", "N/A"),
            "Timestamp": log["timestamp"]
        })

    if logs_list:
        st.dataframe(logs_list)  # Show logs in a dynamic table
    else:
        st.info("No logs found.")



# Main Streamlit app
# Main Streamlit app
def main():
    st.title("Streamlit RBAC System")
    menu = st.sidebar.selectbox("Menu", ["Login", "Register", "Dashboard"])

    # Check if the user is already logged in
    token = st.session_state.get("token")
    if token:
        decoded = decode_token(token)
        if decoded:
            role = decoded["role"]
            st.sidebar.write(f"Logged in as: {decoded['username']} ({role.capitalize()})")
            
            # Add Logout button
            if st.sidebar.button("Logout"):
                # Clear session state and redirect to login
                st.session_state.clear()
                st.success("Logged out successfully!")
                st.rerun()

            # Role-based navigation
            if role == "admin":
                admin_dashboard()
            elif role in ["moderator", "admin"]:
                view_logs()
            elif role == "user":
                view_logs()
        else:
            st.error("Access denied. Please log in.")
    else:
        # Show the selected menu
        if menu == "Register":
            register_user()
        elif menu == "Login":
            login_user()
        elif menu == "Dashboard":
            st.error("Access denied. Please log in.")

if __name__ == "__main__":
    main()