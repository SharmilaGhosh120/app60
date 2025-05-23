# -*- coding: utf-8 -*-
import streamlit as st
import pandas as pd
import sqlite3
from datetime import datetime, timedelta
import requests
import re
import os
import hashlib
import uuid
import logging
import csv
import time
from io import BytesIO
import pdfkit
from ratelimit import limits, sleep_and_retry

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# --- Rate Limiting Configuration ---
CALLS = 10  # Number of API calls allowed
PERIOD = 60  # Time period in seconds

# --- SQLite Database Setup ---
def init_db():
    db_path = os.path.join(os.getcwd(), 'kyra.db')
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    # Create users table with password_hash
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            name TEXT,
            role TEXT,
            password_hash TEXT
        )
    ''')
    
    # Check if password_hash column exists in users table and add it if missing
    c.execute("PRAGMA table_info(users)")
    columns = [info[1] for info in c.fetchall()]
    if 'password_hash' not in columns:
        c.execute('ALTER TABLE users ADD COLUMN password_hash TEXT')
    
    # --- Ensure projects table has correct schema ---
    c.execute("PRAGMA table_info(projects)")
    project_columns = [info[1] for info in c.fetchall()]
    required_project_columns = ['project_id', 'email', 'project_title', 'timestamp']
    if not all(col in project_columns for col in required_project_columns):
        logger.warning("Projects table schema incorrect or missing columns. Recreating table.")
        c.execute('DROP TABLE IF EXISTS projects')
        c.execute('''
            CREATE TABLE projects (
                project_id TEXT PRIMARY KEY,
                email TEXT,
                project_title TEXT,
                timestamp TEXT,
                FOREIGN KEY (email) REFERENCES users(email)
            )
        ''')
    else:
        # Create projects table if it doesn't exist
        c.execute('''
            CREATE TABLE IF NOT EXISTS projects (
                project_id TEXT PRIMARY KEY,
                email TEXT,
                project_title TEXT,
                timestamp TEXT,
                FOREIGN KEY (email) REFERENCES users(email)
            )
        ''')

    # Create queries table with query_id and feedback_rating
    c.execute('''
        CREATE TABLE IF NOT EXISTS queries (
            query_id TEXT PRIMARY KEY,
            email TEXT,
            name TEXT,
            project_title TEXT,
            question TEXT,
            response TEXT,
            timestamp TEXT,
            feedback_rating INTEGER,
            FOREIGN KEY (email) REFERENCES users(email)
        )
    ''')
    
    # Create student_project_map table
    c.execute('''
        CREATE TABLE IF NOT EXISTS student_project_map (
            student_id TEXT,
            project_id TEXT,
            timestamp TEXT,
            PRIMARY KEY (student_id, project_id),
            FOREIGN KEY (student_id) REFERENCES users(email),
            FOREIGN KEY (project_id) REFERENCES projects(project_id)
        )
    ''')
    
    # Clear and populate users table with all users
    c.execute('DELETE FROM users')  # Clear existing users to ensure correct data
    default_password_hash = hashlib.sha256('password'.encode()).hexdigest()
    bulk_password_hash = hashlib.sha256('default123'.encode()).hexdigest()
    all_users = [
        ('student123@college.edu', 'John Doe', 'student', default_password_hash),
        ('admin@college.edu', 'Jane Admin', 'admin', default_password_hash),
        ('student456@college.edu', 'Alice Smith', 'student', default_password_hash),
        ('newstudent1@college.edu', 'Emma Watson', 'student', bulk_password_hash),
        ('newstudent2@college.edu', 'James Brown', 'student', bulk_password_hash),
        ('newadmin1@college.edu', 'Sarah Admin', 'admin', bulk_password_hash)
    ]
    c.executemany('INSERT INTO users (email, name, role, password_hash) VALUES (?, ?, ?, ?)', all_users)
    
    conn.commit()
    conn.close()

# Initialize database
init_db()

# --- Authentication Functions ---
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_user(email, password):
    db_path = os.path.join(os.getcwd(), 'kyra.db')
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('SELECT password_hash, name, role FROM users WHERE email = ?', (email,))
    result = c.fetchone()
    conn.close()
    if not result:
        return None, "Email not found."
    input_hash = hash_password(password)
    logger.debug(f"Input password hash: {input_hash}")
    logger.debug(f"Stored password hash: {result[0]}")
    if result[0] == input_hash:
        return {"name": result[1], "role": result[2]}, None
    return None, "Incorrect password."

# --- Admin Password Reset ---
def reset_user_password(email, new_password):
    db_path = os.path.join(os.getcwd(), 'kyra.db')
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    password_hash = hash_password(new_password)
    c.execute('UPDATE users SET password_hash = ? WHERE email = ?', (password_hash, email))
    conn.commit()
    conn.close()

# --- API Health Check ---
@sleep_and_retry
@limits(calls=CALLS, period=PERIOD)
def is_api_alive():
    url = "http://kyra.kyras.in:8000/health"
    retries = 3
    for attempt in range(retries):
        try:
            r = requests.get(url, timeout=5)
            return r.status_code == 200
        except requests.exceptions.RequestException as e:
            logger.warning(f"API health check failed (attempt {attempt + 1}/{retries}): {str(e)}")
            if attempt < retries - 1:
                time.sleep(1)  # Wait before retrying
    return False

# --- Bulk Register Users from CSV ---
def bulk_register_users(csv_file_path):
    try:
        db_path = os.path.join(os.getcwd(), 'kyra.db')
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        with open(csv_file_path, 'r') as f:
            reader = csv.DictReader(f)
            required_columns = ['email', 'name', 'role']
            if not all(col in reader.fieldnames for col in required_columns):
                return False, "CSV must contain 'email', 'name', and 'role' columns."
            for row in reader:
                email = row['email']
                name = row['name']
                role = row['role']
                if not is_valid_email(email):
                    return False, f"Invalid email format: {email}"
                if role not in ['student', 'admin']:
                    return False, f"Invalid role for {email}: {role}"
                password = 'default123'  # Default password for bulk registration
                password_hash = hash_password(password)
                c.execute('INSERT OR IGNORE INTO users (email, name, role, password_hash) VALUES (?, ?, ?, ?)',
                          (email, name, role, password_hash))
        conn.commit()
        conn.close()
        return True, "Users registered successfully!"
    except Exception as e:
        return False, f"Error processing CSV: {str(e)}"

# --- Export Query Logs ---
def export_query_logs_to_csv():
    db_path = os.path.join(os.getcwd(), 'kyra.db')
    conn = sqlite3.connect(db_path)
    query_logs = pd.read_sql_query("SELECT email, name, project_title, question, response, timestamp, feedback_rating FROM queries", conn)
    conn.close()
    if not query_logs.empty:
        return query_logs.to_csv(index=False).encode('utf-8')
    return None

def export_query_logs_to_pdf():
    db_path = os.path.join(os.getcwd(), 'kyra.db')
    conn = sqlite3.connect(db_path)
    query_logs = pd.read_sql_query("SELECT email, name, project_title, question, response, timestamp, feedback_rating FROM queries", conn)
    conn.close()
    
    if not query_logs.empty:
        html_content = """
        <html>
        <head>
            <style>
                table { width: 100%; border-collapse: collapse; }
                th, td { border: 1px solid black; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
            <h2>Query Logs Report</h2>
            <table>
                <tr>
                    <th>Email</th>
                    <th>Name</th>
                    <th>Project Title</th>
                    <th>Question</th>
                    <th>Response</th>
                    <th>Timestamp</th>
                    <th>Feedback Rating</th>
                </tr>
        """
        for _, row in query_logs.iterrows():
            rating = row['feedback_rating'] if pd.notna(row['feedback_rating']) else "Not rated"
            html_content += f"""
                <tr>
                    <td>{row['email']}</td>
                    <td>{row['name']}</td>
                    <td>{row['project_title']}</td>
                    <td>{row['question']}</td>
                    <td>{row['response']}</td>
                    <td>{row['timestamp']}</td>
                    <td>{rating}</td>
                </tr>
            """
        html_content += """
            </table>
        </body>
        </html>
        """
        try:
            pdf = pdfkit.from_string(html_content, False)
            return pdf
        except Exception as e:
            logger.error(f"Error generating PDF: {str(e)}")
            return None
    return None

# --- Streamlit frontend ---
st.set_page_config(
    page_title="Ask Ky’ra",
    page_icon="https://raw.githubusercontent.com/SharmilaGhosh120/app16/main/WhatsApp%20Image%202025-05-20%20at%2015.17.59.jpeg",
    layout="centered"
)

# Custom styling
st.markdown(
    """
    <style>
    .main {
        background-color: #ffffff;
        padding: 20px;
        border-radius: 10px;
        font-family: 'Roboto', sans-serif;
    }
    .stTextInput > div > input {
        border: 1px solid #ccc;
        border-radius: 5px;
        font-family: 'Roboto', sans-serif;
    }
    .stTextArea > div > textarea {
        border: 1px solid #ccc;
        border-radius: 5px;
        font-family: 'Roboto', sans-serif;
    }
    .submit-button {
        display: flex;
        justify-content: center;
    }
    .submit-button .stButton > button {
        background-color: #4fb8ac;
        color: white;
        font-size: 18px;
        padding: 10px 20px;
        border-radius: 8px;
        width: 200px;
        font-family: 'Roboto', sans-serif;
    }
    .history-entry {
        padding: 15px;
        border: 1px solid #e0e0e0;
        border-radius: 12px;
        background-color: #ffffff;
        margin-bottom: 10px;
        box-shadow: 1px 1px 3px #ccc;
        font-family: 'Roboto', sans-serif;
        word-wrap: break-word;
        overflow-wrap: break-word;
        max-width: 100%;
    }
    .chat-container {
        max-height: 400px;
        overflow-y: auto;
        padding: 10px;
        border: 1px solid #e0e0e0;
        border-radius: 12px;
        background-color: #f9f9f9;
    }
    .chat-footer {
        text-align: center;
        font-family: 'Roboto', sans-serif;
        color: #4fb8ac;
        margin-top: 20px;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# Header with Ky’ra logo
try:
    logo_url = "https://raw.githubusercontent.com/SharmilaGhosh120/app16/main/WhatsApp%20Image%202025-05-20%20at%2015.17.59.jpeg"
    st.image(logo_url, width=80, caption="Ky’ra Logo", use_column_width=True, output_format="JPEG")
except Exception as e:
    st.warning("Unable to load Ky’ra logo. Please check your internet connection or try again later.")

# Initialize session state
if "email" not in st.session_state:
    st.session_state.email = ""
if "name" not in st.session_state:
    st.session_state.name = ""
if "role" not in st.session_state:
    st.session_state.role = ""
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []
if "page" not in st.session_state:
    st.session_state.page = 1
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

# Logout Functionality
if st.session_state.authenticated:
    if st.button("Logout"):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.success("You have been logged out.")
        st.rerun()

# Login interface
if not st.session_state.authenticated:
    st.subheader("Login to Ask Ky’ra")
    email_input = st.text_input("Email", placeholder="student123@college.edu")
    password_input = st.text_input("Password", type="password", placeholder="Enter your password")
    if st.button("Login"):
        if email_input and password_input:
            user_info, error = verify_user(email_input, password_input)
            if user_info:
                st.session_state.authenticated = True
                st.session_state.email = email_input
                st.session_state.name = user_info["name"]
                st.session_state.role = user_info["role"]
                st.success("Login successful!")
                st.rerun()
            else:
                st.error(error)
        else:
            st.error("Please enter both email and password.")
else:
    # Input fields for updating user details
    st.subheader("Your Details")
    email_input = st.text_input("Student Email", value=st.session_state.email, placeholder="student123@college.edu", disabled=True)
    name_input = st.text_input("Your Name", value=st.session_state.name, placeholder="Enter your name")
    password_input = st.text_input("New Password (optional)", type="password", placeholder="Set or update password")
    
    # Function to validate email
    def is_valid_email(email):
        pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        return re.match(pattern, email) is not None

    # Save or update user details
    def save_user(email, name, password=None):
        db_path = os.path.join(os.getcwd(), 'kyra.db')
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        role = "admin" if "admin" in email.lower() else "student"
        password_hash = hash_password(password) if password else None
        if password:
            c.execute('INSERT OR REPLACE INTO users (email, name, role, password_hash) VALUES (?, ?, ?, ?)',
                     (email, name, role, password_hash))
        else:
            c.execute('INSERT OR REPLACE INTO users (email, name, role) VALUES (?, ?, ?)',
                     (email, name, role))
        conn.commit()
        conn.close()

    # Update user details
    if st.button("Update Details"):
        if name_input:
            save_user(st.session_state.email, name_input, password_input)
            st.session_state.name = name_input
            st.success("Details updated successfully!")
        else:
            st.error("Please enter your name.")

    # Register New User Section (Admin Only)
    if st.session_state.role == "admin":
        st.subheader("Register New User")
        new_email = st.text_input("New User Email", placeholder="newstudent@college.edu")
        new_name = st.text_input("New User Name", placeholder="Enter new user name")
        new_role = st.selectbox("Role", ["student", "admin"])
        new_password = st.text_input("New User Password", type="password", placeholder="Set password")
        if st.button("Register User"):
            if new_email and new_name and new_password:
                if is_valid_email(new_email):
                    save_user(new_email, new_name, new_password)
                    st.success(f"User {new_name} ({new_email}) registered successfully!")
                else:
                    st.error("Please enter a valid email address.")
            else:
                st.error("Please fill in all fields for the new user.")
        
        # Admin Password Reset Section
        st.subheader("Reset User Password")
        reset_email = st.text_input("User Email to Reset", placeholder="Enter user email")
        reset_password = st.text_input("New Password", type="password", placeholder="Enter new password")
        if st.button("Reset Password"):
            if reset_email and reset_password:
                if is_valid_email(reset_email):
                    reset_user_password(reset_email, reset_password)
                    st.success(f"Password reset successfully for {reset_email}!")
                else:
                    st.error("Please enter a valid email address.")
            else:
                st.error("Please provide both email and new password.")
        
        # Bulk Register Users from CSV
        st.subheader("Bulk Register Users")
        uploaded_user_file = st.file_uploader("Upload a CSV file (email,name,role)", type=["csv"])
        if uploaded_user_file is not None:
            try:
                # Save uploaded file temporarily
                temp_file_path = os.path.join(os.getcwd(), "temp_users.csv")
                with open(temp_file_path, "wb") as f:
                    f.write(uploaded_user_file.getbuffer())
                success, message = bulk_register_users(temp_file_path)
                os.remove(temp_file_path)  # Clean up temporary file
                if success:
                    st.success(message)
                else:
                    st.error(message)
            except Exception as e:
                st.error(f"Error processing user CSV: {str(e)}")

    # Format timestamp
    def format_timestamp(timestamp_str):
        try:
            dt = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            return dt.strftime("%B %d, %Y %I:%M %p")
        except:
            return timestamp_str

    # Role-based dashboards
    def show_admin_dashboard(name):
        st.markdown(f"<h1 style='text-align: center; color: #4fb8ac; font-family: \"Roboto\", sans-serif;'>🎓 Welcome College Admin, {name}!</h1>", unsafe_allow_html=True)
        st.markdown("<p style='text-align: center; font-family: \"Roboto\", sans-serif;'>Manage student mappings, projects, and reports with Ky’ra.</p>", unsafe_allow_html=True)
        
        # Admin Dashboard: Student Mapping Upload
        st.subheader("Upload Student Mapping")
        uploaded_file = st.file_uploader("Upload a CSV file (student_id,project_title)", type=["csv"], key="mapping_uploader")
        if uploaded_file is not None:
            try:
                mapping_df = pd.read_csv(uploaded_file)
                required_columns = ["student_id", "project_title"]
                if not all(col in mapping_df.columns for col in required_columns):
                    st.error("CSV must contain 'student_id' and 'project_title' columns.")
                elif mapping_df.empty:
                    st.error("Uploaded CSV is empty.")
                elif mapping_df['student_id'].isnull().any() or mapping_df['project_title'].isnull().any():
                    st.error("CSV contains missing values in 'student_id' or 'project_title'.")
                else:
                    st.markdown("**Preview of Uploaded Student Mapping:**")
                    st.dataframe(mapping_df)
                    if st.button("Save Mapping"):
                        db_path = os.path.join(os.getcwd(), 'kyra.db')
                        conn = sqlite3.connect(db_path)
                        c = conn.cursor()
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        for _, row in mapping_df.iterrows():
                            if not is_valid_email(row['student_id']):
                                st.error(f"Invalid email format: {row['student_id']}")
                                conn.close()
                                return
                            project_id = str(uuid.uuid4())
                            c.execute('INSERT INTO projects (project_id, email, project_title, timestamp) VALUES (?, ?, ?, ?)',
                                    (project_id, row['student_id'], row['project_title'], timestamp))
                            c.execute('INSERT INTO student_project_map (student_id, project_id, timestamp) VALUES (?, ?, ?)',
                                    (row['student_id'], project_id, timestamp))
                        conn.commit()
                        conn.close()
                        st.success("Student mapping saved successfully!")
            except pd.errors.EmptyDataError:
                st.error("Uploaded CSV is empty or improperly formatted.")
            except pd.errors.ParserError:
                st.error("Error parsing CSV. Please ensure it is properly formatted.")
            except Exception as e:
                st.error(f"Error processing file: {str(e)}")
        
        # Admin: Export Query Logs
        st.subheader("Export Query Logs")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Export to CSV"):
                csv_data = export_query_logs_to_csv()
                if csv_data:
                    st.download_button(
                        label="Download Query Logs CSV",
                        data=csv_data,
                        file_name=f"query_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv"
                    )
                else:
                    st.error("No query logs available to export.")
        with col2:
            if st.button("Export to PDF"):
                pdf_data = export_query_logs_to_pdf()
                if pdf_data:
                    st.download_button(
                        label="Download Query Logs PDF",
                        data=pdf_data,
                        file_name=f"query_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                        mime="application/pdf"
                    )
                else:
                    st.error("No query logs available to export.")
        
        # Admin: View project-wise query logs
        st.subheader("Project-Wise Query Logs")
        db_path = os.path.join(os.getcwd(), 'kyra.db')
        conn = sqlite3.connect(db_path)
        query_logs = pd.read_sql_query("SELECT email, name, project_title, question, response, timestamp, feedback_rating FROM queries", conn)
        conn.close()
        if not query_logs.empty:
            for project_title in query_logs['project_title'].unique():
                with st.expander(f"Query Logs for Project: {project_title}"):
                    project_logs = query_logs[query_logs['project_title'] == project_title]
                    for _, row in project_logs.iterrows():
                        rating = row['feedback_rating'] if pd.notna(row['feedback_rating']) else "Not rated"
                        st.markdown(
                            f"<div class='history-entry'><strong>{row['name']} ({row['email']}) asked:</strong> {row['question']} <i>(submitted at {format_timestamp(row['timestamp'])})</i><br><strong>Ky’ra replied:</strong> {row['response']}<br><strong>Feedback Rating:</strong> {rating}</div>",
                            unsafe_allow_html=True
                        )
                        st.markdown("---")
        else:
            st.markdown("<p style='font-family: \"Roboto\", sans-serif;'>No query logs available.</p>", unsafe_allow_html=True)

    def show_student_dashboard(name):
        st.markdown(f"<h1 style='text-align: center; color: #4fb8ac; font-family: \"Roboto\", sans-serif;'>👋 Welcome, {name}!</h1>", unsafe_allow_html=True)
        st.markdown("<p style='text-align: center; font-family: \"Roboto\", sans-serif;'>Ask Ky’ra anything about resumes, interviews, or project help - I’ll guide you step-by-step!</p>", unsafe_allow_html=True)
        
        # Student Dashboard: Project Assignment Submission
        st.subheader("Submit Your Project Title")
        project_title = st.text_input("Enter your project title:", placeholder="E.g., AI-based Chatbot for Internship Assistance")
        if st.button("Submit Project"):
            if project_title:
                db_path = os.path.join(os.getcwd(), 'kyra.db')
                conn = sqlite3.connect(db_path)
                c = conn.cursor()
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                project_id = str(uuid.uuid4())
                try:
                    c.execute('INSERT INTO projects (project_id, email, project_title, timestamp) VALUES (?, ?, ?, ?)',
                            (project_id, st.session_state.email, project_title, timestamp))
                    c.execute('INSERT INTO student_project_map (student_id, project_id, timestamp) VALUES (?, ?, ?)',
                            (st.session_state.email, project_id, timestamp))
                    conn.commit()
                    st.success("Project title submitted successfully!")
                except sqlite3.Error as e:
                    st.error(f"Database error during project submission: {str(e)}")
                finally:
                    conn.close()
            else:
                st.error("Please enter a project title.")

    # Show dashboard based on role
    if st.session_state.role == "admin":
        show_admin_dashboard(st.session_state.name)
    else:
        show_student_dashboard(st.session_state.name)

    # Query Section (for both roles)
    st.subheader("Ask Ky’ra a Question")
    
    sample_questions = [
        "How do I write my internship resume?",
        "What are the best final-year projects in AI?",
        "How can I prepare for my upcoming interview?",
        "What skills should I learn for a career in cybersecurity?"
    ]
    selected_question = st.selectbox("Choose a sample question or type your own:", sample_questions + ["Custom question..."])
    query_text = st.text_area("Your Question", value=selected_question if selected_question != "Custom question..." else "", height=150, placeholder="E.g., How can I prepare for my internship interview?")
    feedback_rating = st.slider("Rate the response (optional, after receiving response)", min_value=1, max_value=5, value=3, step=1, disabled=True)

    # Function to call Ky’ra's backend API with rate limiting
    @sleep_and_retry
    @limits(calls=CALLS, period=PERIOD)
    def kyra_response(email, query):
        api_url = "http://kyra.kyras.in:8000/student-query"
        payload = {"student_id": email.strip(), "query": query.strip()}
        retries = 3
        for attempt in range(retries):
            try:
                response = requests.post(api_url, params=payload, timeout=10)
                if response.status_code == 200:
                    return response.json().get("response", "No response from Ky’ra.")
                else:
                    logger.warning(f"API query failed (attempt {attempt + 1}/{retries}): {response.status_code} - {response.text}")
                    if attempt < retries - 1:
                        time.sleep(1)
            except requests.exceptions.RequestException as e:
                logger.warning(f"API query failed (attempt {attempt + 1}/{retries}): {str(e)}")
                if attempt < retries - 1:
                    time.sleep(1)
        st.error("Unable to connect to Ky’ra’s API after multiple attempts. Please try again later.")
        return "Error: API unavailable. Please try again later."

    # Function to save queries to SQLite
    def save_query(email, name, project_title, question, response, timestamp, feedback_rating=None):
        db_path = os.path.join(os.getcwd(), 'kyra.db')
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        query_id = str(uuid.uuid4())
        c.execute('SELECT * FROM queries WHERE email = ? AND question = ? AND timestamp = ?', (email, question, timestamp))
        if not c.fetchone():
            c.execute('INSERT INTO queries (query_id, email, name, project_title, question, response, timestamp, feedback_rating) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                     (query_id, email, name, project_title, question, response, timestamp, feedback_rating))
            conn.commit()
        conn.close()

    # Submit button logic for queries
    st.markdown('<div class="submit-button">', unsafe_allow_html=True)
    if st.button("Submit", type="primary"):
        if not query_text:
            st.error("Please enter a query.")
        else:
            try:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                db_path = os.path.join(os.getcwd(), 'kyra.db')
                conn = sqlite3.connect(db_path)
                c = conn.cursor()
                c.execute('SELECT project_title FROM projects WHERE email = ? ORDER BY timestamp DESC LIMIT 1', (st.session_state.email,))
                result = c.fetchone()
                project_title = result[0] if result else "No Project Assigned"
                conn.close()
                
                response = kyra_response(st.session_state.email, query_text)
                save_query(st.session_state.email, st.session_state.name, project_title, query_text, response, timestamp)
                st.session_state.chat_history.append({
                    "email": st.session_state.email,
                    "name": st.session_state.name,
                    "query": query_text,
                    "response": response,
                    "timestamp": timestamp
                })
                st.success("Thank you! Ky’ra has received your question and is preparing your guidance.")
                with st.expander("🧠 Ky’ra’s Response", expanded=True):
                    st.markdown(
                        f"<div class='history-entry'><strong>Ky’ra’s Response:</strong><br>{response}</div>",
                        unsafe_allow_html=True
                    )
                    feedback_rating = st.slider("Rate this response", min_value=1, max_value=5, value=3, step=1, key=f"rating_{timestamp}")
                    if st.button("Submit Rating", key=f"submit_rating_{timestamp}"):
                        db_path = os.path.join(os.getcwd(), 'kyra.db')
                        conn = sqlite3.connect(db_path)
                        c = conn.cursor()
                        c.execute('UPDATE queries SET feedback_rating = ? WHERE email = ? AND timestamp = ?', 
                                 (feedback_rating, st.session_state.email, timestamp))
                        conn.commit()
                        conn.close()
                        st.success("Feedback rating submitted!")
            except Exception as e:
                st.error(f"Failed to process query: {str(e)}")
    st.markdown('</div>', unsafe_allow_html=True)

    # Display paginated query history
    st.markdown("**🧾 Your Query History:**")
    db_path = os.path.join(os.getcwd(), 'kyra.db')
    conn = sqlite3.connect(db_path)
    user_df = pd.read_sql_query("SELECT name, question, response, timestamp, feedback_rating FROM queries WHERE email = ? ORDER BY timestamp DESC", 
                               conn, params=(st.session_state.email,))
    conn.close()
    
    if not user_df.empty:
        user_df = user_df.drop_duplicates(subset=['question', 'timestamp'])
        items_per_page = 5
        total_pages = (len(user_df) + items_per_page - 1) // items_per_page
        st.session_state.page = max(1, min(st.session_state.page, total_pages))
        
        start_idx = (st.session_state.page - 1) * items_per_page
        end_idx = start_idx + items_per_page
        paginated_df = user_df.iloc[start_idx:end_idx]
        
        st.markdown('<div class="chat-container">', unsafe_allow_html=True)
        for idx, row in paginated_df.iterrows():
            response_text = row['response'] if pd.notna(row['response']) else "No response available."
            rating = row['feedback_rating'] if pd.notna(row['feedback_rating']) else "Not rated"
            with st.expander(f"Question from {format_timestamp(row['timestamp'])}"):
                st.markdown(
                    f"<div class='history-entry'><strong>You asked:</strong> {row['question']} <i>(submitted at {format_timestamp(row['timestamp'])})</i><br><strong>Ky’ra replied:</strong> {response_text}<br><strong>Feedback Rating:</strong> {rating}</div>",
                    unsafe_allow_html=True
                )
                st.markdown("---")
        st.markdown('</div>', unsafe_allow_html=True)
        
        # Pagination controls
        col1, col2, col3 = st.columns([1, 2, 1])
        with col1:
            if st.button("Previous", disabled=st.session_state.page == 1):
                st.session_state.page -= 1
        with col3:
            if st.button("Next", disabled=st.session_state.page == total_pages):
                st.session_state.page += 1
        with col2:
            st.write(f"Page {st.session_state.page} of {total_pages}")
    else:
        st.markdown("<p style='font-family: \"Roboto\", sans-serif;'>No query history yet. Ask Ky’ra a question to get started!</p>", unsafe_allow_html=True)
    st.markdown("<br>", unsafe_allow_html=True)

    # Display project submissions (for students)
    if st.session_state.role != "admin":
        st.subheader("Your Submitted Projects")
        db_path = os.path.join(os.getcwd(), 'kyra.db')
        conn = sqlite3.connect(db_path)
        user_projects = pd.read_sql_query("SELECT project_title, timestamp FROM projects WHERE email = ? ORDER BY timestamp DESC", 
                                        conn, params=(st.session_state.email,))
        conn.close()
        if not user_projects.empty:
            st.markdown('<div class="chat-container">', unsafe_allow_html=True)
            for idx, row in user_projects.iterrows():
                st.markdown(
                    f"<div class='history-entry'><strong>Project Title:</strong> {row['project_title']} <i>(submitted at {format_timestamp(row['timestamp'])})</i></div>",
                    unsafe_allow_html=True
                )
                st.markdown("---")
            st.markdown('</div>', unsafe_allow_html=True)
        else:
            st.markdown("<p style='font-family: \"Roboto\", sans-serif;'>No projects submitted yet.</p>", unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)

# Footer
st.markdown(
    "<p class='chat-footer'>Ky’ra is here whenever you need. Ask freely. Grow boldly.</p>",
    unsafe_allow_html=True
)

# Storage notice
st.markdown("Your query history and project submissions are securely stored to help Ky’ra guide you better next time.", unsafe_allow_html=True)