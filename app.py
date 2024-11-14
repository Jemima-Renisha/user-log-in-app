from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ff4d7c4bc92cebc7b40c635b91568920'  # Inserted secret key

# Database setup function
def init_db():
    conn = sqlite3.connect('user_data.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL,
                        email TEXT NOT NULL UNIQUE)''')
    conn.commit()
    conn.close()

# Initialize the database
init_db()

# Route for the home page (redirects to login)
@app.route('/')
def home():
    return redirect(url_for('login'))

# Route for the login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Connect to the database and check credentials
        conn = sqlite3.connect('user_data.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):  # user[2] is the password hash in the database
            session['username'] = user[1]  # Store username in session
            flash("Login successful!", "success")
            return redirect(url_for('welcome'))
        else:
            flash("Invalid username or password", "danger")
    
    return render_template('login.html')

# Route for the registration page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        # Hash the password using the correct method
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        # Connect to the database and insert new user
        try:
            conn = sqlite3.connect('user_data.db')
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", 
                           (username, hashed_password, email))
            conn.commit()
            conn.close()
            flash("Registration successful! You can now log in.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username or email already exists", "danger")
    
    return render_template('registration.html')

# Route for the welcome page (only accessible after login)
@app.route('/welcome')
def welcome():
    if 'username' in session:
        return render_template('welcome.html', name=session['username'], msg="Login Successful")
    else:
        flash("Please log in to access this page", "danger")
        return redirect(url_for('login'))

# Route for logging out
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash("You have been logged out", "info")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
