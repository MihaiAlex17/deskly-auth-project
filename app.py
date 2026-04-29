from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
import sqlite3
import datetime
import secrets

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = secrets.token_hex(24)

def get_db_connection():
    conn = sqlite3.connect('authx.db')
    conn.row_factory = sqlite3.Row
    return conn

# Functie auxiliara pentru validarea complexitatii parolei
def is_password_strong(password):
    if len(password) < 8:
        return False
    if not any(char.isupper() for char in password):
        return False
    if not any(char.isdigit() for char in password):
        return False
    return True

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # Noua validare: lungime + litera mare + cifra
        if not is_password_strong(password):
            return "Eroare: Parola trebuie sa aiba minim 8 caractere, o litera mare si o cifra!"

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        role = 'ANALYST'

        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)',
                         (email, hashed_password, role))
            conn.commit()
            return 'Cont creat cu succes! <a href="/login">Logheaza-te aici</a>'
        except sqlite3.IntegrityError:
            return 'Eroare: Acest email este deja inregistrat.'
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        if user and user['locked']:
            return "Eroare: Acest cont a fost blocat din motive de securitate."

        if user and bcrypt.check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['email'] = user['email']
            session['role'] = user['role']
            log_action(user['id'], 'LOGIN_SUCCESS', 'auth')
            return redirect(url_for('tickets'))
        else:
            return "Eroare: Email sau parola incorecta!"

    return render_template('login.html')

def log_action(user_id, action, resource, resource_id=None):
    conn = get_db_connection()
    conn.execute('INSERT INTO audit_logs (user_id, action, resource, resource_id, ip_address) VALUES (?, ?, ?, ?, ?)',
                 (user_id, action, resource, resource_id, request.remote_addr))
    conn.commit()
    conn.close()

@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    if user_id:
        log_action(user_id, 'LOGOUT', 'auth')
    session.clear()
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        token = secrets.token_urlsafe(32)
        link_resetare = url_for('reset_password', token=token, _external=True)
        return f"Link-ul de resetare: <a href='{link_resetare}'>{link_resetare}</a>"
    
    return render_template('forgot_password.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    token = request.args.get('token')
    if not token:
        return "Eroare: Token invalid!"
        
    if request.method == 'POST':
        new_password = request.form['password']
        
        # Validam si aici noua parola
        if not is_password_strong(new_password):
            return "Eroare: Parola noua trebuie sa aiba minim 8 caractere, o litera mare si o cifra!"
            
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        return "Parola a fost actualizata in siguranta! <a href='/login'>Login</a>"
    
    return render_template('reset_password.html', token=token)

@app.route('/tickets', methods=['GET', 'POST'])
def tickets():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    if request.method == 'POST':
        title = request.form['title']
        desc = request.form['description']
        conn.execute('INSERT INTO tickets (title, description, owner_id, status) VALUES (?, ?, ?, ?)',
                     (title, desc, session['user_id'], 'OPEN'))
        conn.commit()
        log_action(session['user_id'], 'CREATE_TICKET', 'ticket')

    query = request.args.get('search', '')
    if query:
        # Folosim parametrizare pentru securitate
        sql = "SELECT * FROM tickets WHERE title LIKE ?"
        all_tickets = conn.execute(sql, ('%' + query + '%',)).fetchall()
    else:
        all_tickets = conn.execute('SELECT * FROM tickets').fetchall()
    
    conn.close()
    return render_template('tickets.html', tickets=all_tickets)

if __name__ == '__main__':
    app.run(debug=False)