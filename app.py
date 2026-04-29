from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3

app = Flask(__name__)
# Cheie secreta pentru sesiuni (in v1 este vulnerabila fiind hardcodata)
app.secret_key = '1234'

# Functie pentru conectarea la baza de date creata anterior
def get_db_connection():
    conn = sqlite3.connect('authx.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def home():
    return 'Pagina principala. Mergi la <a href="/register">Register</a> sau <a href="/login">Login</a>.'

# 3.1 Inregistrare utilizator (Vulnerabil: stocare in clar)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        role = 'ANALYST' # Rol implicit conform cerintei din proiect

        conn = get_db_connection()
        try:
            # VULNERABILITATE: Parola se salveaza direct in clar (Plain Text)
            # Nu exista nicio verificare pentru lungimea sau complexitatea parolei
            conn.execute('INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)',
                         (email, password, role))
            conn.commit()
            return 'Cont creat cu succes! <a href="/login">Mergi la Login</a>'
        except sqlite3.IntegrityError:
            return 'Eroare: Emailul exista deja!'
        finally:
            conn.close()
    return render_template('register.html')

# 3.2 Autentificare (Vulnerabil: User Enumeration)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        # Cautam utilizatorul in baza de date [cite: 19, 37]
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        # VULNERABILITATE: User Enumeration (mesaje de eroare diferite) 
        if user is None:
            # Mesaj specific care confirma ca email-ul nu exista 
            return "Eroare: Utilizatorul nu a fost gasit!" 
        
        # VULNERABILITATE: Verificare parola in clar (Plain Text) [cite: 11]
        if user['password_hash'] == password:
            # Autentificare reusita - Initializam sesiunea 
            session['user_id'] = user['id']
            session['email'] = user['email']
            session['role'] = user['role']
            
            # Audit & Logging: Inregistram accesul in baza de date [cite: 37, 80]
            # Nota: Asigura-te ca ai definit functia log_action inainte de asta
            log_action(user['id'], 'LOGIN', 'auth')
            
            # Redirectionare catre functionalitatea de business (Tickets) [cite: 19]
            return redirect(url_for('tickets'))
        else:
            # Mesaj specific care confirma ca email-ul e bun, dar parola e gresita 
            return "Eroare: Parola este incorecta pentru acest utilizator!"

    return render_template('login.html')
import datetime

# --- Functie auxiliara pentru Audit Logs ---
def log_action(user_id, action, resource, resource_id=None):
    conn = get_db_connection()
    conn.execute('INSERT INTO audit_logs (user_id, action, resource, resource_id, ip_address) VALUES (?, ?, ?, ?, ?)',
                 (user_id, action, resource, resource_id, request.remote_addr))
    conn.commit()
    conn.close()

# --- 3.3 Logout ---
@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    if user_id:
        log_action(user_id, 'LOGOUT', 'auth')
    session.clear()
    return redirect(url_for('login'))

# --- 3.4 Resetare parola (Vulnerabil: Token predictibil/simplu) ---
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        # In v1 trimitem un "token" care este doar email-ul in baza64 sau ceva predictibil
        # Aici doar redirectionam catre pagina de reset cu email-ul in URL (foarte nesigur)
        return f"Link-ul de resetare a fost trimis (simulat): /reset-password?user={email}"
    return 'Formular Forgot Password (v1)'

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    user_email = request.args.get('user')
    if request.method == 'POST':
        new_password = request.form['password']
        conn = get_db_connection()
        # Vulnerabil: Nu verificam token-ul, doar schimbam parola pentru email-ul din URL
        conn.execute('UPDATE users SET password_hash = ? WHERE email = ?', (new_password, user_email))
        conn.commit()
        conn.close()
        return "Parola a fost schimbata! <a href='/login'>Login</a>"
    return f"Reseteaza parola pentru: {user_email} <form method='POST'><input name='password' type='password'><button>Reset</button></form>"

# --- 3.5 Gestionare Business (Tickets + Search) ---
@app.route('/tickets', methods=['GET', 'POST'])
def tickets():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Adaugare Ticket
    if request.method == 'POST':
        title = request.form['title']
        desc = request.form['description']
        conn.execute('INSERT INTO tickets (title, description, owner_id, status) VALUES (?, ?, ?, ?)',
                     (title, desc, session['user_id'], 'OPEN'))
        conn.commit()
        log_action(session['user_id'], 'CREATE_TICKET', 'ticket')

    # Search - VULNERABIL la SQL Injection (cerinta pentru v1)
    query = request.args.get('search', '')
    if query:
        # Folosim concatenare in loc de parametrizare pentru a fi vulnerabil
        sql = f"SELECT * FROM tickets WHERE title LIKE '%{query}%'"
        all_tickets = conn.execute(sql).fetchall()
    else:
        all_tickets = conn.execute('SELECT * FROM tickets').fetchall()
    
    conn.close()
    return render_template('tickets.html', tickets=all_tickets)

if __name__ == '__main__':
    app.run(debug=True)