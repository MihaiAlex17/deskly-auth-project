import sqlite3

def init_db():
    # Conectarea la baza de date 
    conn = sqlite3.connect('authx.db')
    cursor = conn.cursor()

    # 1. Tabelul users 
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,           
            password_hash TEXT NOT NULL,          
            role TEXT CHECK(role IN ('ANALYST', 'MANAGER')) DEFAULT 'ANALYST',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
            locked BOOLEAN DEFAULT 0              
        )
    ''')

    # 2. Tabelul tickets 
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            title TEXT NOT NULL,                  
            description TEXT,                     
            severity TEXT CHECK(severity IN ('LOW', 'MED', 'HIGH')),
            status TEXT CHECK(status IN ('OPEN', 'IN PROGRESS', 'RESOLVED')), 
            owner_id INTEGER,                     
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
            FOREIGN KEY (owner_id) REFERENCES users (id)    
        )
    ''')

    # 3. Tabelul audit_logs 
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            user_id INTEGER,                      
            action TEXT,                          
            resource TEXT,                        
            resource_id TEXT,                    
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
            ip_address TEXT,                      
            FOREIGN KEY (user_id) REFERENCES users (id)    
        )
    ''')

    conn.commit()
    conn.close()
    print("Baza de date a fost initializata cu succes conform cerintelor.")

if __name__ == "__main__":
    init_db()