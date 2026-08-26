import requests
from bs4 import BeautifulSoup


def create_dvwa_session(
    base_url: str,
    username: str = "admin",
    password: str = "password",
    security_level: str = "low"
) -> requests.Session:
    """
    Cria e autentica uma sessão HTTP no DVWA, configurando o nível de segurança.
    
    :param base_url: URL base do DVWA (ex: 'http://192.168.100.165')
    :param username: Nome de usuário para autenticação
    :param password: Senha para autenticação
    :param security_level: Nível de segurança do DVWA ('low', 'medium', 'high', 'impossible')
    :return: requests.Session autenticada
    """
    session = requests.Session()
    login_url = f"{base_url}/login.php"

    try:
        response = session.get(login_url, timeout=10)
    except requests.RequestException as e:
        raise RuntimeError(f"Erro de conexão ao tentar acessar o DVWA em {login_url}: {e}")

    if response.status_code != 200:
        raise RuntimeError(
            f"Não foi possível acessar a página de login do DVWA. "
            f"Status HTTP: {response.status_code}"
        )

    soup = BeautifulSoup(response.text, "html.parser")
    token_input = soup.find("input", {"name": "user_token"})

    if token_input is None:
        raise RuntimeError("Token CSRF 'user_token' não encontrado na página de login.")

    user_token = token_input.get("value")

    data = {
        "username": username,
        "password": password,
        "Login": "Login",
        "user_token": user_token
    }

    try:
        login_response = session.post(login_url, data=data, timeout=10)
    except requests.RequestException as e:
        raise RuntimeError(f"Erro ao enviar requisição de autenticação: {e}")

    if "You have logged in as" not in login_response.text:
        raise RuntimeError(
            "Falha na autenticação no DVWA. Verifique as credenciais fornecidas."
        )

    # Configura o nível de segurança do DVWA nos cookies da sessão
    session.cookies.set("security", security_level)

    return session
