import requests
from bs4 import BeautifulSoup

from scanner.core.finding import Finding


def login_dvwa(base_url: str, username: str, password: str):
    """
    Cria uma sessão autenticada no DVWA.
    """

    session = requests.Session()

    login_url = f"{base_url}/login.php"

    response = session.get(
        login_url,
        timeout=10
    )

    if response.status_code != 200:
        raise RuntimeError(
            f"Não foi possível acessar o login do DVWA. "
            f"Status HTTP: {response.status_code}"
        )

    soup = BeautifulSoup(response.text, "html.parser")

    token = soup.find(
        "input",
        {"name": "user_token"}
    )

    if token is None:
        raise RuntimeError(
            "Token CSRF 'user_token' não encontrado."
        )

    user_token = token.get("value")

    data = {
        "username": username,
        "password": password,
        "Login": "Login",
        "user_token": user_token
    }

    login_response = session.post(
        login_url,
        data=data,
        timeout=10
    )

    if "You have logged in as" not in login_response.text:
        raise RuntimeError(
            "Não foi possível autenticar no DVWA."
        )

    return session


def test_brute_force(
    session,
    brute_force_url: str,
    username: str,
    passwords: list[str]
):
    """
    Testa um conjunto controlado de credenciais.
    """

    for password in passwords:

        params = {
            "username": username,
            "password": password,
            "Login": "Login"
        }

        response = session.get(
            brute_force_url,
            params=params,
            timeout=10
        )

        print(f"\nSenha testada: {password}")
        print(f"Status HTTP: {response.status_code}")

        # Sessão perdida
        if "Login :: Damn Vulnerable Web Application" in response.text:
            return Finding(
                category="A07",
                name="Authentication Failures",
                test="Brute Force",
                status="error",
                severity="medium",
                evidence=(
                    "A sessão de autenticação foi perdida "
                    "durante a execução do teste."
                ),
                recommendation=(
                    "Verificar o gerenciamento da sessão "
                    "antes da execução dos testes."
                )
            )

        # Evidência positiva de sucesso
        if "Welcome to the password protected area" in response.text:

            print("Possível credencial válida encontrada.")

            return Finding(
                category="A07",
                name="Authentication Failures",
                test="Brute Force",
                status="detected",
                severity="medium",
                evidence=(
                    "Uma credencial válida foi identificada "
                    "durante tentativas automatizadas."
                ),
                recommendation=(
                    "Implementar mecanismos de proteção contra "
                    "tentativas repetidas de autenticação, como "
                    "rate limiting e bloqueio temporário."
                )
            )

    # Nenhuma credencial foi encontrada
    return Finding(
        category="A07",
        name="Authentication Failures",
        test="Brute Force",
        status="not_detected",
        severity="medium",
        evidence=(
            "Nenhuma das credenciais utilizadas no conjunto "
            "de teste foi aceita pela aplicação."
        ),
        recommendation=(
            "Manter mecanismos de proteção contra tentativas "
            "automatizadas de autenticação."
        )
    )


def test_rate_limiting(
    session,
    brute_force_url: str,
    username: str,
    invalid_passwords: list[str]
):
    """
    Testa se a aplicação apresenta sinais de bloqueio
    ou limitação após tentativas inválidas consecutivas.
    """

    responses = []

    for password in invalid_passwords:

        params = {
            "username": username,
            "password": password,
            "Login": "Login"
        }

        response = session.get(
            brute_force_url,
            params=params,
            timeout=10
        )

        responses.append(response)

        print(f"\nTeste de proteção: {password}")
        print(f"Status HTTP: {response.status_code}")

        # Rate limiting
        if response.status_code == 429:
            return Finding(
                category="A07",
                name="Authentication Failures",
                test="Brute Force Protection",
                status="not_detected",
                severity="medium",
                evidence=(
                    "A aplicação retornou HTTP 429 após "
                    "múltiplas tentativas inválidas, indicando "
                    "um mecanismo de rate limiting."
                ),
                recommendation=(
                    "Manter e monitorar o mecanismo de "
                    "limitação de tentativas."
                )
            )

        # Possível bloqueio
        if response.status_code == 403:
            return Finding(
                category="A07",
                name="Authentication Failures",
                test="Brute Force Protection",
                status="not_detected",
                severity="medium",
                evidence=(
                    "A aplicação retornou HTTP 403 durante "
                    "as tentativas consecutivas, indicando "
                    "possível mecanismo de bloqueio."
                ),
                recommendation=(
                    "Manter o mecanismo de bloqueio e "
                    "monitorar tentativas suspeitas."
                )
            )

    status_codes = [
        response.status_code
        for response in responses
    ]

    # Todas as tentativas continuaram sendo aceitas normalmente
    if len(set(status_codes)) == 1 and status_codes[0] == 200:
        return Finding(
            category="A07",
            name="Authentication Failures",
            test="Brute Force Protection",
            status="detected",
            severity="medium",
            evidence=(
                f"Foram realizadas {len(invalid_passwords)} "
                "tentativas inválidas consecutivas e a aplicação "
                "continuou respondendo normalmente, sem apresentar "
                "sinais observáveis de bloqueio ou rate limiting."
            ),
            recommendation=(
                "Implementar rate limiting, bloqueio temporário "
                "ou outro mecanismo de proteção contra tentativas "
                "automatizadas de autenticação."
            )
        )

    return Finding(
        category="A07",
        name="Authentication Failures",
        test="Brute Force Protection",
        status="not_detected",
        severity="medium",
        evidence=(
            "O comportamento da aplicação mudou durante "
            "as tentativas consecutivas, indicando possível "
            "mecanismo de proteção."
        ),
        recommendation=(
            "Avaliar e manter os mecanismos de proteção "
            "contra tentativas automatizadas."
        )
    )


def run_brute_force(
    base_url: str,
    username: str,
    passwords: list[str]
):
    """
    Executa todos os testes relacionados ao A07.
    """

    brute_force_url = (
        f"{base_url}/vulnerabilities/brute/"
    )

    # ==========================================
    # 1. AUTENTICAÇÃO
    # ==========================================

    session = login_dvwa(
        base_url=base_url,
        username=username,
        password="password"
    )

    print("Sessão autenticada com sucesso.")

    # ==========================================
    # 2. TESTE DE BRUTE FORCE
    # ==========================================

    brute_force_finding = test_brute_force(
        session=session,
        brute_force_url=brute_force_url,
        username=username,
        passwords=passwords
    )

    # ==========================================
    # 3. TESTE DE PROTEÇÃO
    # ==========================================

    invalid_passwords = [
        "invalid_test_001",
        "invalid_test_002",
        "invalid_test_003",
        "invalid_test_004",
        "invalid_test_005"
    ]

    protection_finding = test_rate_limiting(
        session=session,
        brute_force_url=brute_force_url,
        username=username,
        invalid_passwords=invalid_passwords
    )

    # ==========================================
    # 4. RETORNA TODOS OS RESULTADOS
    # ==========================================

    return [
        brute_force_finding,
        protection_finding
    ]