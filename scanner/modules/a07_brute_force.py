import requests
from bs4 import BeautifulSoup

from scanner.core.finding import Finding
from scanner.utils.dvwa import create_dvwa_session


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

        print(f"[A07] Testando credencial: '{password}' (Status HTTP: {response.status_code})")

        # Sessão perdida
        if "Login :: Damn Vulnerable Web Application" in response.text:
            return Finding(
                category="A07",
                name="Authentication Failures",
                test="Brute Force",
                status="error",
                severity="medium",
                evidence=(
                    "A sessão de autenticação foi encerrada ou perdida "
                    "durante a execução do teste."
                ),
                recommendation=(
                    "Verificar a estabilidade e a persistência da sessão "
                    "antes da execução de novos testes."
                )
            )

        # Evidência positiva de sucesso
        if "Welcome to the password protected area" in response.text:
            print(f"[A07] Credencial válida identificada com sucesso: '{password}'")

            return Finding(
                category="A07",
                name="Authentication Failures",
                test="Brute Force",
                status="detected",
                severity="medium",
                evidence=(
                    f"Uma credencial válida foi identificada com sucesso "
                    f"durante tentativas automatizadas de força bruta para o usuário '{username}'."
                ),
                recommendation=(
                    "Implementar mecanismos de proteção contra ataques de força bruta, "
                    "como limitação de taxa de requisições (rate limiting), bloqueio "
                    "temporário de contas após tentativas inválidas consecutivas e "
                    "autenticação multifator (MFA)."
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
            "Nenhuma das credenciais testadas foi aceita pela aplicação "
            "no conjunto de palavras (wordlist) utilizado."
        ),
        recommendation=(
            "Manter políticas rigorosas de senhas fortes e mecanismos ativos "
            "de proteção contra tentativas automatizadas."
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

        print(f"[A07] Testando proteção com credencial inválida: '{password}' (Status HTTP: {response.status_code})")

        # Rate limiting
        if response.status_code == 429:
            return Finding(
                category="A07",
                name="Authentication Failures",
                test="Brute Force Protection",
                status="not_detected",
                severity="medium",
                evidence=(
                    "A aplicação retornou HTTP 429 (Too Many Requests) após "
                    "múltiplas tentativas inválidas consecutivas, indicando a "
                    "presença de mecanismo de rate limiting."
                ),
                recommendation=(
                    "Manter e auditar periodicamente as regras e os limites "
                    "configurados para o rate limiting."
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
                    "A aplicação retornou HTTP 403 (Forbidden) durante as "
                    "tentativas consecutivas, indicando bloqueio temporário "
                    "ou permanente por política de segurança."
                ),
                recommendation=(
                    "Manter o mecanismo de bloqueio e monitorar incidentes "
                    "para evitar falsos positivos com usuários legítimos."
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
                f"Foram realizadas {len(invalid_passwords)} tentativas inválidas consecutivas "
                "e a aplicação continuou respondendo normalmente com HTTP 200, sem apresentar "
                "mecanismos observáveis de bloqueio, atraso progressivo ou limitação de taxa (rate limiting)."
            ),
            recommendation=(
                "Implementar controles defensivos contra tentativas automatizadas, "
                "tais como limitação de taxa de requisições (rate limiting), atraso progressivo "
                "(tarpitting), bloqueio temporário de conta/IP ou desafio CAPTCHA."
            )
        )

    return Finding(
        category="A07",
        name="Authentication Failures",
        test="Brute Force Protection",
        status="not_detected",
        severity="medium",
        evidence=(
            "O comportamento da aplicação variou durante as tentativas "
            "consecutivas, indicando provável mecanismo defensivo ativo."
        ),
        recommendation=(
            "Avaliar a eficácia das regras de proteção e manter o monitoramento "
            "ativo de requisições de autenticação."
        )
    )


def run_brute_force(
    base_url: str,
    username: str,
    passwords: list[str],
    session=None,
    **kwargs
):
    """
    Executa todos os testes relacionados ao A07.
    """

    brute_force_url = (
        f"{base_url}/vulnerabilities/brute/"
    )

    print("\n--- Executando Testes de Falhas de Autenticação (A07) ---")

    # ==========================================
    # 1. AUTENTICAÇÃO
    # ==========================================

    if session is None:
        session = create_dvwa_session(
            base_url=base_url,
            username=username,
            password="password"
        )
        print("[A07] Sessão autenticada criada com sucesso no DVWA.")
    else:
        print("[A07] Reutilizando sessão autenticada existente.")

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