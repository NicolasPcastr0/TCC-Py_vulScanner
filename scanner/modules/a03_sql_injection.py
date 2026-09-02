import re
import requests
from bs4 import BeautifulSoup

from scanner.core.finding import Finding
from scanner.utils.dvwa import create_dvwa_session


# Assinaturas comuns de erros de banco de dados (SGBDs variados)
SQL_ERROR_SIGNATURES = [
    # MySQL / MariaDB
    re.compile(r"you have an error in your sql syntax", re.IGNORECASE),
    re.compile(r"warning:\s+mysqli?_", re.IGNORECASE),
    re.compile(r"check the manual that corresponds to your (mariadb|mysql) server", re.IGNORECASE),
    re.compile(r"valid mysql result", re.IGNORECASE),
    # PostgreSQL
    re.compile(r"postgresql.*error", re.IGNORECASE),
    re.compile(r"warning:\s+pg_", re.IGNORECASE),
    # SQLite
    re.compile(r"sqlite3::sqlexception", re.IGNORECASE),
    re.compile(r"unrecognized token", re.IGNORECASE),
    # SQL Server
    re.compile(r"unclosed quotation mark after the character string", re.IGNORECASE),
    # Genérico / ODBC
    re.compile(r"syntax error in string in query", re.IGNORECASE),
]


def _send_sqli_probe(session: requests.Session, sqli_url: str, payload: str) -> requests.Response:
    """
    Envia o payload de teste testando tanto requisições GET quanto POST
    para suportar diferentes níveis de segurança do DVWA (Low e Medium).
    """
    params = {"id": payload, "Submit": "Submit"}
    
    # 1. Tenta via GET (padrão Low)
    try:
        resp_get = session.get(sqli_url, params=params, timeout=10)
        # Se encontrou erro SQL ou múltiplos registros via GET, retorna
        for sig in SQL_ERROR_SIGNATURES:
            if sig.search(resp_get.text):
                return resp_get
        if "First name:" in resp_get.text or "<pre>" in resp_get.text:
            return resp_get
    except requests.RequestException:
        pass

    # 2. Tenta via POST (padrão Medium)
    return session.post(sqli_url, data=params, timeout=10)


def test_error_based_sqli(
    session: requests.Session,
    sqli_url: str
) -> Finding:
    """
    Testa se a aplicação é vulnerável a SQL Injection baseado em erros (Error-based).
    Injeta caracteres de escape sintático e analisa se mensagens de erro do SGBD vazam na resposta.
    """
    payloads = ["'", "1'", "1' OR '1'='1", "1 OR 1=1", "admin'--"]

    for payload in payloads:
        try:
            response = _send_sqli_probe(session, sqli_url, payload)
        except requests.RequestException as e:
            return Finding(
                category="A03",
                name="Injection",
                test="SQL Injection (Error-based)",
                status="error",
                severity="high",
                evidence=f"Falha de comunicação durante o teste: {e}",
                recommendation="Verificar a conectividade e disponibilidade da aplicação alvo."
            )

        # Inspeciona a resposta procurando assinaturas de erro de SGBD
        for signature in SQL_ERROR_SIGNATURES:
            match = signature.search(response.text)
            if match:
                # Extrai um trecho contextual ao redor da mensagem de erro
                start = max(0, match.start() - 30)
                end = min(len(response.text), match.end() + 70)
                snippet = response.text[start:end].replace("\n", " ").strip()

                print(f"[A03] Erro de sintaxe SQL detectado com o payload: {payload}")

                return Finding(
                    category="A03",
                    name="Injection",
                    test="SQL Injection (Error-based)",
                    status="detected",
                    severity="high",
                    evidence=(
                        f"A aplicação expôs mensagens internas de erro do SGBD ao receber o payload '{payload}'. "
                        f"Trecho identificado: '{snippet}'."
                    ),
                    recommendation=(
                        "Utilizar consultas parametrizadas (Prepared Statements) ou ORM para "
                        "separar estritamente instruções de código dos dados fornecidos pelo usuário. Desabilitar a "
                        "exibição pública de mensagens detalhadas de erro de banco de dados em ambientes de produção."
                    )
                )

    return Finding(
        category="A03",
        name="Injection",
        test="SQL Injection (Error-based)",
        status="not_detected",
        severity="high",
        evidence="Nenhuma assinatura conhecida de erro de SGBD foi identificada nas respostas com caracteres especiais.",
        recommendation=(
            "Manter o uso de consultas preparadas e garantir que mensagens detalhadas de erro "
            "permaneçam ocultas para o usuário final."
        )
    )


def test_boolean_based_sqli(
    session: requests.Session,
    sqli_url: str
) -> Finding:
    """
    Testa se a aplicação é vulnerável a SQL Injection baseado em lógica booleana/tautologia.
    Compara o comportamento da aplicação entre uma consulta legítima (id=1),
    injeções tautológicas (1' OR '1'='1 e 1 OR 1=1) e injeções falsas (1' AND '1'='2 e 1 AND 1=2).
    """
    try:
        # 1. Linha de base legítima
        baseline_resp = _send_sqli_probe(session, sqli_url, "1")
        soup_base = BeautifulSoup(baseline_resp.text, "html.parser")
        baseline_results = len(soup_base.find_all("pre"))

        # Pares de teste (Tautologia Verdadeira vs Contradição Falsa)
        # 1' OR '1'='1 (para campos entre aspas - Low) e 1 OR 1=1 (para campos numéricos sem aspas - Medium)
        test_pairs = [
            ("1' OR '1'='1", "1' AND '1'='2"),
            ("1 OR 1=1", "1 AND 1=2")
        ]

        for tautology_payload, false_payload in test_pairs:
            # 2. Injeção Tautológica (Verdadeira)
            tautology_resp = _send_sqli_probe(session, sqli_url, tautology_payload)
            soup_tautology = BeautifulSoup(tautology_resp.text, "html.parser")
            tautology_results = len(soup_tautology.find_all("pre"))

            # 3. Injeção Falsa / Contraditória
            false_resp = _send_sqli_probe(session, sqli_url, false_payload)
            soup_false = BeautifulSoup(false_resp.text, "html.parser")
            false_results = len(soup_false.find_all("pre"))

            print(f"[A03] Teste Booleano ({tautology_payload}) - Base: {baseline_results}, Tautologia: {tautology_results}, Falso: {false_results}")

            if tautology_results > baseline_results:
                if tautology_payload == "1 OR 1=1":
                    bypass_info = "A injeção explorou a ausência de aspas em campo numérico (ex: WHERE user_id = $id), contornando com sucesso a função mysqli_real_escape_string(). "
                else:
                    bypass_info = "A injeção explorou a concatenação direta de dados na consulta SQL. "

                return Finding(
                    category="A03",
                    name="Injection",
                    test="SQL Injection (Boolean-based)",
                    status="detected",
                    severity="critical",
                    evidence=(
                        f"A injeção lógica '{tautology_payload}' alterou a semântica da consulta no banco de dados. "
                        f"{bypass_info}A consulta maliciosa retornou {tautology_results} registros, enquanto a consulta legítima "
                        f"de referência retornou apenas {baseline_results} (a injeção contraditória '{false_payload}' retornou "
                        f"{false_results} registros, comprovando controle sobre a cláusula WHERE)."
                    ),
                    recommendation=(
                        "Implementar imediatamente consultas parametrizadas (Prepared Statements com PDO ou MySQLi). "
                        "Nunca concatenar dados de entrada de usuários diretamente em strings de comando SQL."
                    )
                )

    except requests.RequestException as e:
        return Finding(
            category="A03",
            name="Injection",
            test="SQL Injection (Boolean-based)",
            status="error",
            severity="critical",
            evidence=f"Falha de comunicação durante o teste: {e}",
            recommendation="Verificar a conectividade e a disponibilidade da aplicação alvo."
        )

    return Finding(
        category="A03",
        name="Injection",
        test="SQL Injection (Boolean-based)",
        status="not_detected",
        severity="critical",
        evidence="A manipulação de operadores booleanos não alterou o conjunto de dados retornado pela aplicação.",
        recommendation="Manter o uso de consultas parametrizadas e validação rigorosa de tipos de dados de entrada."
    )


def run_sql_injection(
    base_url: str,
    session: requests.Session = None,
    username: str = "admin",
    password: str = "password",
    **kwargs
) -> list[Finding]:
    """
    Executa todos os testes relacionados a OWASP A03 - SQL Injection.
    """
    sqli_url = f"{base_url}/vulnerabilities/sqli/"

    # Garante que temos uma sessão autenticada com segurança configurada
    if session is None:
        session = create_dvwa_session(
            base_url=base_url,
            username=username,
            password=password,
            security_level="medium"
        )
        print("[A03] Sessão autenticada criada com sucesso.")
    else:
        print("[A03] Reutilizando sessão autenticada existente.")

    print("\n--- Executando Testes de SQL Injection (A03) ---")
    error_finding = test_error_based_sqli(session=session, sqli_url=sqli_url)
    boolean_finding = test_boolean_based_sqli(session=session, sqli_url=sqli_url)

    return [error_finding, boolean_finding]
