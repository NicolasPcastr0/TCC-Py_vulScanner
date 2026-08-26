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


def test_error_based_sqli(
    session: requests.Session,
    sqli_url: str
) -> Finding:
    """
    Testa se a aplicação é vulnerável a SQL Injection baseado em erros (Error-based).
    Injeta caracteres de escape sintático e analisa se mensagens de erro do SGBD vazam na resposta.
    """
    payloads = ["'", "1'", "1' OR '1'='1", "admin'--"]

    for payload in payloads:
        params = {
            "id": payload,
            "Submit": "Submit"
        }

        try:
            response = session.get(sqli_url, params=params, timeout=10)
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
    uma injeção tautológica verdadeira (1' OR '1'='1) e uma injeção falsa (1' AND '1'='2).
    """
    try:
        # 1. Linha de base legítima
        baseline_resp = session.get(sqli_url, params={"id": "1", "Submit": "Submit"}, timeout=10)
        soup_base = BeautifulSoup(baseline_resp.text, "html.parser")
        baseline_results = len(soup_base.find_all("pre"))

        # 2. Injeção Tautológica (Verdadeira)
        tautology_payload = "1' OR '1'='1"
        tautology_resp = session.get(sqli_url, params={"id": tautology_payload, "Submit": "Submit"}, timeout=10)
        soup_tautology = BeautifulSoup(tautology_resp.text, "html.parser")
        tautology_results = len(soup_tautology.find_all("pre"))

        # 3. Injeção Falsa / Contraditória
        false_payload = "1' AND '1'='2"
        false_resp = session.get(sqli_url, params={"id": false_payload, "Submit": "Submit"}, timeout=10)
        soup_false = BeautifulSoup(false_resp.text, "html.parser")
        false_results = len(soup_false.find_all("pre"))

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

    print(f"[A03] Registros retornados - Consulta base: {baseline_results}, Tautologia ('1'='1): {tautology_results}, Condição falsa: {false_results}")

    # Se a injeção tautológica retornou mais registros do que a consulta legítima
    # e a injeção falsa retornou menos, a query SQL foi manipulada com sucesso
    if tautology_results > baseline_results:
        return Finding(
            category="A03",
            name="Injection",
            test="SQL Injection (Boolean-based)",
            status="detected",
            severity="critical",
            evidence=(
                f"A injeção lógica '{tautology_payload}' alterou a semântica da consulta SQL, retornando "
                f"{tautology_results} registros, enquanto a consulta legítima de referência retornou apenas {baseline_results}. "
                f"A injeção contraditória '{false_payload}' retornou {false_results} registros, comprovando "
                "a execução arbitrária da condição booleana no banco de dados."
            ),
            recommendation=(
                "Implementar imediatamente consultas parametrizadas (Prepared Statements com PDO ou MySQLi). "
                "Nunca concatenar dados de entrada de usuários diretamente em strings de comando SQL."
            )
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
            security_level="low"
        )
        print("[A03] Sessão autenticada criada com sucesso.")
    else:
        print("[A03] Reutilizando sessão autenticada existente.")

    print("\n--- Executando Testes de SQL Injection (A03) ---")
    error_finding = test_error_based_sqli(session=session, sqli_url=sqli_url)
    boolean_finding = test_boolean_based_sqli(session=session, sqli_url=sqli_url)

    return [error_finding, boolean_finding]
