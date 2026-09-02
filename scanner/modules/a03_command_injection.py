import requests
from bs4 import BeautifulSoup

from scanner.core.finding import Finding
from scanner.utils.dvwa import create_dvwa_session


def test_command_injection(
    session: requests.Session,
    exec_url: str
) -> Finding:
    """
    Testa se a aplicação é vulnerável a Command Injection (Injeção de Comandos no Sistema Operacional).
    Envia entradas com operadores de encadeamento de shell (;, &&, |) e verifica se comandos
    arbitrários são executados e retornados pelo servidor.
    """
    canary_token = "SECURESCAN_CMD_EXEC_CONFIRMED"
    payloads = [
        f"127.0.0.1; echo {canary_token}",
        f"127.0.0.1 && echo {canary_token}",
        f"127.0.0.1 | echo {canary_token}",
    ]

    for payload in payloads:
        data = {
            "ip": payload,
            "Submit": "Submit"
        }

        try:
            response = session.post(exec_url, data=data, timeout=20)
        except requests.RequestException as e:
            return Finding(
                category="A03",
                name="Injection",
                test="Command Injection",
                status="error",
                severity="critical",
                evidence=f"Falha de comunicação durante o teste: {e}",
                recommendation="Verificar a conectividade e a disponibilidade da aplicação alvo."
            )

        # Inspeciona se a resposta da aplicação contém o resultado do comando injetado
        if canary_token in response.text:
            soup = BeautifulSoup(response.text, "html.parser")
            pre_tag = soup.find("pre")
            
            if pre_tag:
                lines = [line.strip() for line in pre_tag.text.strip().splitlines() if line.strip()]
                # Mantém as linhas finais que contêm a confirmação de execução de forma enxuta
                snippet = " | ".join(lines[-2:]) if len(lines) >= 2 else lines[0]
            else:
                snippet = f"Marcador '{canary_token}' encontrado no corpo da resposta."

            print(f"[A03] Injeção de comando de SO detectada com o payload: {payload}")

            bypass_info = ""
            if "|" in payload:
                bypass_info = "O teste contornou com sucesso a lista negra de operadores (bloqueio de ';' e '&&') utilizando o operador pipe ('|'). "

            return Finding(
                category="A03",
                name="Injection",
                test="Command Injection",
                status="detected",
                severity="critical",
                evidence=(
                    f"O servidor executou comandos arbitrários de shell concatenados à entrada. "
                    f"{bypass_info}Ao submeter o payload '{payload}', o comando injetado foi executado "
                    f"no sistema operacional e retornou o marcador de confirmação '{canary_token}'. "
                    f"Trecho capturado: '{snippet}'."
                ),
                recommendation=(
                    "Evitar a invocação direta de comandos de shell do sistema operacional através de funções "
                    "como shell_exec(), exec() ou system(). Caso seja estritamente necessário interagir com "
                    "recursos do sistema, utilizar APIs nativas da linguagem de programação ou aplicar listas "
                    "brancas rigorosas (whitelisting) com validação de formato de dados (ex: regex para IPv4/IPv6) "
                    "e funções de escape seguras (como escapeshellcmd e escapeshellarg)."
                )
            )

    return Finding(
        category="A03",
        name="Injection",
        test="Command Injection",
        status="not_detected",
        severity="critical",
        evidence="Nenhum dos operadores de encadeamento de shell testados resultou na execução de comandos arbitrários.",
        recommendation=(
            "Manter o isolamento entre dados de entrada e chamadas de sistema, aplicando validações estritas de tipo."
        )
    )


def run_command_injection(
    base_url: str,
    session: requests.Session = None,
    username: str = "admin",
    password: str = "password",
    **kwargs
) -> list[Finding]:
    """
    Executa todos os testes relacionados a OWASP A03 - Command Injection.
    """
    exec_url = f"{base_url}/vulnerabilities/exec/"

    # Garante que temos uma sessão autenticada com segurança configurada
    if session is None:
        session = create_dvwa_session(
            base_url=base_url,
            username=username,
            password=password,
            security_level="low"
        )
        print("[A03] Sessão autenticada criada com sucesso para teste de Command Injection.")
    else:
        print("[A03] Reutilizando sessão autenticada existente para teste de Command Injection.")

    print("\n--- Executando Testes de Command Injection (A03) ---")
    cmd_finding = test_command_injection(session=session, exec_url=exec_url)

    return [cmd_finding]
