import html
import requests

from scanner.core.finding import Finding
from scanner.utils.dvwa import create_dvwa_session


def test_reflected_xss(
    session: requests.Session,
    xss_url: str
) -> Finding:
    """
    Testa se a aplicação é vulnerável a Cross-Site Scripting Refletido (Reflected XSS).
    Envia payloads de teste com marcadores e verifica se são refletidos no corpo HTML
    da resposta sem a devida sanitização ou codificação de entidades HTML.
    """
    # Payloads seguros com identificadores do SecureScan
    probe_token = "SECURESCAN_XSS_PROBE"
    payloads = [
        f"<script>/*{probe_token}*/</script>",
        f"<img src=x onerror=/*{probe_token}*/ />",
        f'"><script>/*{probe_token}*/</script>',
        f"'><script>/*{probe_token}*/</script>",
    ]

    for payload in payloads:
        params = {
            "name": payload
        }

        try:
            response = session.get(xss_url, params=params, timeout=10)
        except requests.RequestException as e:
            return Finding(
                category="A03",
                name="Injection",
                test="Cross-Site Scripting (Reflected XSS)",
                status="error",
                severity="high",
                evidence=f"Falha de comunicação durante o teste: {e}",
                recommendation="Verificar a conectividade e a disponibilidade da aplicação alvo."
            )

        # Verifica se o payload bruto (não escapado) está presente na resposta
        if payload in response.text:
            # Extrai um trecho contextual ao redor da reflexão
            pos = response.text.find(payload)
            start = max(0, pos - 25)
            end = min(len(response.text), pos + len(payload) + 25)
            snippet = response.text[start:end].replace("\n", " ").strip()

            print(f"[A03] XSS Refletido detectado com o payload: {payload}")

            return Finding(
                category="A03",
                name="Injection",
                test="Cross-Site Scripting (Reflected XSS)",
                status="detected",
                severity="high",
                evidence=(
                    f"A aplicação refletiu o payload de teste '{payload}' diretamente no corpo da resposta "
                    f"sem codificar caracteres especiais em entidades HTML. Trecho identificado: '{snippet}'."
                ),
                recommendation=(
                    "Implementar codificação de saída sensível ao contexto (Context-Aware Output Encoding) "
                    "utilizando funções adequadas (como htmlspecialchars() com flags ENT_QUOTES no PHP) "
                    "ou mecanismos de auto-escape de templates. Configurar cabeçalhos de segurança como "
                    "Content-Security-Policy (CSP) para mitigar a execução de scripts inline não autorizados."
                )
            )

    return Finding(
        category="A03",
        name="Injection",
        test="Cross-Site Scripting (Reflected XSS)",
        status="not_detected",
        severity="high",
        evidence="Os payloads de teste foram devidamente codificados, filtrados ou não refletidos na resposta.",
        recommendation=(
            "Manter as políticas de codificação de saída e aplicar cabeçalhos defensivos como Content-Security-Policy."
        )
    )


def run_xss(
    base_url: str,
    session: requests.Session = None,
    username: str = "admin",
    password: str = "password",
    **kwargs
) -> list[Finding]:
    """
    Executa todos os testes relacionados a OWASP A03 - Cross-Site Scripting (XSS).
    """
    xss_url = f"{base_url}/vulnerabilities/xss_r/"

    # Garante que temos uma sessão autenticada com segurança configurada
    if session is None:
        session = create_dvwa_session(
            base_url=base_url,
            username=username,
            password=password,
            security_level="low"
        )
        print("[A03] Sessão autenticada criada com sucesso para teste de XSS.")
    else:
        print("[A03] Reutilizando sessão autenticada existente para teste de XSS.")

    print("\n--- Executando Testes de Cross-Site Scripting (A03) ---")
    xss_finding = test_reflected_xss(session=session, xss_url=xss_url)

    return [xss_finding]
