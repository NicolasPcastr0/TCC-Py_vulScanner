import re
import requests

from scanner.core.finding import Finding
from scanner.utils.dvwa import create_dvwa_session


def check_content_security_policy(headers: requests.structures.CaseInsensitiveDict) -> Finding:
    """
    Verifica a presença e integridade do cabeçalho Content-Security-Policy (CSP).
    """
    csp = headers.get("Content-Security-Policy")
    if not csp:
        return Finding(
            category="A05:2021",
            name="Security Misconfiguration",
            test="Ausência de Content-Security-Policy (CSP)",
            status="detected",
            severity="medium",
            evidence="O cabeçalho de resposta HTTP 'Content-Security-Policy' não foi retornado pela aplicação. A ausência de CSP impede que o navegador restrinja a origem de scripts e recursos dinâmicos, ampliando a superfície de exploração para ataques de XSS e injeção de dados.",
            recommendation="Configurar uma política rigorosa de Content-Security-Policy no servidor web ou na aplicação (ex.: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none')."
        )
    return Finding(
        category="A05:2021",
        name="Security Misconfiguration",
        test="Ausência de Content-Security-Policy (CSP)",
        status="not_detected",
        severity="medium",
        evidence=f"Cabeçalho Content-Security-Policy presente na resposta: {csp[:120]}...",
        recommendation="Revisar periodicamente as diretivas do CSP para evitar o uso de 'unsafe-inline' e 'unsafe-eval'."
    )


def check_x_frame_options(headers: requests.structures.CaseInsensitiveDict) -> Finding:
    """
    Verifica a presença de proteção contra Clickjacking (X-Frame-Options / frame-ancestors).
    """
    xfo = headers.get("X-Frame-Options")
    csp = headers.get("Content-Security-Policy", "")
    has_frame_ancestors = "frame-ancestors" in csp.lower()

    if not xfo and not has_frame_ancestors:
        return Finding(
            category="A05:2021",
            name="Security Misconfiguration",
            test="Ausência de Proteção contra Clickjacking (X-Frame-Options)",
            status="detected",
            severity="medium",
            evidence="O cabeçalho 'X-Frame-Options' não foi configurado e não há diretiva 'frame-ancestors' no CSP. A aplicação pode ser incorporada em <iframe> ou <frame> por sites maliciosos para realizar ataques de Clickjacking (UI Redressing).",
            recommendation="Adicionar o cabeçalho 'X-Frame-Options: DENY' ou 'X-Frame-Options: SAMEORIGIN', ou utilizar a diretiva 'frame-ancestors' na Content-Security-Policy."
        )
    return Finding(
        category="A05:2021",
        name="Security Misconfiguration",
        test="Ausência de Proteção contra Clickjacking (X-Frame-Options)",
        status="not_detected",
        severity="medium",
        evidence=f"Proteção contra Clickjacking ativa: {xfo or 'CSP frame-ancestors configurado'}.",
        recommendation="Manter a política de restrição de enquadramento (framing) atualizada."
    )


def check_x_content_type_options(headers: requests.structures.CaseInsensitiveDict) -> Finding:
    """
    Verifica a proteção contra MIME-sniffing (X-Content-Type-Options: nosniff).
    """
    xcto = headers.get("X-Content-Type-Options")
    if not xcto or "nosniff" not in xcto.lower():
        return Finding(
            category="A05:2021",
            name="Security Misconfiguration",
            test="Ausência de X-Content-Type-Options (MIME Sniffing)",
            status="detected",
            severity="low",
            evidence="O cabeçalho 'X-Content-Type-Options: nosniff' não foi enviado pelo servidor. Navegadores podem tentar adivinhar o tipo MIME de arquivos de forma divergente do cabeçalho Content-Type, o que pode levar à interpretação indevida de arquivos de mídia como scripts executáveis.",
            recommendation="Configurar o cabeçalho 'X-Content-Type-Options: nosniff' em todas as respostas HTTP da aplicação."
        )
    return Finding(
        category="A05:2021",
        name="Security Misconfiguration",
        test="Ausência de X-Content-Type-Options (MIME Sniffing)",
        status="not_detected",
        severity="low",
        evidence="Cabeçalho 'X-Content-Type-Options: nosniff' configurado corretamente.",
        recommendation="Manter o cabeçalho ativo em todos os ambientes."
    )


def check_hsts(headers: requests.structures.CaseInsensitiveDict, target_url: str) -> Finding:
    """
    Verifica a presença de Strict-Transport-Security (HSTS).
    """
    hsts = headers.get("Strict-Transport-Security")
    if not hsts:
        return Finding(
            category="A05:2021",
            name="Security Misconfiguration",
            test="Ausência de Strict-Transport-Security (HSTS)",
            status="detected",
            severity="low",
            evidence="O cabeçalho 'Strict-Transport-Security' (HSTS) não foi identificado na resposta HTTP. A ausência de HSTS permite que atacantes na mesma rede realizem ataques de rebaixamento de protocolo (SSL Stripping) e interceptem tráfego não criptografado.",
            recommendation="Migrar todo o tráfego da aplicação para HTTPS e adicionar o cabeçalho 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."
        )
    return Finding(
        category="A05:2021",
        name="Security Misconfiguration",
        test="Ausência de Strict-Transport-Security (HSTS)",
        status="not_detected",
        severity="low",
        evidence=f"Cabeçalho HSTS ativo: {hsts}.",
        recommendation="Garantir que max-age seja configurado com valor mínimo de 1 ano (31536000 segundos)."
    )


def check_information_disclosure(headers: requests.structures.CaseInsensitiveDict) -> Finding:
    """
    Verifica se cabeçalhos como Server e X-Powered-By revelam versões detalhadas de software.
    """
    server = headers.get("Server", "")
    powered_by = headers.get("X-Powered-By", "")
    leak_details = []

    # Detecta se há versões explícitas (ex: Apache/2.4.54, PHP/8.1)
    has_server_version = bool(re.search(r"[\d.]+", server)) if server else False
    has_powered_by_version = bool(re.search(r"[\d.]+", powered_by)) if powered_by else False

    if server and has_server_version:
        leak_details.append(f"Server: '{server}'")
    elif server:
        leak_details.append(f"Server: '{server}' (sem versão específica)")

    if powered_by:
        leak_details.append(f"X-Powered-By: '{powered_by}'")

    if has_server_version or has_powered_by_version or powered_by:
        evidence_str = "Foram identificados cabeçalhos de resposta HTTP que divulgam tecnologias e versões internas: " + ", ".join(leak_details) + ". Essa exposição facilita o levantamento de vulnerabilidades públicas conhecidas (CVEs) direcionadas à versão exata do software em execução."
        return Finding(
            category="A05:2021",
            name="Security Misconfiguration",
            test="Vazamento de Informações do Servidor (Banner Disclosure)",
            status="detected",
            severity="low",
            evidence=evidence_str,
            recommendation="Ocultar banners e versões de software no servidor web (no Apache: 'ServerTokens Prod' e 'ServerSignature Off'; no Nginx: 'server_tokens off'; no PHP: 'expose_php = Off' no php.ini)."
        )

    return Finding(
        category="A05:2021",
        name="Security Misconfiguration",
        test="Vazamento de Informações do Servidor (Banner Disclosure)",
        status="not_detected",
        severity="low",
        evidence="Nenhum vazamento evidente de versão de software identificado nos cabeçalhos HTTP Server ou X-Powered-By.",
        recommendation="Manter as configurações de ofuscação de banners ativas em produção."
    )


def run_security_misconfiguration(
    base_url: str,
    session: requests.Session = None,
    username: str = "admin",
    password: str = "password",
    **kwargs
) -> list[Finding]:
    """
    Executa a auditoria passiva de cabeçalhos de segurança e misconfigurations (OWASP A05:2021).
    """
    print("\n--- Executando Análise de Cabeçalhos e Misconfiguration (A05) ---")

    if session is None:
        try:
            session = create_dvwa_session(
                base_url=base_url,
                username=username,
                password=password,
                security_level="medium"
            )
        except Exception:
            session = requests.Session()

    try:
        response = session.get(base_url, timeout=10, allow_redirects=True)
        headers = response.headers
    except requests.RequestException as e:
        print(f"[-] Erro ao obter cabeçalhos de {base_url}: {e}")
        return [
            Finding(
                category="A05:2021",
                name="Security Misconfiguration",
                test="Análise Passiva de Cabeçalhos HTTP",
                status="error",
                severity="low",
                evidence=f"Não foi possível obter resposta HTTP do alvo {base_url}. Erro de rede: {e}",
                recommendation="Certificar-se de que a aplicação alvo está em execução e acessível via rede."
            )
        ]

    findings = [
        check_content_security_policy(headers),
        check_x_frame_options(headers),
        check_x_content_type_options(headers),
        check_hsts(headers, base_url),
        check_information_disclosure(headers)
    ]

    detected_count = sum(1 for f in findings if f.status == "detected")
    print(f"[A05] Análise de cabeçalhos concluída. {detected_count} misconfiguration(s) identificada(s).")
    return findings
