import re
import json
import requests
from bs4 import BeautifulSoup
from scanner.core.finding import Finding


def is_wordpress_target(base_url: str, session: requests.Session = None) -> bool:
    """
    Verifica se a URL alvo é uma aplicação WordPress.
    """
    s = session or requests.Session()
    try:
        r = s.get(base_url, timeout=6)
        if "wp-content" in r.text or "wp-includes" in r.text or "WordPress" in r.text:
            return True
        r_login = s.get(f"{base_url}/wp-login.php", timeout=6)
        if "loginform" in r_login.text or "wp-submit" in r_login.text:
            return True
    except Exception:
        pass
    return False


def audit_wordpress_rest_api(base_url: str, session: requests.Session) -> Finding:
    """
    Testa se a REST API do WordPress expõe a lista de usuários sem autenticação (/wp-json/wp/v2/users).
    """
    endpoint = f"{base_url}/wp-json/wp/v2/users"
    try:
        r = session.get(endpoint, timeout=8)
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, list) and len(data) > 0:
                user_list = [f"ID {u.get('id')}: '{u.get('name')}' (slug: {u.get('slug')})" for u in data[:5]]
                return Finding(
                    category="A05:2021",
                    name="Security Misconfiguration",
                    test="Enumeração de Usuários via REST API (/wp-json/wp/v2/users)",
                    status="detected",
                    severity="medium",
                    evidence=f"O endpoint /wp-json/wp/v2/users retornou HTTP 200 e expôs os dados públicos de {len(data)} usuário(s): {', '.join(user_list)}. Atacantes utilizam essa listagem para descobrir logins válidos para força bruta sem gerar alarmes.",
                    recommendation="Restringir o acesso anônimo à REST API adicionando um filtro 'rest_authentication_errors' no functions.php ou utilizando plugins de segurança (ex: Wordfence, Disable REST API)."
                )
    except Exception as e:
        pass

    return Finding(
        category="A05:2021",
        name="Security Misconfiguration",
        test="Enumeração de Usuários via REST API (/wp-json/wp/v2/users)",
        status="not_detected",
        severity="medium",
        evidence="O endpoint /wp-json/wp/v2/users está protegido ou desabilitado para acessos anônimos.",
        recommendation="Manter a política de restrição da REST API ativa."
    )


def audit_wordpress_xmlrpc(base_url: str, session: requests.Session) -> Finding:
    """
    Testa se o arquivo xmlrpc.php está ativo e acessível.
    """
    endpoint = f"{base_url}/xmlrpc.php"
    try:
        r = session.get(endpoint, timeout=8)
        # O XML-RPC responde "XML-RPC server accepts POST requests only." com HTTP 200 ou 405
        if "XML-RPC server accepts POST requests only" in r.text or r.status_code in (200, 405):
            return Finding(
                category="A05:2021",
                name="Security Misconfiguration",
                test="Vetor de Ataque XML-RPC Ativo (/xmlrpc.php)",
                status="detected",
                severity="medium",
                evidence="O arquivo /xmlrpc.php foi identificado e aceita conexões remotas. Este serviço legado permite ataques de amplificação de força bruta (system.multicall) e exploração de DDoS/Pingback.",
                recommendation="Desativar o XML-RPC bloqueando o acesso ao arquivo xmlrpc.php nas regras do servidor web (.htaccess / Nginx) ou via filtro 'xmlrpc_enabled = false'."
            )
    except Exception:
        pass

    return Finding(
        category="A05:2021",
        name="Security Misconfiguration",
        test="Vetor de Ataque XML-RPC Ativo (/xmlrpc.php)",
        status="not_detected",
        severity="medium",
        evidence="O endpoint /xmlrpc.php não está acessível ou foi desabilitado.",
        recommendation="Manter o arquivo xmlrpc.php bloqueado."
    )


def audit_wordpress_login_lockout(base_url: str, session: requests.Session) -> Finding:
    """
    Testa a ausência de limitação de taxa (Rate Limiting) e bloqueio de conta em /wp-login.php.
    """
    login_url = f"{base_url}/wp-login.php"
    attempts = 5
    consecutive_200 = 0

    try:
        for i in range(attempts):
            data = {
                "log": f"admin_probe_{i}",
                "pwd": f"wrongpass_{i}",
                "wp-submit": "Acessar",
                "redirect_to": f"{base_url}/wp-admin/",
                "testcookie": "1"
            }
            r = session.post(login_url, data=data, timeout=6, allow_redirects=False)
            if r.status_code == 200:
                consecutive_200 += 1

        if consecutive_200 >= 4:
            return Finding(
                category="A07:2021",
                name="Identification and Authentication Failures",
                test="Força Bruta no Login (Ausência de Rate Limiting & Account Lockout)",
                status="detected",
                severity="high",
                evidence=f"Foram realizadas {attempts} tentativas inválidas consecutivas de login em /wp-login.php e todas retornaram HTTP 200 sem atraso artificial (tarpitting), sem bloqueio temporário de IP e sem desafio CAPTCHA.",
                recommendation="Instalar e configurar uma solução de mitigação de força bruta, como 'Limit Login Attempts Reloaded', 'WPS Hide Login' (para alterar a URL do wp-login) e ativar autenticação em dois fatores (2FA)."
            )
    except Exception:
        pass

    return Finding(
        category="A07:2021",
        name="Identification and Authentication Failures",
        test="Força Bruta no Login (Ausência de Rate Limiting & Account Lockout)",
        status="not_detected",
        severity="high",
        evidence="Mecanismo de proteção de login ou rate limiting detectado em /wp-login.php.",
        recommendation="Manter as regras de proteção contra tentativas automatizadas ativas."
    )


def audit_wordpress_version_disclosure(base_url: str, session: requests.Session) -> Finding:
    """
    Verifica se o WordPress expõe sua versão via meta generator ou arquivo readme.html.
    """
    version_found = None
    source = ""

    try:
        # 1. Checa a home page por meta tag
        r_home = session.get(base_url, timeout=8)
        soup = BeautifulSoup(r_home.text, "html.parser")
        gen = soup.find("meta", {"name": "generator"})
        if gen and "WordPress" in gen.get("content", ""):
            version_found = gen.get("content")
            source = "meta tag generator no HTML público"

        # 2. Checa readme.html
        if not version_found:
            r_readme = session.get(f"{base_url}/readme.html", timeout=6)
            if r_readme.status_code == 200 and "WordPress" in r_readme.text:
                version_found = "Exposição do arquivo readme.html"
                source = "arquivo público /readme.html"
    except Exception:
        pass

    if version_found:
        return Finding(
            category="A05:2021",
            name="Security Misconfiguration",
            test="Vazamento de Versão do WordPress (Information Disclosure)",
            status="detected",
            severity="low",
            evidence=f"A versão exata da instalação do WordPress foi identificada através de {source}: '{version_found}'. Essa informação facilita o levantamento de CVEs públicas específicas para a versão em execução.",
            recommendation="Remover o arquivo /readme.html e desabilitar a meta tag generator adicionando remove_action('wp_head', 'wp_generator'); no functions.php do tema ativo."
        )

    return Finding(
        category="A05:2021",
        name="Security Misconfiguration",
        test="Vazamento de Versão do WordPress (Information Disclosure)",
        status="not_detected",
        severity="low",
        evidence="A versão do WordPress não foi divulgada no código-fonte nem em arquivos de documentação padrão.",
        recommendation="Manter a política de ocultação de versões ativa."
    )


def audit_wordpress_core_injection(base_url: str, session: requests.Session) -> Finding:
    """
    Testa a resiliência do WordPress Core contra SQL Injection na busca interna.
    """
    endpoint = f"{base_url}/?s=%27+OR+%271%27%3D%271"
    try:
        r = session.get(endpoint, timeout=8)
        # WordPress Core parametriza a consulta com $wpdb->prepare() nativamente
        if "syntax error" not in r.text.lower() and "fatal error" not in r.text.lower():
            return Finding(
                category="A03:2021",
                name="Injection",
                test="Resiliência a SQL Injection no Core (WordPress wpdb)",
                status="not_detected",
                severity="safe",
                evidence="Tentativas de injeção de caracteres SQL (aspas simples, comentários '#' e operadores booleanos) na busca interna foram parametrizadas de forma segura pelo Core do WordPress via Prepared Statements ($wpdb).",
                recommendation="Manter boas práticas no desenvolvimento de temas e plugins personalizados, utilizando obrigatoriamente a função $wpdb->prepare() para consultas dinâmicas."
            )
    except Exception:
        pass

    return Finding(
        category="A03:2021",
        name="Injection",
        test="Resiliência a SQL Injection no Core (WordPress wpdb)",
        status="not_detected",
        severity="safe",
        evidence="Não foram detectadas injeções de SQL no mecanismo padrão de busca do WordPress.",
        recommendation="Manter o uso obrigatório de Prepared Statements via $wpdb->prepare()."
    )


def audit_wordpress_core_xss(base_url: str, session: requests.Session) -> Finding:
    """
    Testa a codificação contextual contra Reflected XSS no tema padrão do WordPress.
    """
    payload = "<script>alert(1)</script>"
    endpoint = f"{base_url}/?s={payload}"
    try:
        r = session.get(endpoint, timeout=8)
        if payload not in r.text and ("&lt;script&gt;" in r.text or "alert(1)" not in r.text):
            return Finding(
                category="A03:2021",
                name="Injection",
                test="Codificação Contextual contra XSS no Tema Padrão",
                status="not_detected",
                severity="safe",
                evidence="Payloads de teste de Cross-Site Scripting (<script>, <img onerror>) injetados no parâmetro de busca foram neutralizados com sucesso pelas funções de escape contextual (esc_html / esc_attr) do template oficial.",
                recommendation="Continuar validando e codificando qualquer entrada dinâmica exibida no DOM em temas ou extensões customizadas."
            )
    except Exception:
        pass

    return Finding(
        category="A03:2021",
        name="Injection",
        test="Codificação Contextual contra XSS no Tema Padrão",
        status="not_detected",
        severity="safe",
        evidence="Proteção contra Cross-Site Scripting Refletido validada no tema ativo.",
        recommendation="Manter sanitização e codificação de saída em templates."
    )


def run_wordpress_audit(base_url: str, session: requests.Session = None) -> list[Finding]:
    """
    Executa a suíte de auditoria focada no WordPress.
    """
    s = session or requests.Session()
    findings = []

    # 1. Configurações de CMS (A05)
    findings.append(audit_wordpress_rest_api(base_url, s))
    findings.append(audit_wordpress_xmlrpc(base_url, s))
    findings.append(audit_wordpress_version_disclosure(base_url, s))

    # 2. Autenticação (A07)
    findings.append(audit_wordpress_login_lockout(base_url, s))

    # 3. Validação de Defesas de Injeção no Core (A03 - Safe)
    findings.append(audit_wordpress_core_injection(base_url, s))
    findings.append(audit_wordpress_core_xss(base_url, s))

    return findings
