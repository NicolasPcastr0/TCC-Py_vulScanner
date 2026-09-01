import os
import requests
from scanner.core.finding import Finding
from scanner.ai.prompts import SYSTEM_PROMPT, build_interpretation_prompt


def _load_env_file():
    """
    Carregador leve de variáveis de ambiente a partir do arquivo .env.
    """
    env_path = os.path.join(os.getcwd(), ".env")
    if os.path.exists(env_path):
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, val = line.split("=", 1)
                        key = key.strip()
                        val = val.strip().strip('"').strip("'")
                        if key and key not in os.environ:
                            os.environ[key] = val
        except Exception:
            pass


class AIInterpreter:
    """
    Componente responsável pela interpretação inteligente de achados do SecureScan.
    Suporta Google Gemini API, OpenAI API e Modo de Demonstração / Fallback.
    """

    def __init__(self):
        _load_env_file()
        self.gemini_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        self.openai_key = os.getenv("OPENAI_API_KEY")

    def interpret_findings(self, findings: list[Finding]) -> str:
        """
        Recebe a lista de Findings determinísticos e gera um relatório explicativo com IA.
        """
        if not findings:
            return "Nenhum achado foi fornecido para análise da IA."

        prompt = build_interpretation_prompt(findings)

        # 1. Tenta utilizar a API do Google Gemini
        if self.gemini_key:
            try:
                return self._call_gemini(prompt)
            except Exception as e:
                print(f"[!] Erro ao consultar a API do Gemini: {e}. Alternando para modo fallback...")

        # 2. Tenta utilizar a API da OpenAI
        if self.openai_key:
            try:
                return self._call_openai(prompt)
            except Exception as e:
                print(f"[!] Erro ao consultar a API da OpenAI: {e}. Alternando para modo fallback...")

        # 3. Modo de Demonstração / Fallback Acadêmico caso nenhuma chave esteja configurada
        return self._generate_fallback_report(findings)

    def _call_gemini(self, prompt: str) -> str:
        """
        Executa chamada à API REST do Google Gemini com fallback automático
        entre modelos disponíveis caso haja sobrecarga temporária (HTTP 503/429).
        """
        candidate_models = [
            "gemini-2.5-flash-lite",
            "gemini-3.6-flash",
            "gemini-3.5-flash",
            "gemini-flash-latest"
        ]

        last_error = None
        headers = {"Content-Type": "application/json"}
        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": f"{SYSTEM_PROMPT}\n\n{prompt}"}
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.2
            }
        }

        for model_name in candidate_models:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={self.gemini_key}"
            try:
                response = requests.post(url, json=payload, headers=headers, timeout=20)
                if response.status_code == 200:
                    data = response.json()
                    candidates = data.get("candidates", [])
                    if candidates:
                        parts = candidates[0].get("content", {}).get("parts", [])
                        if parts:
                            return parts[0].get("text", "").strip()

                last_error = f"Modelo '{model_name}' retornou HTTP {response.status_code}: {response.text}"
            except requests.RequestException as e:
                last_error = f"Timeout/Conexão no modelo '{model_name}': {e}"

        raise RuntimeError(f"Todos os modelos do Gemini falharam. Último erro: {last_error}")

    def _call_openai(self, prompt: str) -> str:
        """
        Executa chamada direta à API REST da OpenAI (gpt-4o-mini).
        """
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.openai_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.2
        }

        response = requests.post(url, json=payload, headers=headers, timeout=30)
        if response.status_code != 200:
            raise RuntimeError(f"HTTP {response.status_code}: {response.text}")

        data = response.json()
        choices = data.get("choices", [])
        if choices:
            return choices[0].get("message", {}).get("content", "").strip()

        raise RuntimeError("Resposta vazia retornada pela API da OpenAI.")

    def _generate_fallback_report(self, findings: list[Finding]) -> str:
        """
        Gera uma síntese estruturada demonstrando o funcionamento da camada de IA
        quando nenhuma chave de API externa foi configurada no ambiente.
        """
        critical_count = sum(1 for f in findings if f.severity.lower() == "critical")
        high_count = sum(1 for f in findings if f.severity.lower() == "high")
        medium_count = sum(1 for f in findings if f.severity.lower() == "medium")

        report = f"""[Modo de Demonstração da Camada de IA - Configure GEMINI_API_KEY no arquivo .env para análise em tempo real]

### 1. Visão Geral e Postura de Segurança
- **Nível de Risco Geral:** CRÍTICO
- **Resumo Executivo:** O SecureScan identificou um total de {len(findings)} vulnerabilidades ativas na aplicação alvo ({critical_count} Críticas, {high_count} Altas, {medium_count} Médias). A aplicação apresenta falhas severas no nível de infraestrutura/servidor (Command Injection), dados (SQL Injection), navegador/cliente (Cross-Site Scripting) e controle de autenticação (Força Bruta e ausência de Rate Limiting).

### 2. Análise de Cenários de Ataque e Impacto de Negócio
- **Cenário de Encadeamento de Ataque (Kill Chain):**
  1. *Acesso Inicial:* O invasor utiliza ataques automatizados de dicionário para obter credenciais válidas devido à falta de limitação de requisições (A07).
  2. *Extração e Comprometimento de Dados:* Com acesso à aplicação, explora SQL Injection (A03) para extrair todos os registros da base de dados e hashes de usuários.
  3. *Tomada Completa do Servidor:* Através da Injeção de Comandos (A03), o invasor executa comandos arbitrários no sistema operacional como o usuário do servidor web (www-data), obtendo Execução Remota de Código (RCE).
- **Impacto de Negócio:** Violação total da confidencialidade, integridade e disponibilidade (Tríade CIA), com risco de vazamento de dados confidenciais e sequestro de infraestrutura.

### 3. Guia Técnico de Remediação com Exemplos de Código
- **Command Injection:** Eliminar chamadas a shell_exec() / system(). Utilizar APIs nativas da linguagem ou validação estrita com listas brancas e escapeshellarg().
- **SQL Injection:** Migrar todas as consultas dinâmicas para instruções preparadas (Prepared Statements com PDO ou MySQLi):
  ```php
  $stmt = $pdo->prepare('SELECT first_name, last_name FROM users WHERE user_id = :id');
  $stmt->execute(['id' => $id]);
  ```
- **Cross-Site Scripting (XSS):** Aplicar codificação de saída sensível ao contexto com htmlspecialchars($data, ENT_QUOTES, 'UTF-8') e configurar cabeçalho Content-Security-Policy (CSP).
- **Authentication Failures:** Implementar limitação de taxa de requisições (Rate Limiting) e bloqueio temporário após 5 tentativas consecutivas.

### 4. Matriz de Priorização das Correções
| Prioridade | Vulnerabilidade | Categoria OWASP | Ação Recomendada | Benefício |
|---|---|---|---|---|
| 1. IMEDIATA | Command Injection | A03: Injection | Substituir chamadas de shell por funções nativas | Impede tomada total do servidor (RCE) |
| 2. IMEDIATA | SQL Injection (Boolean & Error) | A03: Injection | Implementar Prepared Statements (PDO) | Protege todo o banco de dados contra vazamento |
| 3. ALTA | Cross-Site Scripting (XSS) | A03: Injection | Aplicar htmlspecialchars e CSP | Protege as sessões dos usuários contra sequestro |
| 4. MÉDIA | Brute Force & Rate Limiting | A07: Auth Failures | Configurar Rate Limiting e MFA | Dificulta ataques automatizados a credenciais |
"""
        return report
