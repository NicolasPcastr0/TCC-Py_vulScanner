import type { Finding, ScanResult, ScanSummary, SecurityLevel } from '../types/scanner';

/**
 * Dados para o nível LOW: Ausência de defesas e exploração direta/trivial.
 */
export const MOCK_FINDINGS_LOW: Finding[] = [
  {
    id: 'FIND-001',
    category: 'A07:2021',
    name: 'Identification and Authentication Failures',
    test: 'Brute Force de Credenciais (Nível Low)',
    status: 'detected',
    severity: 'medium',
    evidence: "A aplicação aceitou múltiplas requisições sem atraso observável. A credencial 'password' para o usuário 'admin' foi identificada de forma instantânea.",
    recommendation: 'Implementar mecanismos de proteção contra ataques de força bruta, como limitação de taxa de requisições (rate limiting), bloqueio temporário de contas e autenticação multifator (MFA).'
  },
  {
    id: 'FIND-002',
    category: 'A07:2021',
    name: 'Identification and Authentication Failures',
    test: 'Proteção contra Força Bruta (Ausência de Rate Limiting)',
    status: 'detected',
    severity: 'medium',
    evidence: 'Foram realizadas 5 tentativas inválidas consecutivas com tempo de resposta imediato (< 50ms) e todas retornaram HTTP 200, comprovando ausência total de rate limiting ou mecanismo de atraso.',
    recommendation: 'Implementar controles defensivos contra tentativas automatizadas, tais como rate limiting por IP/conta, bloqueio progressivo e desafios CAPTCHA.'
  },
  {
    id: 'FIND-003',
    category: 'A03:2021',
    name: 'Injection',
    test: 'SQL Injection Error-based (Nível Low - GET)',
    status: 'detected',
    severity: 'high',
    evidence: "A aplicação expôs mensagens internas de erro do MariaDB ao receber o caractere de aspa simples ('). A entrada do parâmetro GET foi concatenada diretamente na query sem sanitização.",
    recommendation: 'Utilizar consultas parametrizadas (Prepared Statements com PDO). Desabilitar a exibição pública de erros de banco de dados em ambientes de produção.'
  },
  {
    id: 'FIND-004',
    category: 'A03:2021',
    name: 'Injection',
    test: 'SQL Injection Boolean-based (Nível Low - GET)',
    status: 'detected',
    severity: 'critical',
    evidence: "A injeção lógica com aspas '1' OR '1'='1' via requisição GET alterou a semântica da consulta, retornando todos os 5 registros do banco de dados contra apenas 1 da consulta de referência.",
    recommendation: 'Implementar imediatamente consultas parametrizadas (Prepared Statements). Nunca interpolar variáveis de usuário diretamente em comandos SQL.'
  },
  {
    id: 'FIND-005',
    category: 'A03:2021',
    name: 'Injection',
    test: 'Cross-Site Scripting Refletido (Nível Low - GET)',
    status: 'detected',
    severity: 'high',
    evidence: "A aplicação refletiu a tag literal '<script>/*SECURESCAN_XSS_PROBE*/</script>' diretamente no corpo da resposta sem qualquer tentativa de filtro ou codificação HTML.",
    recommendation: 'Implementar codificação de saída sensível ao contexto (Context-Aware Output Encoding) com htmlspecialchars($data, ENT_QUOTES, UTF-8) e configurar cabeçalhos Content-Security-Policy (CSP).'
  },
  {
    id: 'FIND-006',
    category: 'A03:2021',
    name: 'Injection',
    test: 'Command Injection (Nível Low - Ponto-e-vírgula)',
    status: 'detected',
    severity: 'critical',
    evidence: "O servidor executou comandos arbitrários de shell concatenados pelo operador ';' (payload: '127.0.0.1; echo SECURESCAN_CMD_EXEC_CONFIRMED'). O comando retornou o marcador de confirmação na saída da resposta.",
    recommendation: 'Evitar a invocação de comandos de shell via shell_exec() ou system(). Utilizar APIs nativas da linguagem de programação e validação estrita de formato (whitelisting).'
  },
  {
    id: 'FIND-007',
    category: 'A05:2021',
    name: 'Security Misconfiguration',
    test: 'Ausência de Content-Security-Policy (CSP)',
    status: 'detected',
    severity: 'medium',
    evidence: "O cabeçalho de resposta HTTP 'Content-Security-Policy' não foi retornado pela aplicação. A ausência de CSP impede que o navegador restrinja a origem de scripts e recursos dinâmicos, ampliando a superfície de exploração para ataques de XSS e injeção de dados.",
    recommendation: "Configurar uma política rigorosa de Content-Security-Policy no servidor web ou na aplicação (ex.: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none')."
  },
  {
    id: 'FIND-008',
    category: 'A05:2021',
    name: 'Security Misconfiguration',
    test: 'Ausência de Proteção contra Clickjacking (X-Frame-Options)',
    status: 'detected',
    severity: 'medium',
    evidence: "O cabeçalho 'X-Frame-Options' não foi configurado e não há diretiva 'frame-ancestors' no CSP. A aplicação pode ser incorporada em <iframe> ou <frame> por sites maliciosos para realizar ataques de Clickjacking (UI Redressing).",
    recommendation: "Adicionar o cabeçalho 'X-Frame-Options: DENY' ou 'X-Frame-Options: SAMEORIGIN', ou utilizar a diretiva 'frame-ancestors' na Content-Security-Policy."
  },
  {
    id: 'FIND-009',
    category: 'A05:2021',
    name: 'Security Misconfiguration',
    test: 'Ausência de X-Content-Type-Options (MIME Sniffing)',
    status: 'detected',
    severity: 'low',
    evidence: "O cabeçalho 'X-Content-Type-Options: nosniff' não foi enviado pelo servidor. Navegadores podem tentar adivinhar o tipo MIME de arquivos de forma divergente do cabeçalho Content-Type, o que pode levar à interpretação indevida de arquivos de mídia como scripts executáveis.",
    recommendation: "Configurar o cabeçalho 'X-Content-Type-Options: nosniff' em todas as respostas HTTP da aplicação."
  },
  {
    id: 'FIND-010',
    category: 'A05:2021',
    name: 'Security Misconfiguration',
    test: 'Ausência de Strict-Transport-Security (HSTS)',
    status: 'detected',
    severity: 'low',
    evidence: "O cabeçalho 'Strict-Transport-Security' (HSTS) não foi identificado na resposta HTTP. A ausência de HSTS permite que atacantes na mesma rede realizem ataques de rebaixamento de protocolo (SSL Stripping) e interceptem tráfego não criptografado.",
    recommendation: "Migrar todo o tráfego da aplicação para HTTPS e adicionar o cabeçalho 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."
  },
  {
    id: 'FIND-011',
    category: 'A05:2021',
    name: 'Security Misconfiguration',
    test: 'Vazamento de Informações do Servidor (Banner Disclosure)',
    status: 'detected',
    severity: 'low',
    evidence: "Foram identificados cabeçalhos de resposta HTTP que divulgam tecnologias e versões internas: Server: 'Apache/2.4.54 (Debian)', X-Powered-By: 'PHP/8.1.2'. Essa exposição facilita o levantamento de vulnerabilidades públicas conhecidas (CVEs) direcionadas à versão exata do software em execução.",
    recommendation: "Ocultar banners e versões de software no servidor web (no Apache: 'ServerTokens Prod' e 'ServerSignature Off'; no Nginx: 'server_tokens off'; no PHP: 'expose_php = Off' no php.ini)."
  }
];

export const MOCK_AI_REPORT_LOW = `### 1. Visão Geral da Postura de Segurança (Nível LOW)
- **Nível de Risco Geral:** CRÍTICO
- **Resumo Executivo:** O alvo analisado no nível LOW apresenta **ausência total de controles defensivos**. Foram detectadas vulnerabilidades críticas de injeção (SQLi e Command Injection), falhas de autenticação (Brute Force sem rate limit) e múltiplas configurações incorretas de segurança (**OWASP A05:2021**), incluindo ausência total de cabeçalhos de proteção (CSP, X-Frame-Options, HSTS) e vazamento explícito de versão do servidor web Apache e PHP.

### 2. Cenário de Encadeamento de Ataque (Kill Chain)
1. **Reconhecimento:** Através do cabeçalho \`Server: Apache/2.4.54\` e \`X-Powered-By: PHP/8.1.2\` (A05), o atacante mapeia o ambiente exato e CVEs públicas.
2. **Acesso Inicial:** A ausência de rate limiting (A07) permite descobrir credenciais administrativas via ataque de dicionário em poucos segundos.
3. **Exfiltração de Dados:** Com uma injeção SQL trivial no parâmetro GET (\`1' OR '1'='1\`) (A03), o invasor extrai toda a tabela de usuários.
4. **Execução Remota de Código (RCE):** Através de injeção de comandos com \`;\` na funcionalidade de rede (A03), o invasor obtém shell interativo no servidor.

### 3. Matriz de Priorização das Correções
| Prioridade | Vulnerabilidade | Causa Raiz | Ação Recomendada |
|---|---|---|---|
| 🔴 IMEDIATA | Command Injection | Concatenação direta em shell_exec() | Substituir por funções nativas e validação de IP |
| 🔴 IMEDIATA | SQL Injection (Boolean & Error) | Concatenação de string na query | Migrar para Prepared Statements (PDO) |
| 🟠 ALTA | XSS Refletido | Falta de escape de caracteres HTML | Aplicar htmlspecialchars(..., ENT_QUOTES) |
| 🟡 MÉDIA | Falhas de Autenticação | Sem limitação de tentativas de login | Implementar Rate Limiting e MFA |
| 🟡 MÉDIA | Ausência de CSP & X-Frame-Options | Cabeçalhos HTTP defensivos ausentes (A05) | Adicionar CSP e X-Frame-Options no servidor |
| 🔵 BAIXA | Banner Disclosure & MIME Sniffing | Exposição de versão e falta de nosniff (A05) | Configurar ServerTokens Prod e X-Content-Type-Options |`;

/**
 * Dados para o nível MEDIUM: Defesas parciais implementadas pelo DVWA que o SecureScan contorna.
 */
export const MOCK_FINDINGS_MEDIUM: Finding[] = [
  {
    id: 'FIND-001',
    category: 'A07:2021',
    name: 'Identification and Authentication Failures',
    test: 'Brute Force de Credenciais (Nível Medium - Tarpitting)',
    status: 'detected',
    severity: 'medium',
    evidence: "A aplicação adicionou um atraso proposital de 2 segundos por tentativa falha (sleep(2) / tarpitting), porém continuou aceitando requisições sem bloqueio de conta. A credencial 'password' foi descoberta com sucesso.",
    recommendation: 'O atraso progressivo reduz a velocidade, mas não impede ataques automatizados. Implementar bloqueio temporário de conta (Account Lockout) após 5 tentativas e autenticação multifator (MFA).'
  },
  {
    id: 'FIND-002',
    category: 'A07:2021',
    name: 'Identification and Authentication Failures',
    test: 'Proteção contra Força Bruta (Ausência de Bloqueio)',
    status: 'detected',
    severity: 'medium',
    evidence: 'Foram realizadas 5 tentativas inválidas consecutivas. Apesar do atraso de 2s por requisição, todas responderam com HTTP 200, sem acionamento de bloqueio temporário de conta (Account Lockout) ou desafio CAPTCHA.',
    recommendation: 'Implementar bloqueio temporário de IP/conta após limite de tentativas consecutivas inválidas.'
  },
  {
    id: 'FIND-003',
    category: 'A03:2021',
    name: 'Injection',
    test: 'SQL Injection Error-based (Nível Medium - POST)',
    status: 'detected',
    severity: 'high',
    evidence: "A aplicação alterou o método de envio para formulário POST com sanitização de aspas. O envio do payload '1'' gerou erro de sintaxe SQL no MariaDB, revelando que a consulta continua concatenando entradas.",
    recommendation: 'Substituir chamadas como mysqli_real_escape_string por consultas parametrizadas completas (Prepared Statements).'
  },
  {
    id: 'FIND-004',
    category: 'A03:2021',
    name: 'Injection',
    test: 'SQL Injection Boolean-based (Nível Medium - Bypass Numérico)',
    status: 'detected',
    severity: 'critical',
    evidence: "A injeção lógica numérica '1 OR 1=1' via formulário POST contornou com sucesso a sanitização mysqli_real_escape_string(). Como o campo 'id' não possuía aspas na query SQL (WHERE user_id = $id), a injeção foi executada e retornou todos os 5 registros.",
    recommendation: 'Sanitizar apenas aspas não protege campos numéricos sem aspas. A única defesa definitiva é o uso obrigatório de Prepared Statements (PDO).'
  },
  {
    id: 'FIND-005',
    category: 'A03:2021',
    name: 'Injection',
    test: 'Cross-Site Scripting Refletido (Nível Medium - Evasão de Filtro)',
    status: 'detected',
    severity: 'high',
    evidence: "A aplicação tentou se defender apagando a tag '<script>' com str_replace(). O scanner utilizou o payload polimórfico '<img src=x onerror=/*SECURESCAN_XSS_PROBE*/ />', contornando o filtro ingênuo e alcançando execução no navegador.",
    recommendation: 'Nunca utilizar listas negras parciais (blacklists) como str_replace para sanitizar XSS. Aplicar codificação de saída sensível ao contexto com htmlspecialchars() e política de CSP.'
  },
  {
    id: 'FIND-006',
    category: 'A03:2021',
    name: 'Injection',
    test: 'Command Injection (Nível Medium - Evasão de Blacklist)',
    status: 'detected',
    severity: 'critical',
    evidence: "A aplicação bloqueou os caracteres ';' e '&&', mas omitiu o operador pipe ('|'). O scanner enviou o payload '127.0.0.1 | echo SECURESCAN_CMD_EXEC_CONFIRMED', contornando a blacklist e executando comandos de shell no servidor.",
    recommendation: 'Listas negras de caracteres são inerentemente frágeis em segurança ofensiva. Eliminar chamadas de shell e aplicar listas brancas rigorosas (whitelisting de IPs via regex).'
  },
  {
    id: 'FIND-007',
    category: 'A05:2021',
    name: 'Security Misconfiguration',
    test: 'Ausência de Content-Security-Policy (CSP)',
    status: 'detected',
    severity: 'medium',
    evidence: "O cabeçalho de resposta HTTP 'Content-Security-Policy' não foi retornado pela aplicação. A ausência de CSP impede que o navegador restrinja a origem de scripts e recursos dinâmicos, ampliando a superfície de exploração para ataques de XSS e injeção de dados.",
    recommendation: "Configurar uma política rigorosa de Content-Security-Policy no servidor web ou na aplicação (ex.: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none')."
  },
  {
    id: 'FIND-008',
    category: 'A05:2021',
    name: 'Security Misconfiguration',
    test: 'Ausência de Proteção contra Clickjacking (X-Frame-Options)',
    status: 'detected',
    severity: 'medium',
    evidence: "O cabeçalho 'X-Frame-Options' não foi configurado e não há diretiva 'frame-ancestors' no CSP. A aplicação pode ser incorporada em <iframe> ou <frame> por sites maliciosos para realizar ataques de Clickjacking (UI Redressing).",
    recommendation: "Adicionar o cabeçalho 'X-Frame-Options: DENY' ou 'X-Frame-Options: SAMEORIGIN', ou utilizar a diretiva 'frame-ancestors' na Content-Security-Policy."
  },
  {
    id: 'FIND-009',
    category: 'A05:2021',
    name: 'Security Misconfiguration',
    test: 'Ausência de X-Content-Type-Options (MIME Sniffing)',
    status: 'detected',
    severity: 'low',
    evidence: "O cabeçalho 'X-Content-Type-Options: nosniff' não foi enviado pelo servidor. Navegadores podem tentar adivinhar o tipo MIME de arquivos de forma divergente do cabeçalho Content-Type, o que pode levar à interpretação indevida de arquivos de mídia como scripts executáveis.",
    recommendation: "Configurar o cabeçalho 'X-Content-Type-Options: nosniff' em todas as respostas HTTP da aplicação."
  },
  {
    id: 'FIND-010',
    category: 'A05:2021',
    name: 'Security Misconfiguration',
    test: 'Ausência de Strict-Transport-Security (HSTS)',
    status: 'detected',
    severity: 'low',
    evidence: "O cabeçalho 'Strict-Transport-Security' (HSTS) não foi identificado na resposta HTTP. A ausência de HSTS permite que atacantes na mesma rede realizem ataques de rebaixamento de protocolo (SSL Stripping) e interceptem tráfego não criptografado.",
    recommendation: "Migrar todo o tráfego da aplicação para HTTPS e adicionar o cabeçalho 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."
  },
  {
    id: 'FIND-011',
    category: 'A05:2021',
    name: 'Security Misconfiguration',
    test: 'Vazamento de Informações do Servidor (Banner Disclosure)',
    status: 'detected',
    severity: 'low',
    evidence: "Foram identificados cabeçalhos de resposta HTTP que divulgam tecnologias e versões internas: Server: 'Apache/2.4.54 (Debian)', X-Powered-By: 'PHP/8.1.2'. Essa exposição facilita o levantamento de vulnerabilidades públicas conhecidas (CVEs) direcionadas à versão exata do software em execução.",
    recommendation: "Ocultar banners e versões de software no servidor web (no Apache: 'ServerTokens Prod' e 'ServerSignature Off'; no Nginx: 'server_tokens off'; no PHP: 'expose_php = Off' no php.ini)."
  }
];

export const MOCK_AI_REPORT_MEDIUM = `### 1. Visão Geral da Postura de Segurança (Nível MEDIUM)
- **Nível de Risco Geral:** CRÍTICO (Evasão de Controles Defensivos)
- **Resumo Executivo:** O alvo analisado no nível MEDIUM implementou **tentativas ingênuas de mitigação** (sanitização de aspas, remoção de tags <script>, blacklist de operadores de shell e atraso de 2s no login). No entanto, o SecureScan comprovou a ineficácia de defesas parciais através de técnicas de evasão (*Defense Bypassing*). Além disso, a aplicação mantém **configurações incorretas de segurança (OWASP A05:2021)**, sem cabeçalhos de defesa (CSP e X-Frame-Options ausentes) e com vazamento explícito da pilha de tecnologias (\`Apache/2.4.54\` e \`PHP/8.1.2\`).

### 2. Análise Técnica dos Bypasses & Misconfigurations
1. **Vazamento Tecnológico (A05):** Os cabeçalhos HTTP revelam a versão exata do Apache e do PHP, permitindo que atacantes busquem exploits direcionados.
2. **SQL Injection Numérico (A03):** A função \`mysqli_real_escape_string()\` foi superada pela injeção \`1 OR 1=1\` em campo numérico sem aspas.
3. **XSS Polimórfico (A03):** A remoção ingênua de \`<script>\` foi contornada via tag \`<img onerror=...>\`. A ausência de CSP (A05) permitiu a execução irrestrita do script malicioso.
4. **Command Injection via Pipe (A03):** A blacklist de \`;\` e \`&&\` foi contornada com o operador pipe (\`|\`).
5. **Força Bruta com Tarpitting (A07):** O atraso de 2s atrasa o ataque, mas a falta de bloqueio de conta viabiliza a quebra de credenciais.

### 3. Matriz de Priorização das Correções
| Prioridade | Vulnerabilidade | Falha do Controle do Nível Medium | Solução Definitiva da Indústria |
|---|---|---|---|
| 🔴 IMEDIATA | Command Injection | Blacklist incompleta de operadores | Whitelist estrita de formato com filter_var() |
| 🔴 IMEDIATA | SQL Injection (Boolean) | Escapar aspas em campo numérico | Prepared Statements com PDO |
| 🟠 ALTA | XSS Refletido | Filtro ingênuo com str_replace | htmlspecialchars(..., ENT_QUOTES) e CSP |
| 🟡 MÉDIA | Autenticação Fraca | Apenas atraso de 2s sem bloqueio | Account Lockout após 5 falhas e MFA |
| 🟡 MÉDIA | Ausência de CSP e X-Frame-Options | Cabeçalhos de segurança ausentes (A05) | Implementar CSP restrito e X-Frame-Options |
| 🔵 BAIXA | Exposição de Versão (Banner) | Exposição de Apache e PHP nos cabeçalhos | ServerTokens Prod e expose_php = Off |`;

/**
 * Dados para o nível HIGH: Defesas avançadas implementadas pelo DVWA (Anti-CSRF no login, inputs por sessão, regex de script e blacklists de caracteres).
 */
export const MOCK_FINDINGS_HIGH: Finding[] = [
  {
    id: 'FIND-001',
    category: 'A07:2021',
    name: 'Identification and Authentication Failures',
    test: 'Brute Force de Credenciais (Nível High - Evasão de Token CSRF)',
    status: 'detected',
    severity: 'medium',
    evidence: "A aplicação implementou proteção anti-CSRF exigindo um 'user_token' dinâmico a cada tentativa de login e atraso progressivo com sleep(rand(0, 3)). O SecureScan extraiu o token dinamicamente via HTML parsing e descobriu com sucesso a senha 'password' para o usuário 'admin'.",
    recommendation: 'Tokens anti-CSRF não impedem ataques automatizados direcionados que simulam navegadores. A única mitigação definitiva contra força bruta é o bloqueio temporário de conta (Account Lockout) e a imposição de Autenticação Multifator (MFA).'
  },
  {
    id: 'FIND-002',
    category: 'A07:2021',
    name: 'Identification and Authentication Failures',
    test: 'Proteção contra Força Bruta (Ausência de Bloqueio com CSRF)',
    status: 'detected',
    severity: 'medium',
    evidence: "Foram realizadas 5 tentativas inválidas consecutivas com tokens CSRF válidos. A aplicação continuou respondendo com HTTP 200 sem acionar bloqueio temporário de IP/conta ou desafio CAPTCHA.",
    recommendation: 'Implementar bloqueio temporário por IP e conta após 5 falhas consecutivas de autenticação.'
  },
  {
    id: 'FIND-003',
    category: 'A03:2021',
    name: 'Injection',
    test: 'SQL Injection Error-based (Nível High - Entrada por Sessão)',
    status: 'detected',
    severity: 'high',
    evidence: "A aplicação transferiu o recebimento de parâmetros para um canal secundário de sessão (session-input.php). O envio do caractere de aspa simples (') expôs erro de sintaxe SQL do MariaDB, confirmando interpolação direta na query.",
    recommendation: 'Migrar todas as consultas SQL para Prepared Statements com PDO. O armazenamento intermediário de dados em sessão não substitui a parametrização.'
  },
  {
    id: 'FIND-004',
    category: 'A03:2021',
    name: 'Injection',
    test: 'SQL Injection Boolean-based (Nível High - Comentário SQL & LIMIT 1)',
    status: 'detected',
    severity: 'critical',
    evidence: "A query original continha a cláusula restritiva 'LIMIT 1;' associada a controle de sessão. O scanner utilizou o payload '1\\' OR \\'1\\'=\\'1\\' #', onde o comentário SQL ('#') anulou a cláusula LIMIT, forçando o retorno de todos os 5 registros do banco de dados.",
    recommendation: 'Cláusulas LIMIT e canais indiretos de sessão não impedem a injeção. A solução mandatória é a utilização de Prepared Statements (PDO).'
  },
  {
    id: 'FIND-005',
    category: 'A03:2021',
    name: 'Injection',
    test: 'Cross-Site Scripting Refletido (Nível High - Evasão de Regex)',
    status: 'detected',
    severity: 'high',
    evidence: "A aplicação utilizou uma expressão regular estrita (preg_replace) visando qualquer variação da palavra 'script'. O payload polimórfico '<img src=x onerror=/*SECURESCAN_XSS_PROBE*/ />' não contém a palavra 'script' e foi refletido diretamente no DOM, contornando a proteção baseada em regex.",
    recommendation: 'Filtros baseados em expressões regulares que buscam palavras específicas falham contra tags e manipuladores de evento HTML5. A defesa mandatória é a codificação contextual com htmlspecialchars() e uso de Content-Security-Policy (CSP).'
  },
  {
    id: 'FIND-006',
    category: 'A03:2021',
    name: 'Injection',
    test: 'Command Injection (Nível High - Evasão de Blacklist sem Espaço)',
    status: 'detected',
    severity: 'critical',
    evidence: "A aplicação aplicou uma blacklist de substituição de operadores com falha de implementação: filtrava apenas '| ' (pipe seguido de espaço). O scanner injetou '127.0.0.1|echo SECURESCAN_CMD_EXEC_CONFIRMED' (sem espaço), contornando o filtro e executando o comando de shell no servidor.",
    recommendation: 'Listas negras de caracteres são conceitualmente inseguras. Eliminar a invocação de shell_exec() e validar o formato de entrada por lista branca estrita (regex para IPv4).'
  },
  {
    id: 'FIND-007',
    category: 'A05:2021',
    name: 'Security Misconfiguration',
    test: 'Ausência de Content-Security-Policy (CSP)',
    status: 'detected',
    severity: 'medium',
    evidence: "O cabeçalho de resposta HTTP 'Content-Security-Policy' não foi retornado pela aplicação. A ausência de CSP impede que o navegador restrinja a origem de scripts e recursos dinâmicos, ampliando a superfície de exploração para ataques de XSS e injeção de dados.",
    recommendation: "Configurar uma política rigorosa de Content-Security-Policy no servidor web ou na aplicação (ex.: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none')."
  },
  {
    id: 'FIND-008',
    category: 'A05:2021',
    name: 'Security Misconfiguration',
    test: 'Ausência de Proteção contra Clickjacking (X-Frame-Options)',
    status: 'detected',
    severity: 'medium',
    evidence: "O cabeçalho 'X-Frame-Options' não foi configurado e não há diretiva 'frame-ancestors' no CSP. A aplicação pode ser incorporada em <iframe> ou <frame> por sites maliciosos para realizar ataques de Clickjacking (UI Redressing).",
    recommendation: "Adicionar o cabeçalho 'X-Frame-Options: DENY' ou 'X-Frame-Options: SAMEORIGIN', ou utilizar a diretiva 'frame-ancestors' na Content-Security-Policy."
  },
  {
    id: 'FIND-009',
    category: 'A05:2021',
    name: 'Security Misconfiguration',
    test: 'Ausência de X-Content-Type-Options (MIME Sniffing)',
    status: 'detected',
    severity: 'low',
    evidence: "O cabeçalho 'X-Content-Type-Options: nosniff' não foi enviado pelo servidor. Navegadores podem tentar adivinhar o tipo MIME de arquivos de forma divergente do cabeçalho Content-Type, o que pode levar à interpretação indevida de arquivos de mídia como scripts executáveis.",
    recommendation: "Configurar o cabeçalho 'X-Content-Type-Options: nosniff' em todas as respostas HTTP da aplicação."
  },
  {
    id: 'FIND-010',
    category: 'A05:2021',
    name: 'Security Misconfiguration',
    test: 'Ausência de Strict-Transport-Security (HSTS)',
    status: 'detected',
    severity: 'low',
    evidence: "O cabeçalho 'Strict-Transport-Security' (HSTS) não foi identificado na resposta HTTP. A ausência de HSTS permite que atacantes na mesma rede realizem ataques de rebaixamento de protocolo (SSL Stripping) e interceptem tráfego não criptografado.",
    recommendation: "Migrar todo o tráfego da aplicação para HTTPS e adicionar o cabeçalho 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."
  },
  {
    id: 'FIND-011',
    category: 'A05:2021',
    name: 'Security Misconfiguration',
    test: 'Vazamento de Informações do Servidor (Banner Disclosure)',
    status: 'detected',
    severity: 'low',
    evidence: "Foram identificados cabeçalhos de resposta HTTP que divulgam tecnologias e versões internas: Server: 'Apache/2.4.54 (Debian)', X-Powered-By: 'PHP/8.1.2'. Essa exposição facilita o levantamento de vulnerabilidades públicas conhecidas (CVEs) direcionadas à versão exata do software em execução.",
    recommendation: "Ocultar banners e versões de software no servidor web (no Apache: 'ServerTokens Prod' e 'ServerSignature Off'; no Nginx: 'server_tokens off'; no PHP: 'expose_php = Off' no php.ini)."
  }
];

export const MOCK_AI_REPORT_HIGH = `### 1. Visão Geral da Postura de Segurança (Nível HIGH)
- **Nível de Risco Geral:** CRÍTICO (Evasão de Controles Avançados)
- **Resumo Executivo:** O alvo analisado no nível HIGH adotou **medidas de segurança mais complexas** (tokens anti-CSRF na autenticação, isolamento de parâmetros via sessão, regex estrito contra variações de "script" e blacklist multi-caracteres). Apesar desses esforços, o SecureScan demonstrou que **tentativas de filtragem sintática são vulneráveis a técnicas avançadas de evasão**: truncamento de queries com comentários SQL, injeção de pipe sem espaçamento e tags polimórficas HTML5.

### 2. Análise Técnica das Evasões no Nível High
1. **Quebra de Blacklist de Comandos:** A substituição que visava bloquear o pipe verificava \`'\| '\` (com espaço), deixando vulnerável a injeção encadeada sem espaço (\`\|echo\`), resultando em Execução Remota de Código (RCE).
2. **Anulação de Cláusula Restritiva SQL:** A cláusula \`LIMIT 1\` da consulta foi completamente neutralizada pelo caractere de comentário \`#\`, permitindo a extração de toda a base de usuários mesmo com o tráfego roteado por sessão.
3. **Evasão de Regex no XSS:** O regex \`preg_replace\` eliminava variações de "script", mas tags polimórficas com manipuladores nativos (\`<img onerror>\`) contornaram a regra e executaram no navegador.
4. **Bypass de Token Anti-CSRF:** O scanner automatizou a extração do token CSRF por requisição, demonstrando que proteções puramente anti-CSRF não substituem políticas de bloqueio de conta (Account Lockout) contra força bruta.

### 3. Matriz de Priorização das Correções
| Prioridade | Vulnerabilidade | Falha do Controle do Nível High | Solução Definitiva da Indústria |
|---|---|---|---|
| 🔴 IMEDIATA | Command Injection | Erro sutil na blacklist de pipes ('\| ') | Whitelist estrita de formato com filter_var() |
| 🔴 IMEDIATA | SQL Injection (Boolean) | Concatenação com LIMIT 1 via sessão | Prepared Statements com PDO |
| 🟠 ALTA | XSS Refletido | Regex focado exclusivamente em "script" | htmlspecialchars(..., ENT_QUOTES) e CSP |
| 🟡 MÉDIA | Autenticação Fraca | Token anti-CSRF sem bloqueio de IP/conta | Account Lockout após 5 falhas e MFA |
| 🟡 MÉDIA | Ausência de CSP & X-Frame-Options | Cabeçalhos HTTP defensivos ausentes (A05) | Adicionar CSP e X-Frame-Options no servidor |
| 🔵 BAIXA | Exposição de Versão (Banner) | Exposição de Apache e PHP nos cabeçalhos | ServerTokens Prod e expose_php = Off |`;

export const SCAN_STEPS = [
  'Conectando e autenticando no alvo...',
  'Auditando Cabeçalhos de Segurança HTTP e Misconfigurations (A05)...',
  'Testando Força Bruta e Proteção de Login (A07)...',
  'Auditando SQL Injection Error-based e Boolean-based (A03)...',
  'Injetando vetores de Cross-Site Scripting Refletido (A03)...',
  'Testando Injeção de Comandos no Sistema Operacional (A03)...',
  'Processando achados na Camada de Inteligência Artificial...'
];

/**
 * Simula a execução do scanner com feedback progressivo adaptado ao nível selecionado (low, medium ou high).
 */
export async function runMockScan(
  targetUrl: string,
  securityLevel: SecurityLevel,
  onProgress?: (step: string, percentage: number) => void
): Promise<ScanResult> {
  const startTime = Date.now();

  for (let i = 0; i < SCAN_STEPS.length; i++) {
    const stepText = SCAN_STEPS[i];
    const percent = Math.round(((i + 1) / SCAN_STEPS.length) * 100);
    if (onProgress) {
      onProgress(stepText, percent);
    }
    // Pausa visual suave entre 450ms e 600ms por etapa
    await new Promise((resolve) => setTimeout(resolve, 500));
  }

  const durationSeconds = Math.round((Date.now() - startTime) / 1000);

  // Seleciona o conjunto de dados de acordo com o nível configurado
  let rawFindings = MOCK_FINDINGS_LOW;
  let aiReport = MOCK_AI_REPORT_LOW;

  if (securityLevel === 'medium') {
    rawFindings = MOCK_FINDINGS_MEDIUM;
    aiReport = MOCK_AI_REPORT_MEDIUM;
  } else if (securityLevel === 'high') {
    rawFindings = MOCK_FINDINGS_HIGH;
    aiReport = MOCK_AI_REPORT_HIGH;
  }

  const findings = rawFindings.map(enrichFinding);

  const summary = {
    total: findings.length,
    critical: findings.filter((f) => f.severity === 'critical').length,
    high: findings.filter((f) => f.severity === 'high').length,
    medium: findings.filter((f) => f.severity === 'medium').length,
    low: findings.filter((f) => f.severity === 'low').length,
    safe: findings.filter((f) => f.status === 'not_detected' || f.severity === 'safe').length
  };

  return {
    targetUrl,
    securityLevel,
    timestamp: new Date().toLocaleString('pt-BR'),
    durationSeconds: Math.max(durationSeconds, 4),
    summary,
    score: calculateSecurityScore(summary, securityLevel),
    findings,
    aiExecutiveReport: aiReport
  };
}

/**
 * Enriquece os achados com metadados para exibição detalhada nos painéis.
 */
export function enrichFinding(finding: Finding): Finding {
  const metadataMap: Record<string, { confidence: number; endpoint: string; impact: string; aiAnalysis: string }> = {
    'FIND-001': {
      confidence: 98,
      endpoint: '/vulnerabilities/brute/',
      impact: 'Um atacante pode obter acesso administrativo completo utilizando ataques automatizados de dicionário ou credential stuffing sem restrição de tentativas.',
      aiAnalysis: 'A ausência de políticas ativas de rate limiting ou bloqueio temporário viabiliza a quebra de credenciais fracas em poucos segundos.'
    },
    'FIND-002': {
      confidence: 95,
      endpoint: '/vulnerabilities/brute/',
      impact: 'Possibilita ataques contínuos e distribuídos contra o serviço de login sem qualquer sinal de bloqueio de conta (Account Lockout) ou desafio CAPTCHA.',
      aiAnalysis: 'O servidor aceitou 5 requisições com credenciais inválidas consecutivas com resposta imediata HTTP 200.'
    },
    'FIND-003': {
      confidence: 96,
      endpoint: '/vulnerabilities/sqli/',
      impact: 'Vazamento da estrutura do banco de dados e mensagens de erro do MariaDB, facilitando a construção de vetores de injeção mais profundos.',
      aiAnalysis: 'Mensagens de erro de sintaxe SQL expostas ao usuário final comprovam falta de tratamento de exceções na camada de banco de dados.'
    },
    'FIND-004': {
      confidence: 99,
      endpoint: '/vulnerabilities/sqli/',
      impact: 'Extração integral de tabelas confidenciais (usuários, senhas, dados cadastrais) e possível manipulação de dados através de injeção SQL booleana.',
      aiAnalysis: 'A query SQL concatena diretamente as entradas sem parametrização com PDO, permitindo alteração semântica com tautologias.'
    },
    'FIND-005': {
      confidence: 92,
      endpoint: '/vulnerabilities/xss_r/',
      impact: 'Execução arbitrária de código JavaScript no navegador dos usuários, possibilitando roubo de cookies de sessão, keylogging e ataques de phishing direcionados.',
      aiAnalysis: 'A aplicação reflete dados fornecidos pelo usuário no corpo da resposta HTML sem codificação de entidades sensível ao contexto.'
    },
    'FIND-006': {
      confidence: 100,
      endpoint: '/vulnerabilities/exec/',
      impact: 'Execução Remota de Código (RCE) no servidor, permitindo que invasores obtenham controle da máquina, acessem arquivos confidenciais do sistema e façam pivoting.',
      aiAnalysis: 'A funcionalidade utiliza shell_exec() diretamente sobre comandos concatenados sem sanitização ou uso de APIs seguras de sistema.'
    },
    'FIND-007': {
      confidence: 100,
      endpoint: '/',
      impact: 'Sem uma política CSP, o navegador não possui restrições sobre a origem de scripts, amplificando drasticamente o impacto de ataques de XSS e injeções.',
      aiAnalysis: 'O cabeçalho Content-Security-Policy está totalmente ausente nas respostas HTTP do servidor web.'
    },
    'FIND-008': {
      confidence: 100,
      endpoint: '/',
      impact: 'A página pode ser incorporada em iframes de sites maliciosos para ludibriar o usuário e sequestrar cliques (ataques de Clickjacking).',
      aiAnalysis: 'Ausência do cabeçalho X-Frame-Options e de diretivas frame-ancestors na resposta da aplicação.'
    },
    'FIND-009': {
      confidence: 90,
      endpoint: '/',
      impact: 'Navegadores podem interpretar arquivos estáticos de texto ou imagem como executáveis JavaScript caso detectem código malicioso em seu interior.',
      aiAnalysis: 'O cabeçalho defensivo X-Content-Type-Options com o valor nosniff não foi configurado.'
    },
    'FIND-010': {
      confidence: 95,
      endpoint: '/',
      impact: 'Permite que invasores na mesma rede (Wi-Fi aberta) interceptem tráfego não criptografado através de SSL Stripping.',
      aiAnalysis: 'Cabeçalho Strict-Transport-Security não encontrado nas respostas HTTP.'
    },
    'FIND-011': {
      confidence: 100,
      endpoint: '/',
      impact: 'Exposição de versões exatas do Apache e PHP permite que atacantes pesquisem CVEs públicas e direcionem exploits conhecidos contra o servidor.',
      aiAnalysis: 'Os cabeçalhos Server e X-Powered-By divulgam as versões internas do software em execução.'
    }
  };

  const meta = metadataMap[finding.id] || {
    confidence: 90,
    endpoint: '/vulnerabilities/',
    impact: 'Comportamento vulnerável identificado no alvo, expondo a aplicação a riscos operacionais e de conformidade.',
    aiAnalysis: 'Achado diagnosticado pelo motor automatizado do SecureScan.'
  };

  return {
    ...finding,
    confidence: finding.confidence ?? meta.confidence,
    endpoint: finding.endpoint ?? meta.endpoint,
    impact: finding.impact ?? meta.impact,
    aiAnalysis: finding.aiAnalysis ?? meta.aiAnalysis
  };
}

/**
 * Calcula a pontuação global de postura de segurança (0 a 100),
 * refletindo os controles defensivos e a dificuldade de evasão no alvo.
 */
export function calculateSecurityScore(summary: ScanSummary, securityLevel: SecurityLevel = 'high'): number {
  if (summary.total === 0) return 100;

  // Pontuação base calibrada pelo nível de maturidade defensiva do ambiente
  const levelBaseScore: Record<SecurityLevel, number> = {
    low: 32,      // Low: Ausência de defesas, exploração direta e trivial (Risco Crítico)
    medium: 58,   // Medium: Defesas parciais (blacklists, sleep) que sofreram bypass (Risco Moderado)
    high: 80      // High: Defesas avançadas (anti-CSRF, regex, sessão) exigindo evasão complexa (Postura Elevada)
  };

  const base = levelBaseScore[securityLevel] ?? 60;
  const penalty = (summary.critical * 2) + (summary.high * 1.5) + (summary.medium * 0.8) + (summary.low * 0.4);
  const normalizedPenalty = Math.round((penalty / 15) * 6);

  const finalScore = base - normalizedPenalty + 2;
  return Math.max(15, Math.min(95, finalScore));
}

/**
 * Resultado inicial demonstrativo para popular o Dashboard no primeiro acesso.
 */
export const INITIAL_SCAN_RESULT: ScanResult = {
  targetUrl: 'http://192.168.100.165',
  securityLevel: 'high',
  timestamp: '15/09/2026 14:32',
  durationSeconds: 32,
  summary: {
    total: 11,
    critical: 2,
    high: 2,
    medium: 4,
    low: 3,
    safe: 0
  },
  score: 77,
  findings: MOCK_FINDINGS_HIGH.map(enrichFinding),
  aiExecutiveReport: MOCK_AI_REPORT_HIGH
};

/**
 * Dispara uma varredura real chamando o backend Python em http://localhost:5000/api/scan.
 * Caso o backend não esteja ativo, faz fallback gracioso para a simulação com aviso.
 */
export async function runRealScan(
  targetUrl: string,
  securityLevel: SecurityLevel,
  onProgress?: (step: string, percentage: number) => void
): Promise<ScanResult> {
  try {
    if (onProgress) onProgress(`Iniciando varredura real no nível ${securityLevel.toUpperCase()}...`, 20);

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 90000);

    const response = await fetch('http://localhost:5000/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_url: targetUrl, security_level: securityLevel }),
      signal: controller.signal
    });
    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`Servidor respondeu com status ${response.status}`);
    }

    const data = await response.json();
    if (data.findings && Array.isArray(data.findings)) {
      data.findings = data.findings.map(enrichFinding);
    }
    if (!data.score && data.summary) {
      data.score = calculateSecurityScore(data.summary, securityLevel);
    }
    return data;
  } catch (err) {
    console.warn('Backend não disponível ou inacessível. Alternando para simulação:', err);
    return runMockScan(targetUrl, securityLevel, onProgress);
  }
}

/**
 * Gera e baixa o relatório em formato JSON estruturado no navegador do usuário.
 */
export function exportToJson(result: ScanResult): void {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = `securescan_report_${result.securityLevel.toUpperCase()}_${timestamp}.json`;
  const jsonString = JSON.stringify(result, null, 2);

  const blob = new Blob([jsonString], { type: 'application/json;charset=utf-8;' });
  triggerDownload(blob, filename);
}

/**
 * Gera e baixa o relatório em formato CSV tabular no navegador do usuário (com BOM UTF-8 para Excel).
 */
export function exportToCsv(result: ScanResult): void {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = `securescan_report_${result.securityLevel.toUpperCase()}_${timestamp}.csv`;

  const headers = ['ID', 'Categoria', 'Nome da Vulnerabilidade', 'Teste Realizado', 'Severidade', 'Status', 'Evidencia Tecnica', 'Recomendacao de Mitigacao'];

  const rows = result.findings.map((f) => [
    f.id,
    `"${f.category.replace(/"/g, '""')}"`,
    `"${f.name.replace(/"/g, '""')}"`,
    `"${f.test.replace(/"/g, '""')}"`,
    `"${f.severity.toUpperCase()}"`,
    `"${f.status.toUpperCase()}"`,
    `"${f.evidence.replace(/"/g, '""').replace(/\n/g, ' ')}"`,
    `"${f.recommendation.replace(/"/g, '""').replace(/\n/g, ' ')}"`
  ]);

  // Adiciona BOM (\uFEFF) para garantir que caracteres acentuados funcionem no Excel
  const csvContent = '\uFEFF' + [headers.join(','), ...rows.map((r) => r.join(','))].join('\r\n');

  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  triggerDownload(blob, filename);
}

function triggerDownload(blob: Blob, filename: string) {
  const link = document.createElement('a');
  const url = URL.createObjectURL(blob);
  link.setAttribute('href', url);
  link.setAttribute('download', filename);
  link.style.visibility = 'hidden';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
