import type { Finding, ScanResult, SecurityLevel } from '../types/scanner';

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
  }
];

export const MOCK_AI_REPORT_LOW = `### 1. Visão Geral da Postura de Segurança (Nível LOW)
- **Nível de Risco Geral:** CRÍTICO
- **Resumo Executivo:** O alvo analisado no nível LOW apresenta **ausência total de controles defensivos**. Todas as 6 verificações foram positivas para exploração direta e sem atrito. A aplicação é vulnerável a Execução Remota de Código (RCE), extração irrestrita de dados via SQLi e sequestro de sessão via XSS direto.

### 2. Cenário de Encadeamento de Ataque (Kill Chain)
1. **Reconhecimento & Acesso:** A ausência de rate limiting permite que o atacante descubra credenciais administrativas em poucos segundos.
2. **Exfiltração de Dados:** Com uma injeção SQL trivial baseada em aspas no parâmetro GET (1' OR '1'='1), o atacante extrai a tabela completa de usuários e hashes.
3. **Comprometimento Integral do Servidor:** Injetando comandos diretos através de ';' na funcionalidade de rede, o invasor obtém shell interativo no servidor sob o privilégio do usuário web (www-data).

### 3. Matriz de Priorização das Correções
| Prioridade | Vulnerabilidade | Causa Raiz | Ação Recomendada |
|---|---|---|---|
| 🔴 IMEDIATA | Command Injection | Concatenação direta em shell_exec() | Substituir por funções nativas e validação de IP |
| 🔴 IMEDIATA | SQL Injection (Boolean & Error) | Concatenação de string na query | Migrar para Prepared Statements (PDO) |
| 🟠 ALTA | XSS Refletido | Falta de escape de caracteres HTML | Aplicar htmlspecialchars(..., ENT_QUOTES) |
| 🟡 MÉDIA | Falhas de Autenticação | Sem limitação de tentativas de login | Implementar Rate Limiting e MFA |`;

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
  }
];

export const MOCK_AI_REPORT_MEDIUM = `### 1. Visão Geral da Postura de Segurança (Nível MEDIUM)
- **Nível de Risco Geral:** CRÍTICO (Evasão de Controles Defensivos)
- **Resumo Executivo:** O alvo analisado no nível MEDIUM implementou **tentativas ingênuas de mitigação** (sanitização de aspas, remoção de tags <script>, blacklist de operadores de shell e atraso de 2s no login). No entanto, o SecureScan comprovou a **ineficácia de defesas parciais**, contornando todas as proteções através de técnicas de evasão (*Defense Bypassing*).

### 2. Análise Técnica dos Bypasses Identificados
1. **SQL Injection Numérico:** A função \`mysqli_real_escape_string()\` escapa apenas aspas, mas a consulta SQL utilizava \`WHERE user_id = $id\` (sem aspas). A injeção \`1 OR 1=1\` passou intacta pelo filtro.
2. **XSS Polimórfico:** A função \`str_replace('<script>', '', $name)\` foi superada utilizando vetores baseados em manipuladores de eventos em tags de imagem (\`<img onerror=...>\`).
3. **Command Injection via Pipe:** A blacklist que bloqueava \`;\` e \`&&\` esqueceu o operador \`|\` (pipe), permitindo a execução de comandos encadeados no terminal.
4. **Força Bruta com Tarpitting:** O atraso de 2 segundos atrasa o ataque, mas a falta de bloqueio de conta permite que a senha correta seja eventualmente descoberta.

### 3. Matriz de Priorização das Correções
| Prioridade | Vulnerabilidade | Falha do Controle do Nível Medium | Solução Definitiva da Indústria |
|---|---|---|---|
| 🔴 IMEDIATA | Command Injection | Blacklist incompleta de operadores | Whitelist estrita de formato com filter_var() |
| 🔴 IMEDIATA | SQL Injection (Boolean) | Escapar aspas em campo numérico | Prepared Statements com PDO |
| 🟠 ALTA | XSS Refletido | Filtro ingênuo com str_replace | htmlspecialchars(..., ENT_QUOTES) e CSP |
| 🟡 MÉDIA | Autenticação Fraca | Apenas atraso de 2s sem bloqueio | Account Lockout após 5 falhas e MFA |`;

export const SCAN_STEPS = [
  'Conectando e autenticando no alvo...',
  'Testando Força Bruta e Proteção de Login (A07)...',
  'Auditando SQL Injection Error-based e Boolean-based (A03)...',
  'Injetando vetores de Cross-Site Scripting Refletido (A03)...',
  'Testando Injeção de Comandos no Sistema Operacional (A03)...',
  'Processando achados na Camada de Inteligência Artificial...'
];

/**
 * Simula a execução do scanner com feedback progressivo adaptado ao nível selecionado (low ou medium).
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
    await new Promise((resolve) => setTimeout(resolve, 550));
  }

  const durationSeconds = Math.round((Date.now() - startTime) / 1000);

  // Seleciona o conjunto de dados de acordo com o nível configurado
  const isMedium = securityLevel === 'medium';
  const findings = isMedium ? MOCK_FINDINGS_MEDIUM : MOCK_FINDINGS_LOW;
  const aiReport = isMedium ? MOCK_AI_REPORT_MEDIUM : MOCK_AI_REPORT_LOW;

  return {
    targetUrl,
    securityLevel,
    timestamp: new Date().toLocaleString('pt-BR'),
    durationSeconds: Math.max(durationSeconds, 4),
    summary: {
      total: findings.length,
      critical: findings.filter((f) => f.severity === 'critical').length,
      high: findings.filter((f) => f.severity === 'high').length,
      medium: findings.filter((f) => f.severity === 'medium').length,
      low: 0,
      safe: 0
    },
    findings,
    aiExecutiveReport: aiReport
  };
}

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
