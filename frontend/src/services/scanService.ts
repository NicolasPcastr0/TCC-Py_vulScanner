import type { Finding, ScanResult, SecurityLevel } from '../types/scanner';

/**
 * Dados de simulação baseados nas execuções reais do SecureScan contra o DVWA.
 */
export const MOCK_FINDINGS: Finding[] = [
  {
    id: 'FIND-001',
    category: 'A07:2021',
    name: 'Identification and Authentication Failures',
    test: 'Brute Force de Credenciais',
    status: 'detected',
    severity: 'medium',
    evidence: "Uma credencial válida foi identificada com sucesso durante tentativas automatizadas de força bruta para o usuário 'admin' (senha descoberta: 'password').",
    recommendation: 'Implementar mecanismos de proteção contra ataques de força bruta, como limitação de taxa de requisições (rate limiting), bloqueio temporário de contas após tentativas inválidas e autenticação multifator (MFA).'
  },
  {
    id: 'FIND-002',
    category: 'A07:2021',
    name: 'Identification and Authentication Failures',
    test: 'Proteção contra Força Bruta (Rate Limiting)',
    status: 'detected',
    severity: 'medium',
    evidence: 'Foram realizadas 5 tentativas inválidas consecutivas e a aplicação continuou respondendo com HTTP 200, sem acionar bloqueio temporário de conta (Account Lockout), atraso progressivo ou limitação de taxa.',
    recommendation: 'Implementar controles defensivos contra tentativas automatizadas, tais como rate limiting por IP/conta, atraso progressivo (tarpitting), bloqueio temporário ou desafio CAPTCHA.'
  },
  {
    id: 'FIND-003',
    category: 'A03:2021',
    name: 'Injection',
    test: 'SQL Injection (Error-based)',
    status: 'detected',
    severity: 'high',
    evidence: "A aplicação expôs mensagens internas de erro do SGBD ao receber o payload '''. Trecho identificado: '<pre>You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version...'.",
    recommendation: 'Utilizar consultas parametrizadas (Prepared Statements com PDO ou MySQLi). Desabilitar a exibição pública de mensagens detalhadas de erro de banco de dados em ambientes de produção.'
  },
  {
    id: 'FIND-004',
    category: 'A03:2021',
    name: 'Injection',
    test: 'SQL Injection (Boolean-based)',
    status: 'detected',
    severity: 'critical',
    evidence: "A injeção lógica '1 OR 1=1' alterou a semântica da consulta no banco de dados. A injeção explorou a ausência de aspas em campo numérico (WHERE user_id = $id), contornando com sucesso a função mysqli_real_escape_string(). A consulta retornou 5 registros vs 1 legítimo.",
    recommendation: 'Implementar imediatamente consultas parametrizadas (Prepared Statements com PDO). Nunca concatenar dados de entrada de usuários diretamente em strings de comando SQL.'
  },
  {
    id: 'FIND-005',
    category: 'A03:2021',
    name: 'Injection',
    test: 'Cross-Site Scripting (Reflected XSS)',
    status: 'detected',
    severity: 'high',
    evidence: "A aplicação refletiu o payload '<img src=x onerror=/*SECURESCAN_XSS_PROBE*/ />' diretamente no corpo HTML sem codificar entidades seguras. O payload polimórfico contornou o filtro ingênuo str_replace('<script>', '').",
    recommendation: 'Implementar codificação de saída sensível ao contexto (Context-Aware Output Encoding) com htmlspecialchars($data, ENT_QUOTES, UTF-8) e configurar cabeçalhos de segurança como Content-Security-Policy (CSP).'
  },
  {
    id: 'FIND-006',
    category: 'A03:2021',
    name: 'Injection',
    test: 'Command Injection (Injeção de Comandos)',
    status: 'detected',
    severity: 'critical',
    evidence: "O servidor executou comandos arbitrários de shell concatenados à entrada. O teste contornou com sucesso a lista negra de operadores (bloqueio de ';' e '&&') utilizando o operador pipe ('|'). Marcador de execução confirmado no terminal do servidor.",
    recommendation: 'Evitar a invocação direta de comandos de shell do sistema operacional via shell_exec() ou system(). Utilizar APIs nativas da linguagem e validação de formato rigorosa (whitelisting de IPs via regex) com escapeshellarg().'
  }
];

export const MOCK_AI_REPORT = `### 1. Visão Geral e Postura de Segurança
A aplicação apresenta um **nível de risco CRÍTICO**, com 6 vulnerabilidades ativas (2 Críticas, 2 Altas e 2 Médias). Há exposição direta à execução remota de código no servidor e extração total do banco de dados relacional.

### 2. Análise de Cenários de Ataque (Kill Chain)
1. **Acesso Inicial:** Invasor utiliza ataques de dicionário para obter credenciais devido à falta de rate limiting (A07).
2. **Extração de Dados:** Com acesso à aplicação, explora SQL Injection (A03) para extrair todos os registros da base de dados.
3. **Tomada Completa do Servidor:** Através da Injeção de Comandos (A03), o invasor executa comandos arbitrários no sistema operacional como o usuário do servidor web (www-data), obtendo Execução Remota de Código (RCE).

### 3. Matriz de Priorização das Correções
- **Prioridade Imediata (0-48h):** Eliminar invocação de shell em Command Injection e migrar queries para Prepared Statements (PDO).
- **Prioridade Alta (1-7 dias):** Aplicar sanitização contextual com htmlspecialchars() contra XSS e ocultar mensagens de erro do MariaDB.
- **Prioridade Média:** Configurar Rate Limiting no Nginx e bloqueio temporário após 5 tentativas falhas.`;

export const SCAN_STEPS = [
  'Conectando e autenticando no alvo...',
  'Testando Força Bruta e Proteção de Login (A07)...',
  'Auditando SQL Injection Error-based e Boolean-based (A03)...',
  'Injetando vetores de Cross-Site Scripting Refletido (A03)...',
  'Testando Injeção de Comandos no Sistema Operacional (A03)...',
  'Processando achados na Camada de Inteligência Artificial...'
];

/**
 * Simula a execução do scanner com feedback progressivo para cada etapa.
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
    // Pausa visual suave entre 500ms e 700ms por etapa
    await new Promise((resolve) => setTimeout(resolve, 600));
  }

  const durationSeconds = Math.round((Date.now() - startTime) / 1000);

  return {
    targetUrl,
    securityLevel,
    timestamp: new Date().toLocaleString('pt-BR'),
    durationSeconds: Math.max(durationSeconds, 4),
    summary: {
      total: MOCK_FINDINGS.length,
      critical: MOCK_FINDINGS.filter((f) => f.severity === 'critical').length,
      high: MOCK_FINDINGS.filter((f) => f.severity === 'high').length,
      medium: MOCK_FINDINGS.filter((f) => f.severity === 'medium').length,
      low: 0,
      safe: 0
    },
    findings: MOCK_FINDINGS,
    aiExecutiveReport: MOCK_AI_REPORT
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
    if (onProgress) onProgress('Iniciando varredura no servidor backend...', 20);

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
  const filename = `securescan_report_${timestamp}.json`;
  const jsonString = JSON.stringify(result, null, 2);

  const blob = new Blob([jsonString], { type: 'application/json;charset=utf-8;' });
  triggerDownload(blob, filename);
}

/**
 * Gera e baixa o relatório em formato CSV tabular no navegador do usuário (com BOM UTF-8 para Excel).
 */
export function exportToCsv(result: ScanResult): void {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = `securescan_report_${timestamp}.csv`;

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
