from scanner.core.finding import Finding


SYSTEM_PROMPT = """Você é um Consultor Sênior Especialista em Segurança de Aplicações Web (AppSec) e Engenharia de Software.
Sua missão é analisar os achados de vulnerabilidades (Findings) coletados de forma determinística pelo scanner de segurança SecureScan e produzir um relatório técnico e executivo completo, didático e acionável.

Diretrizes de resposta:
- Utilize linguagem clara, formal e profissional (em Português do Brasil).
- Evite jargões desnecessários na visão executiva, mas seja tecnicamente rigoroso no guia de remediação.
- Não invente vulnerabilidades além das que foram fornecidas na lista de achados.
- Estruture a resposta exatamente nas 4 seções solicitadas."""


def build_interpretation_prompt(findings: list[Finding]) -> str:
    """
    Constrói o prompt de contexto e análise a partir da lista de Findings do scanner.
    """
    if not findings:
        return "Nenhuma vulnerabilidade foi identificada durante o scan."

    findings_text = ""
    for idx, f in enumerate(findings, start=1):
        findings_text += f"""
--- ACHADO {idx} ---
- Categoria OWASP: {f.category}
- Nome: {f.name}
- Teste Realizado: {f.test}
- Status: {f.status.upper()}
- Severidade: {f.severity.upper()}
- Evidência Coletada: {f.evidence}
- Recomendação do Scanner: {f.recommendation}
"""

    prompt = f"""Analise os seguintes achados de segurança coletados pelo SecureScan em uma aplicação web:

{findings_text}

Com base estritamente nesses achados, elabore um relatório estruturado em formato Markdown contendo as seguintes seções:

### 1. Visão Geral e Postura de Segurança
- Avaliação geral do nível de risco da aplicação (Crítico, Alto, Médio ou Baixo).
- Resumo executivo em linguagem acessível para gestores e partes interessadas não técnicas, explicando o estado geral de segurança.

### 2. Análise de Cenários de Ataque e Impacto de Negócio
- Como um invasor real poderia encadear ou explorar essas falhas na prática.
- Impactos diretos para a organização (ex.: vazamento de dados, perda de integridade, sequestro de servidor, indisponibilidade).

### 3. Guia Técnico de Remediação com Exemplos de Código
- Para cada tipo de falha detectada, forneça a solução técnica recomendada com exemplos práticos de código seguro (ex: consultas preparadas em PHP/PDO, codificação de saída contra XSS, sanitização e eliminação de chamadas diretas de shell para injeção de comandos, implementação de rate limiting).

### 4. Matriz de Priorização das Correções
- Uma tabela com o que a equipe de desenvolvimento deve corrigir primeiro (Ordem de Prioridade: Imediata / Alta / Média), com a estimativa do benefício de segurança gerado pela correção.
"""
    return prompt
