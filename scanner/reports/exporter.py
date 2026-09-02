import html
import json
import os
import re
from datetime import datetime
from scanner.core.finding import Finding


class ReportExporter:
    """
    Exportador profissional de relatórios para o SecureScan.
    Suporta geração de relatórios em HTML (interativo e visual), Markdown (.md) e JSON estruturado.
    """

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir, exist_ok=True)

    def export_all(
        self,
        target_url: str,
        security_level: str,
        findings: list[Finding],
        ai_report: str
    ) -> dict[str, str]:
        """
        Executa a exportação simultânea nos formatos HTML, Markdown e JSON.
        Retorna um dicionário com os caminhos absolutos dos arquivos criados.
        """
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"securescan_report_{timestamp_str}"

        html_path = os.path.join(self.output_dir, f"{base_filename}.html")
        md_path = os.path.join(self.output_dir, f"{base_filename}.md")
        json_path = os.path.join(self.output_dir, f"{base_filename}.json")

        self.export_html(html_path, target_url, security_level, findings, ai_report)
        self.export_markdown(md_path, target_url, security_level, findings, ai_report)
        self.export_json(json_path, target_url, security_level, findings, ai_report)

        return {
            "html": os.path.abspath(html_path),
            "markdown": os.path.abspath(md_path),
            "json": os.path.abspath(json_path)
        }

    def export_json(
        self,
        filepath: str,
        target_url: str,
        security_level: str,
        findings: list[Finding],
        ai_report: str
    ):
        """Exporta os dados em formato JSON estruturado (machine-readable)."""
        data = {
            "scanner": "SecureScan",
            "version": "1.0.0",
            "timestamp": datetime.now().isoformat(),
            "target": {
                "url": target_url,
                "security_level": security_level
            },
            "summary": {
                "total_findings": len(findings),
                "critical": sum(1 for f in findings if f.severity.lower() == "critical"),
                "high": sum(1 for f in findings if f.severity.lower() == "high"),
                "medium": sum(1 for f in findings if f.severity.lower() == "medium"),
                "low": sum(1 for f in findings if f.severity.lower() == "low"),
            },
            "findings": [
                {
                    "category": f.category,
                    "name": f.name,
                    "test": f.test,
                    "status": f.status,
                    "severity": f.severity,
                    "evidence": f.evidence,
                    "recommendation": f.recommendation
                }
                for f in findings
            ],
            "ai_executive_analysis": ai_report
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def export_markdown(
        self,
        filepath: str,
        target_url: str,
        security_level: str,
        findings: list[Finding],
        ai_report: str
    ):
        """Exporta o relatório técnico no formato Markdown (.md)."""
        now_str = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        crit = sum(1 for f in findings if f.severity.lower() == "critical")
        high = sum(1 for f in findings if f.severity.lower() == "high")
        med = sum(1 for f in findings if f.severity.lower() == "medium")
        low = sum(1 for f in findings if f.severity.lower() == "low")

        content = f"""# 🛡️ SecureScan - Relatório de Análise de Vulnerabilidades

**Data da Varredura:** {now_str}  
**Alvo Analisado:** `{target_url}`  
**Nível de Segurança (DVWA):** `{security_level.upper()}`  

---

## 📊 Sumário Executivo de Métricas
| Métrica | Quantidade |
|---|---|
| **Total de Achados Detectados** | **{len(findings)}** |
| 🔴 Severidade Crítica | {crit} |
| 🟠 Severidade Alta | {high} |
| 🟡 Severidade Média | {med} |
| 🔵 Severidade Baixa | {low} |

---

## 🔍 Achados Determinísticos de Segurança

"""
        for i, f in enumerate(findings, start=1):
            content += f"""### Achado #{i}: {f.test} [{f.severity.upper()}]
* **Categoria OWASP:** `{f.category} - {f.name}`
* **Status:** `{f.status.upper()}`
* **Severidade:** `{f.severity.upper()}`

**Evidência Técnica:**
> {f.evidence}

**Recomendação de Defesa:**
{f.recommendation}

---
"""

        content += f"""
## 🤖 Interpretação e Análise Estratégica (Camada de IA)

{ai_report}

---
*Relatório gerado automaticamente pelo SecureScan — Projeto de Graduação em Ciência da Computação.*
"""

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

    def export_html(
        self,
        filepath: str,
        target_url: str,
        security_level: str,
        findings: list[Finding],
        ai_report: str
    ):
        """Exporta o relatório visual interativo e responsivo em HTML autocontido."""
        now_str = datetime.now().strftime("%d/%m/%Y às %H:%M:%S")
        crit = sum(1 for f in findings if f.severity.lower() == "critical")
        high = sum(1 for f in findings if f.severity.lower() == "high")
        med = sum(1 for f in findings if f.severity.lower() == "medium")
        low = sum(1 for f in findings if f.severity.lower() == "low")

        # Converte o markdown da IA em HTML formatado
        ai_html = self._markdown_to_html(ai_report)

        findings_cards = ""
        for i, f in enumerate(findings, start=1):
            sev = f.severity.lower()
            sev_class = f"badge-{sev}"
            findings_cards += f"""
            <div class="finding-card {sev}">
                <div class="finding-header">
                    <div>
                        <span class="finding-number">Achado #{i}</span>
                        <h3 class="finding-title">{html.escape(f.test)}</h3>
                    </div>
                    <span class="badge {sev_class}">{html.escape(f.severity.upper())}</span>
                </div>
                <div class="finding-meta">
                    <strong>Categoria OWASP:</strong> {html.escape(f.category)} - {html.escape(f.name)} &nbsp;|&nbsp; 
                    <strong>Status:</strong> <span class="status-tag">{html.escape(f.status.upper())}</span>
                </div>
                <div class="finding-section">
                    <h4>Evidência Técnica</h4>
                    <div class="evidence-box">{html.escape(f.evidence)}</div>
                </div>
                <div class="finding-section">
                    <h4>Recomendação de Defesa</h4>
                    <p class="recommendation-text">{html.escape(f.recommendation)}</p>
                </div>
            </div>
            """

        html_template = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureScan - Relatório de Vulnerabilidades</title>
    <style>
        :root {{
            --bg: #0f172a;
            --surface: #1e293b;
            --surface-hover: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --border: #334155;
            --primary: #3b82f6;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #3b82f6;
            --success: #10b981;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }}
        body {{ background-color: var(--bg); color: var(--text-primary); line-height: 1.6; padding: 2rem 1rem; }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        
        /* Header */
        .header {{ background: linear-gradient(135deg, #1e293b, #0f172a); border: 1px solid var(--border); border-radius: 12px; padding: 2rem; margin-bottom: 2rem; box-shadow: 0 4px 20px rgba(0,0,0,0.3); }}
        .header h1 {{ font-size: 2.2rem; color: #60a5fa; display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem; }}
        .header p {{ color: var(--text-secondary); font-size: 0.95rem; }}
        .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-top: 1.5rem; padding-top: 1.5rem; border-top: 1px solid var(--border); }}
        .meta-item strong {{ display: block; color: var(--text-secondary); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }}
        .meta-item span {{ font-size: 1rem; font-weight: 600; color: var(--text-primary); }}

        /* Metrics */
        .metrics-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 2.5rem; }}
        .metric-card {{ background-color: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1.25rem; text-align: center; }}
        .metric-card.critical {{ border-top: 4px solid var(--critical); }}
        .metric-card.high {{ border-top: 4px solid var(--high); }}
        .metric-card.medium {{ border-top: 4px solid var(--medium); }}
        .metric-card.total {{ border-top: 4px solid var(--primary); }}
        .metric-val {{ font-size: 2rem; font-weight: 700; margin-top: 0.25rem; }}
        .metric-card.critical .metric-val {{ color: var(--critical); }}
        .metric-card.high .metric-val {{ color: var(--high); }}
        .metric-card.medium .metric-val {{ color: var(--medium); }}
        .metric-card.total .metric-val {{ color: var(--primary); }}

        /* Section Titles */
        .section-title {{ font-size: 1.5rem; color: #f1f5f9; margin-bottom: 1.25rem; display: flex; align-items: center; gap: 0.5rem; border-bottom: 2px solid var(--border); padding-bottom: 0.5rem; }}

        /* Findings */
        .finding-card {{ background-color: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1.5rem; margin-bottom: 1.25rem; transition: transform 0.2s, box-shadow 0.2s; }}
        .finding-card:hover {{ box-shadow: 0 6px 15px rgba(0,0,0,0.25); }}
        .finding-card.critical {{ border-left: 5px solid var(--critical); }}
        .finding-card.high {{ border-left: 5px solid var(--high); }}
        .finding-card.medium {{ border-left: 5px solid var(--medium); }}
        .finding-header {{ display: flex; justify-content: space-between; align-items: flex-start; gap: 1rem; margin-bottom: 0.5rem; }}
        .finding-number {{ font-size: 0.75rem; text-transform: uppercase; font-weight: 700; color: #94a3b8; letter-spacing: 0.05em; }}
        .finding-title {{ font-size: 1.25rem; color: #f8fafc; font-weight: 600; margin-top: 0.1rem; }}
        .badge {{ padding: 0.3rem 0.75rem; border-radius: 20px; font-size: 0.75rem; font-weight: 700; letter-spacing: 0.05em; text-transform: uppercase; }}
        .badge-critical {{ background-color: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid var(--critical); }}
        .badge-high {{ background-color: rgba(249, 115, 22, 0.2); color: #fdba74; border: 1px solid var(--high); }}
        .badge-medium {{ background-color: rgba(234, 179, 8, 0.2); color: #fde047; border: 1px solid var(--medium); }}
        .finding-meta {{ color: var(--text-secondary); font-size: 0.85rem; margin-bottom: 1rem; }}
        .status-tag {{ color: var(--success); font-weight: 600; }}
        .finding-section {{ margin-top: 1rem; }}
        .finding-section h4 {{ font-size: 0.9rem; color: #cbd5e1; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.35rem; }}
        .evidence-box {{ background-color: #0b1120; border: 1px solid #1e293b; border-radius: 6px; padding: 0.85rem; font-family: "SFMono-Regular", Consolas, Menlo, monospace; font-size: 0.85rem; color: #e2e8f0; word-break: break-word; }}
        .recommendation-text {{ color: #cbd5e1; font-size: 0.92rem; }}

        /* AI Section */
        .ai-container {{ background: linear-gradient(145deg, #1e293b, #111827); border: 1px solid #3b82f6; border-radius: 12px; padding: 2rem; margin-top: 2.5rem; box-shadow: 0 4px 25px rgba(59, 130, 246, 0.15); }}
        .ai-header {{ display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1.5rem; color: #60a5fa; }}
        .ai-content {{ color: #e2e8f0; font-size: 0.95rem; line-height: 1.7; }}
        .ai-content h2, .ai-content h3, .ai-content h4 {{ color: #93c5fd; margin-top: 1.5rem; margin-bottom: 0.75rem; }}
        .ai-content p {{ margin-bottom: 1rem; }}
        .ai-content ul, .ai-content ol {{ margin-left: 1.5rem; margin-bottom: 1rem; }}
        .ai-content li {{ margin-bottom: 0.35rem; }}
        .ai-content table {{ width: 100%; border-collapse: collapse; margin: 1.5rem 0; font-size: 0.88rem; }}
        .ai-content th, .ai-content td {{ border: 1px solid var(--border); padding: 0.75rem 1rem; text-align: left; }}
        .ai-content th {{ background-color: #0f172a; color: #60a5fa; }}
        .ai-content pre {{ background-color: #0b1120; border: 1px solid #334155; border-radius: 8px; padding: 1rem; overflow-x: auto; margin: 1rem 0; }}
        .ai-content code {{ font-family: Consolas, monospace; font-size: 0.85rem; color: #38bdf8; }}

        /* Footer */
        .footer {{ text-align: center; margin-top: 3rem; color: var(--text-secondary); font-size: 0.85rem; border-top: 1px solid var(--border); padding-top: 1.5rem; }}
        
        @media print {{
            body {{ background: #fff; color: #000; }}
            .container {{ max-width: 100%; }}
            .finding-card, .header, .ai-container {{ border: 1px solid #ccc; background: #fff; color: #000; box-shadow: none; }}
            .evidence-box, .ai-content pre {{ background: #f4f4f4; color: #000; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header class="header">
            <h1>🛡️ SecureScan</h1>
            <p>Relatório Consolidado de Análise de Vulnerabilidades Web e Interpretação por Inteligência Artificial</p>
            <div class="meta-grid">
                <div class="meta-item">
                    <strong>Alvo Analisado</strong>
                    <span>{html.escape(target_url)}</span>
                </div>
                <div class="meta-item">
                    <strong>Nível de Segurança</strong>
                    <span>{html.escape(security_level.upper())}</span>
                </div>
                <div class="meta-item">
                    <strong>Data da Execução</strong>
                    <span>{now_str}</span>
                </div>
                <div class="meta-item">
                    <strong>Mecanismo de IA</strong>
                    <span>OpenRouter / MiniMax-M3</span>
                </div>
            </div>
        </header>

        <!-- Summary Metrics -->
        <section class="metrics-grid">
            <div class="metric-card total">
                <div>Total de Achados</div>
                <div class="metric-val">{len(findings)}</div>
            </div>
            <div class="metric-card critical">
                <div>Críticas</div>
                <div class="metric-val">{crit}</div>
            </div>
            <div class="metric-card high">
                <div>Altas</div>
                <div class="metric-val">{high}</div>
            </div>
            <div class="metric-card medium">
                <div>Médias</div>
                <div class="metric-val">{med}</div>
            </div>
        </section>

        <!-- Findings List -->
        <section>
            <h2 class="section-title">🔍 Achados Determinísticos de Segurança</h2>
            {findings_cards}
        </section>

        <!-- AI Executive Report -->
        <section class="ai-container">
            <div class="ai-header">
                <h2>🤖 Análise Executiva & Guia de Remediação (Camada de IA)</h2>
            </div>
            <div class="ai-content">
                {ai_html}
            </div>
        </section>

        <!-- Footer -->
        <footer class="footer">
            <p>SecureScan — Ferramenta de Análise Automatizada de Vulnerabilidades Web Integrada com IA</p>
            <p>Trabalho de Conclusão de Curso (TCC) em Ciência da Computação — 2026</p>
        </footer>
    </div>
</body>
</html>
"""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_template)

    def _markdown_to_html(self, md_text: str) -> str:
        """
        Conversor leve de markdown para HTML com suporte a cabeçalhos, tabelas,
        blocos de código e destaques para apresentação no navegador.
        """
        if not md_text:
            return "<p>Nenhuma análise gerada pela IA.</p>"

        # Escapa HTML inicial
        text = html.escape(md_text)

        # Blocos de código ```php ... ```
        def replace_code_block(match):
            lang = match.group(1) or ""
            code = match.group(2)
            return f'<pre><code class="language-{lang}">{code.strip()}</code></pre>'

        text = re.sub(r"```(\w*)\n([\s\S]*?)```", replace_code_block, text)

        # Código inline `code`
        text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)

        # Cabeçalhos #, ##, ###, ####
        text = re.sub(r"^#### (.*?)$", r"<h4>\1</h4>", text, flags=re.MULTILINE)
        text = re.sub(r"^### (.*?)$", r"<h3>\1</h3>", text, flags=re.MULTILINE)
        text = re.sub(r"^## (.*?)$", r"<h2>\1</h2>", text, flags=re.MULTILINE)
        text = re.sub(r"^# (.*?)$", r"<h1>\1</h1>", text, flags=re.MULTILINE)

        # Negrito **texto**
        text = re.sub(r"\*\*(.*?)\*\*", r"<strong>\1</strong>", text)

        # Itálico *texto*
        text = re.sub(r"\*(.*?)\*", r"<em>\1</em>", text)

        # Linhas horizontais ---
        text = re.sub(r"^---+$", r"<hr style='border: 1px solid var(--border); margin: 1.5rem 0;'>", text, flags=re.MULTILINE)

        # Processamento de Tabelas Markdown
        lines = text.split("\n")
        output = []
        in_table = False
        table_rows = []

        for line in lines:
            stripped = line.strip()
            if stripped.startswith("|") and stripped.endswith("|"):
                if "---" in stripped:
                    # Linha separadora da tabela
                    continue
                in_table = True
                cols = [c.strip() for c in stripped.split("|")[1:-1]]
                table_rows.append(cols)
            else:
                if in_table:
                    # Fecha a tabela
                    output.append("<table>")
                    if table_rows:
                        # Cabeçalho
                        output.append("<thead><tr>" + "".join(f"<th>{c}</th>" for c in table_rows[0]) + "</tr></thead>")
                        # Corpo
                        output.append("<tbody>")
                        for r in table_rows[1:]:
                            output.append("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>")
                        output.append("</tbody>")
                    output.append("</table>")
                    in_table = False
                    table_rows = []

                if stripped.startswith("&gt;"):
                    output.append(f"<blockquote>{stripped[4:].strip()}</blockquote>")
                elif stripped.startswith("- ") or stripped.startswith("* "):
                    output.append(f"<li>{stripped[2:].strip()}</li>")
                elif stripped.startswith("<h") or stripped.startswith("<pre") or stripped.startswith("<hr"):
                    output.append(stripped)
                elif stripped:
                    output.append(f"<p>{stripped}</p>")

        if in_table:
            output.append("<table>")
            if table_rows:
                output.append("<thead><tr>" + "".join(f"<th>{c}</th>" for c in table_rows[0]) + "</tr></thead>")
                output.append("<tbody>")
                for r in table_rows[1:]:
                    output.append("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>")
                output.append("</tbody>")
            output.append("</table>")

        return "\n".join(output)
