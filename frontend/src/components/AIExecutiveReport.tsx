import React, { useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Sparkles, BrainCircuit, Copy, Check } from 'lucide-react';

interface AIExecutiveReportProps {
  reportText?: string;
}

export const AIExecutiveReport: React.FC<AIExecutiveReportProps> = ({ reportText }) => {
  const [copied, setCopied] = useState(false);

  if (!reportText) return null;

  const handleCopy = () => {
    navigator.clipboard.writeText(reportText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <section className="ai-report-card">
      <div className="ai-report-header">
        <div className="ai-title-wrap">
          <div className="ai-icon-bubble">
            <Sparkles size={22} className="ai-icon" />
          </div>
          <div>
            <div className="ai-title-row">
              <h3 className="ai-title">Interpretação e Análise Executiva (Camada de IA)</h3>
              <span className="ai-badge-ai">Síntese Cognitiva</span>
            </div>
            <p className="ai-subtitle">
              Avaliação de impacto no negócio, encadeamento de falhas (Kill Chain) e remediações técnicas
            </p>
          </div>
        </div>

        <div className="ai-header-actions">
          <span className="ai-model-pill">
            <BrainCircuit size={14} /> OpenRouter / Gemini
          </span>
          <button
            onClick={handleCopy}
            className="btn-copy-ai"
            title="Copiar relatório completo da IA"
          >
            {copied ? <Check size={14} className="text-safe" /> : <Copy size={14} />}
            <span>{copied ? 'Copiado!' : 'Copiar Texto'}</span>
          </button>
        </div>
      </div>

      <div className="ai-markdown-content">
        <ReactMarkdown
          remarkPlugins={[remarkGfm]}
          components={{
            h1: ({ children }) => <h3 className="ai-section-title">{children}</h3>,
            h2: ({ children }) => <h3 className="ai-section-title">{children}</h3>,
            h3: ({ children }) => <h4 className="ai-sub-title">{children}</h4>,
            p: ({ children }) => <p className="ai-paragraph">{children}</p>,
            ul: ({ children }) => <ul className="ai-bullet-list">{children}</ul>,
            ol: ({ children }) => <ol className="ai-numbered-list">{children}</ol>,
            li: ({ children }) => <li className="ai-list-item">{children}</li>,
            strong: ({ children }) => <strong className="ai-strong">{children}</strong>,
            code: ({ children, className }) => {
              const isInline = !className;
              return isInline ? (
                <code className="ai-inline-code">{children}</code>
              ) : (
                <code className="ai-block-code">{children}</code>
              );
            },
            pre: ({ children }) => <pre className="ai-code-wrapper">{children}</pre>,
            blockquote: ({ children }) => <blockquote className="ai-quote">{children}</blockquote>,
            table: ({ children }) => (
              <div className="ai-table-container">
                <table className="ai-table">{children}</table>
              </div>
            ),
            th: ({ children }) => <th className="ai-table-th">{children}</th>,
            td: ({ children }) => {
              const text = String(children);
              let badgeClass = '';
              if (text.includes('🔴') || text.includes('IMEDIATA')) {
                badgeClass = 'cell-badge-critical';
              } else if (text.includes('🟠') || text.includes('ALTA')) {
                badgeClass = 'cell-badge-high';
              } else if (text.includes('🟡') || text.includes('MÉDIA')) {
                badgeClass = 'cell-badge-medium';
              }

              return (
                <td className={`ai-table-td ${badgeClass}`}>
                  {children}
                </td>
              );
            }
          }}
        >
          {reportText}
        </ReactMarkdown>
      </div>
    </section>
  );
};
