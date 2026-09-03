import React from 'react';
import { Sparkles, BrainCircuit } from 'lucide-react';

interface AIExecutiveReportProps {
  reportText?: string;
}

export const AIExecutiveReport: React.FC<AIExecutiveReportProps> = ({ reportText }) => {
  if (!reportText) return null;

  return (
    <section className="ai-report-card">
      <div className="ai-report-header">
        <div className="ai-title-wrap">
          <div className="ai-icon-bubble">
            <Sparkles size={22} className="ai-icon" />
          </div>
          <div>
            <h3 className="ai-title">Interpretação e Análise Executiva (Camada de IA)</h3>
            <p className="ai-subtitle">Síntese contextual gerada com suporte ao OWASP Top 10 e mitigação técnica</p>
          </div>
        </div>
        <span className="ai-model-pill">
          <BrainCircuit size={14} /> OpenRouter / Gemini
        </span>
      </div>

      <div className="ai-report-body">
        <pre className="ai-text-pre">{reportText}</pre>
      </div>
    </section>
  );
};
