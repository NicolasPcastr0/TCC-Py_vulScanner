import { ChevronDown, Terminal, Shield } from 'lucide-react';
import type { Finding, Severity } from '../types/scanner';

interface FindingCardProps {
  finding: Finding;
  index: number;
}

export const FindingCard: React.FC<FindingCardProps> = ({ finding, index }) => {
  const getSeverityDetails = (severity: Severity) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return {
          emoji: '🔴',
          label: 'CRÍTICO',
          colorClass: 'sev-critical'
        };
      case 'high':
        return {
          emoji: '🟠',
          label: 'ALTO',
          colorClass: 'sev-high'
        };
      case 'medium':
        return {
          emoji: '🟡',
          label: 'MÉDIO',
          colorClass: 'sev-medium'
        };
      default:
        return {
          emoji: '🟢',
          label: 'SEGURO',
          colorClass: 'sev-safe'
        };
    }
  };

  const sev = getSeverityDetails(finding.severity);

  return (
    <details className={`finding-accordion ${sev.colorClass}`}>
      <summary className="accordion-summary">
        <div className="summary-left">
          <span className="summary-emoji">{sev.emoji}</span>
          <span className={`badge-severity ${sev.colorClass}`}>
            [{sev.label}]
          </span>
          <span className="summary-title">#{index} - {finding.test}</span>
        </div>

        <div className="summary-right">
          <span className="category-pill">{finding.category}</span>
          <ChevronDown size={18} className="chevron-icon" />
        </div>
      </summary>

      <div className="accordion-content">
        <div className="finding-detail-row">
          <span className="detail-label">Nome da Vulnerabilidade:</span>
          <span className="detail-value">{finding.name}</span>
        </div>

        <div className="finding-detail-row">
          <span className="detail-label">Status da Detecção:</span>
          <span className="status-badge status-detected">{finding.status.toUpperCase()}</span>
        </div>

        <div className="detail-block">
          <h4 className="detail-block-title">
            <Terminal size={15} /> Evidência Técnica Identificada
          </h4>
          <div className="evidence-code-box">
            <code>{finding.evidence}</code>
          </div>
        </div>

        <div className="detail-block">
          <h4 className="detail-block-title">
            <Shield size={15} /> Recomendação de Mitigação
          </h4>
          <div className="recommendation-box">
            <p>{finding.recommendation}</p>
          </div>
        </div>
      </div>
    </details>
  );
};
