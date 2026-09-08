import { ChevronDown, Terminal, Shield } from 'lucide-react';
import type { Finding } from '../types/scanner';

interface FindingCardProps {
  finding: Finding;
  index: number;
}

export const FindingCard: React.FC<FindingCardProps> = ({ finding, index }) => {
  const getFindingDetails = () => {
    // Se o teste não detectou falha, o alvo está protegido contra esta técnica
    if (finding.status === 'not_detected' || finding.severity === 'safe') {
      return {
        emoji: '🟢',
        label: 'PROTEGIDO',
        colorClass: 'sev-safe',
        statusLabel: 'PROTEGIDO',
        statusClass: 'status-safe'
      };
    }

    // Vulnerabilidade identificada - mapeia de acordo com a severidade CVSS/OWASP
    switch (finding.severity.toLowerCase()) {
      case 'critical':
        return {
          emoji: '🔴',
          label: 'CRÍTICO',
          colorClass: 'sev-critical',
          statusLabel: 'VULNERÁVEL',
          statusClass: 'status-detected'
        };
      case 'high':
        return {
          emoji: '🟠',
          label: 'ALTO',
          colorClass: 'sev-high',
          statusLabel: 'VULNERÁVEL',
          statusClass: 'status-detected'
        };
      case 'medium':
        return {
          emoji: '🟡',
          label: 'MÉDIO',
          colorClass: 'sev-medium',
          statusLabel: 'VULNERÁVEL',
          statusClass: 'status-detected'
        };
      case 'low':
      default:
        return {
          emoji: '🔵',
          label: 'BAIXO',
          colorClass: 'sev-low',
          statusLabel: 'VULNERÁVEL',
          statusClass: 'status-low'
        };
    }
  };

  const details = getFindingDetails();

  return (
    <details className={`finding-accordion ${details.colorClass}`}>
      <summary className="accordion-summary">
        <div className="summary-left">
          <span className="summary-emoji">{details.emoji}</span>
          <span className={`badge-severity ${details.colorClass}`}>
            [{details.label}]
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
          <span className="detail-label">Status da Auditoria:</span>
          <span className={`status-badge ${details.statusClass}`}>
            {details.statusLabel} ({finding.status.toUpperCase()})
          </span>
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
