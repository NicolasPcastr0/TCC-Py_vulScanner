import React from 'react';
import { ShieldAlert, AlertTriangle, AlertCircle, ShieldCheck, Layers } from 'lucide-react';
import type { ScanSummary } from '../types/scanner';

interface MetricsSummaryProps {
  summary: ScanSummary;
  targetUrl: string;
  securityLevel: string;
  timestamp: string;
}

export const MetricsSummary: React.FC<MetricsSummaryProps> = ({
  summary,
  targetUrl,
  securityLevel,
  timestamp
}) => {
  return (
    <div className="metrics-section">
      <div className="metrics-meta-banner">
        <div>
          <span className="meta-label">Alvo:</span> <strong>{targetUrl}</strong>
        </div>
        <div>
          <span className="meta-label">Nível DVWA:</span> <strong className="uppercase">{securityLevel}</strong>
        </div>
        <div>
          <span className="meta-label">Data:</span> <span>{timestamp}</span>
        </div>
      </div>

      <div className="metrics-grid">
        <div className="metric-card metric-total">
          <div className="metric-icon-wrap">
            <Layers size={20} />
          </div>
          <div className="metric-info">
            <span className="metric-count">{summary.total}</span>
            <span className="metric-title">Total de Achados</span>
          </div>
        </div>

        <div className="metric-card metric-critical">
          <div className="metric-icon-wrap">
            <ShieldAlert size={20} />
          </div>
          <div className="metric-info">
            <span className="metric-count">{summary.critical}</span>
            <span className="metric-title">Críticas</span>
          </div>
        </div>

        <div className="metric-card metric-high">
          <div className="metric-icon-wrap">
            <AlertTriangle size={20} />
          </div>
          <div className="metric-info">
            <span className="metric-count">{summary.high}</span>
            <span className="metric-title">Altas</span>
          </div>
        </div>

        <div className="metric-card metric-medium">
          <div className="metric-icon-wrap">
            <AlertCircle size={20} />
          </div>
          <div className="metric-info">
            <span className="metric-count">{summary.medium}</span>
            <span className="metric-title">Médias</span>
          </div>
        </div>

        <div className="metric-card metric-safe">
          <div className="metric-icon-wrap">
            <ShieldCheck size={20} />
          </div>
          <div className="metric-info">
            <span className="metric-count">{summary.safe || 0}</span>
            <span className="metric-title">Protegidas</span>
          </div>
        </div>
      </div>
    </div>
  );
};
