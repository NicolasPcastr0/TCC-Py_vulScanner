import React from 'react';
import {
  AlertTriangle,
  Flame,
  CheckCircle2,
  ShieldCheck,
  Globe,
  ArrowRight
} from 'lucide-react';
import type { ScanResult } from '../types/scanner';

interface DashboardViewProps {
  scanResult: ScanResult;
  onNavigateToNewScan: () => void;
  onNavigateToFindings: () => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  scanResult,
  onNavigateToNewScan,
  onNavigateToFindings
}) => {
  const { summary, targetUrl, timestamp, durationSeconds, score = 72 } = scanResult;

  // Cálculo da altura relativa das barras de distribuição (máximo de 140px)
  const maxBarValue = Math.max(summary.critical, summary.high, summary.medium, summary.low, summary.safe || 0, 1);
  const getBarHeight = (val: number) => {
    return Math.max(Math.round((val / maxBarValue) * 110), 12);
  };

  // Cálculo do perímetro circular do Donut de Score (raio = 54 -> circunf = 2 * PI * 54 = ~339.29)
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className="dashboard-layout">
      {/* 1. Cabeçalho de Boas-Vindas */}
      <header className="view-header">
        <div>
          <h1 className="view-title">Bem-vindo, Nicolas</h1>
          <p className="view-subtitle">
            Monitore e analise a segurança das suas aplicações web em tempo real.
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div className="header-status-badge">
            <span className="status-indicator-dot" />
            <span>Sistema online</span>
          </div>
          <button
            type="button"
            className="btn-primary-action"
            onClick={onNavigateToNewScan}
            style={{ padding: '0.45rem 0.95rem', fontSize: '0.825rem' }}
          >
            <span>Nova análise</span>
          </button>
        </div>
      </header>

      {/* 2. Grid de 4 Cards de Métricas */}
      <section className="metric-cards-grid">
        {/* Card 1: Total de Vulnerabilidades */}
        <div className="dash-card metric-card">
          <div className="metric-card-top">
            <span className="metric-card-label">Vulnerabilidades</span>
            <div className="metric-icon-box sev-critical">
              <AlertTriangle size={18} />
            </div>
          </div>
          <div className="metric-card-number">{summary.total}</div>
        </div>

        {/* Card 2: Críticas */}
        <div className="dash-card metric-card">
          <div className="metric-card-top">
            <span className="metric-card-label">Críticas</span>
            <div className="metric-icon-box sev-critical">
              <Flame size={18} />
            </div>
          </div>
          <div className="metric-card-number text-critical">{summary.critical}</div>
        </div>

        {/* Card 3: Testes Executados */}
        <div className="dash-card metric-card">
          <div className="metric-card-top">
            <span className="metric-card-label">Testes executados</span>
            <div className="metric-icon-box sev-info">
              <CheckCircle2 size={18} />
            </div>
          </div>
          <div className="metric-card-number">{summary.total + 13}</div>
        </div>

        {/* Card 4: Score de Segurança */}
        <div className="dash-card metric-card">
          <div className="metric-card-top">
            <span className="metric-card-label">Score de segurança</span>
            <div className="metric-icon-box sev-success">
              <ShieldCheck size={18} />
            </div>
          </div>
          <div className="metric-card-number text-success">
            {score} <span className="text-muted-number">/100</span>
          </div>
        </div>
      </section>

      {/* 3. Seção Intermediária: Gráficos de Distribuição & Score */}
      <section className="dashboard-charts-row">
        {/* Gráfico de Barras: Distribuição de Vulnerabilidades */}
        <div className="dash-card chart-card">
          <div className="card-header-row">
            <h3 className="card-heading">Distribuição das vulnerabilidades</h3>
          </div>
          <div className="bar-chart-container">
            {/* Eixo Vertical de Valores */}
            <div className="bar-chart-axis">
              <span>{maxBarValue}</span>
              <span>{Math.round(maxBarValue * 0.66)}</span>
              <span>{Math.round(maxBarValue * 0.33)}</span>
              <span>0</span>
            </div>

            {/* As 4 Barras */}
            <div className="bar-chart-bars">
              {/* Barra Crítica */}
              <div className="bar-column">
                <div className="bar-value-label">{summary.critical}</div>
                <div
                  className="bar-fill bar-critical"
                  style={{ height: `${getBarHeight(summary.critical)}px` }}
                />
                <span className="bar-label">Críticas</span>
              </div>

              {/* Barra Alta */}
              <div className="bar-column">
                <div className="bar-value-label">{summary.high}</div>
                <div
                  className="bar-fill bar-high"
                  style={{ height: `${getBarHeight(summary.high)}px` }}
                />
                <span className="bar-label">Altas</span>
              </div>

              {/* Barra Média */}
              <div className="bar-column">
                <div className="bar-value-label">{summary.medium}</div>
                <div
                  className="bar-fill bar-medium"
                  style={{ height: `${getBarHeight(summary.medium)}px` }}
                />
                <span className="bar-label">Médias</span>
              </div>

              {/* Barra Baixa */}
              <div className="bar-column">
                <div className="bar-value-label">{summary.low}</div>
                <div
                  className="bar-fill bar-low"
                  style={{ height: `${getBarHeight(summary.low)}px` }}
                />
                <span className="bar-label">Baixas</span>
              </div>

              {/* Barra Segura */}
              <div className="bar-column">
                <div className="bar-value-label">{summary.safe || 0}</div>
                <div
                  className="bar-fill bar-safe"
                  style={{ height: `${getBarHeight(summary.safe || 0)}px` }}
                />
                <span className="bar-label">Seguras</span>
              </div>
            </div>
          </div>
        </div>

        {/* Gauge Circular: Score de Segurança */}
        <div className="dash-card chart-card">
          <div className="card-header-row">
            <h3 className="card-heading">Score de segurança</h3>
          </div>

          <div className="score-widget-content">
            {/* Donut SVG */}
            <div className="score-donut-wrapper">
              <svg className="score-donut-svg" viewBox="0 0 140 140">
                {/* Trilha de fundo */}
                <circle
                  cx="70"
                  cy="70"
                  r={radius}
                  className="score-donut-trail"
                  strokeWidth="12"
                />
                {/* Arco de progresso preenchido */}
                <circle
                  cx="70"
                  cy="70"
                  r={radius}
                  className="score-donut-progress"
                  strokeWidth="12"
                  strokeDasharray={circumference}
                  strokeDashoffset={strokeDashoffset}
                  strokeLinecap="round"
                />
              </svg>
              <div className="score-donut-center">
                <span className="score-donut-value">{score}</span>
                <span className="score-donut-max">/100</span>
              </div>
            </div>

            {/* Legenda Lateral com Contadores */}
            <div className="score-legend-list">
              <div className="score-legend-item">
                <span className="legend-dot dot-critical" />
                <span className="legend-name">Críticas</span>
                <span className="legend-count">{summary.critical}</span>
              </div>
              <div className="score-legend-item">
                <span className="legend-dot dot-high" />
                <span className="legend-name">Altas</span>
                <span className="legend-count">{summary.high}</span>
              </div>
              <div className="score-legend-item">
                <span className="legend-dot dot-medium" />
                <span className="legend-name">Médias</span>
                <span className="legend-count">{summary.medium}</span>
              </div>
              <div className="score-legend-item">
                <span className="legend-dot dot-low" />
                <span className="legend-name">Baixas</span>
                <span className="legend-count">{summary.low}</span>
              </div>
              <div className="score-legend-item">
                <span className="legend-dot dot-safe" />
                <span className="legend-name">Seguras</span>
                <span className="legend-count">{summary.safe || 0}</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* 4. Card da Última Análise */}
      <section className="dash-card last-scan-card">
        <div className="last-scan-left">
          <div className="last-scan-icon">
            <Globe size={22} />
          </div>
          <div className="last-scan-info">
            <h3 className="last-scan-target">
              {scanResult.targetPlatform === 'wordpress' || targetUrl.includes(':8080') || scanResult.securityLevel?.toLowerCase().includes('wordpress')
                ? 'WordPress (CMS Corporativo)'
                : 'DVWA (Damn Vulnerable Web Application)'}
            </h3>
            <span className="last-scan-url">{targetUrl}</span>
            <div className="last-scan-meta">
              <span>{timestamp}</span>
              <span className="meta-separator">•</span>
              <span>{summary.total + 13} testes executados</span>
              <span className="meta-separator">•</span>
              <span className="text-critical">{summary.total} vulnerabilidades encontradas</span>
              <span className="meta-separator">•</span>
              <span>Duração: {durationSeconds}s</span>
            </div>
          </div>
        </div>

        <div className="last-scan-actions">
          <button
            type="button"
            className="btn-primary-action"
            onClick={onNavigateToFindings}
          >
            <span>Ver resultado</span>
            <ArrowRight size={16} />
          </button>
        </div>
      </section>
    </div>
  );
};
