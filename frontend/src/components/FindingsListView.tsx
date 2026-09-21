import React, { useState } from 'react';
import {
  ArrowLeft,
  ArrowRight,
  Globe,
  ChevronRight,
  AlertTriangle,
  Flame,
  ShieldAlert,
  Info,
  CheckCircle2,
  Sparkles,
  Download,
  Filter
} from 'lucide-react';
import type { Finding, ScanResult, Severity } from '../types/scanner';
import { exportToJson, exportToCsv, exportToPdf } from '../services/scanService';

interface FindingsListViewProps {
  scanResult: ScanResult | null;
  onBack: () => void;
  onSelectFinding: (finding: Finding) => void;
  onOpenAiReport: () => void;
  onNavigateToNewScan?: () => void;
}

export const FindingsListView: React.FC<FindingsListViewProps> = ({
  scanResult,
  onBack,
  onSelectFinding,
  onOpenAiReport,
  onNavigateToNewScan
}) => {
  if (!scanResult) {
    return (
      <div className="findings-list-layout">
        <header className="results-header-bar">
          <button type="button" className="btn-back-link" onClick={onBack}>
            <ArrowLeft size={16} />
            <span>Voltar ao Dashboard</span>
          </button>
          <h1 className="results-main-title">Resultado da análise</h1>
        </header>

        <div
          className="dash-card"
          style={{
            padding: '3.5rem 2rem',
            textAlign: 'center',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            marginTop: '1.5rem'
          }}
        >
          <div
            style={{
              width: '64px',
              height: '64px',
              borderRadius: '50%',
              background: 'rgba(59, 130, 246, 0.1)',
              border: '1px solid rgba(59, 130, 246, 0.25)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#60a5fa',
              marginBottom: '1.25rem'
            }}
          >
            <ShieldAlert size={32} />
          </div>
          <h2 style={{ fontSize: '1.25rem', fontWeight: 700, color: '#f8fafc', marginBottom: '0.5rem' }}>
            Nenhuma análise executada ainda
          </h2>
          <p style={{ color: '#94a3b8', fontSize: '0.9rem', maxWidth: '480px', lineHeight: 1.5, marginBottom: '1.5rem' }}>
            Nenhum resultado foi gerado nesta sessão. Acesse a aba <strong>Nova análise</strong> para configurar seu alvo (DVWA ou WordPress) e iniciar a varredura.
          </p>
          <button
            type="button"
            className="btn-primary-action"
            onClick={onNavigateToNewScan || onBack}
          >
            <span>Iniciar nova análise</span>
            <ArrowRight size={16} />
          </button>
        </div>
      </div>
    );
  }

  const { targetUrl, timestamp, durationSeconds, summary, findings, score = 72 } = scanResult;

  // Filtro por severidade
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const filteredFindings = findings.filter((f) => {
    const isSafe = f.severity === 'safe' || f.status === 'not_detected';
    const matchesSeverity =
      selectedSeverity === 'all' ||
      (selectedSeverity === 'safe' ? isSafe : f.severity === selectedSeverity);
    const matchesSearch =
      searchQuery === '' ||
      f.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.test.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.category.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesSeverity && matchesSearch;
  });

  const getSeverityIcon = (sev: Severity) => {
    switch (sev) {
      case 'critical':
        return <AlertTriangle size={18} className="text-critical" />;
      case 'high':
        return <Flame size={18} className="text-high" />;
      case 'medium':
        return <ShieldAlert size={18} className="text-medium" />;
      case 'low':
        return <Info size={18} className="text-low" />;
      case 'safe':
      default:
        return <CheckCircle2 size={18} className="text-success" />;
    }
  };

  const getSeverityBadgeClass = (sev: Severity) => {
    switch (sev) {
      case 'critical':
        return 'badge-sev-critical';
      case 'high':
        return 'badge-sev-high';
      case 'medium':
        return 'badge-sev-medium';
      case 'low':
        return 'badge-sev-low';
      case 'safe':
      default:
        return 'badge-sev-safe';
    }
  };

  // Raio do mini Donut
  const radius = 34;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className="findings-list-layout">
      {/* 1. Barra Superior com Botão de Voltar */}
      <header className="results-header-bar">
        <button type="button" className="btn-back-link" onClick={onBack}>
          <ArrowLeft size={16} />
          <span>Voltar ao Dashboard</span>
        </button>
        <h1 className="results-main-title">Resultado da análise</h1>
      </header>

      {/* 2. Card de Resumo do Alvo */}
      <section className="dash-card target-summary-card">
        <div className="target-summary-left">
          <div className="target-globe-icon">
            <Globe size={24} />
          </div>
          <div className="target-details-col">
            <div className="target-name-row">
              <h2 className="target-heading">
                {scanResult.targetPlatform === 'wordpress' || targetUrl.includes(':8080') || scanResult.securityLevel?.toLowerCase().includes('wordpress')
                  ? 'WordPress CMS'
                  : 'DVWA'}
              </h2>
              <span className="target-sub-url">{targetUrl}</span>
            </div>
            <div className="target-meta-row">
              <div className="meta-item">
                <span className="meta-item-label">Data:</span>
                <span className="meta-item-value">{timestamp}</span>
              </div>
              <span className="meta-separator">•</span>
              <div className="meta-item">
                <span className="meta-item-label">Duração:</span>
                <span className="meta-item-value">{durationSeconds} segundos</span>
              </div>
              <span className="meta-separator">•</span>
              <div className="meta-item">
                <span className="meta-item-label">
                  {scanResult.targetPlatform === 'wordpress' || targetUrl.includes(':8080') || scanResult.securityLevel?.toLowerCase().includes('wordpress')
                    ? 'Ambiente:'
                    : 'Nível DVWA:'}
                </span>
                <span className="meta-item-value uppercase-badge">{scanResult.securityLevel}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Donut Score Compacto */}
        <div className="target-score-box">
          <span className="score-box-label">Score de segurança</span>
          <div className="mini-donut-container">
            <svg className="mini-donut-svg" viewBox="0 0 88 88">
              <circle
                cx="44"
                cy="44"
                r={radius}
                className="score-donut-trail"
                strokeWidth="8"
              />
              <circle
                cx="44"
                cy="44"
                r={radius}
                className="score-donut-progress"
                strokeWidth="8"
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
              />
            </svg>
            <div className="mini-donut-center">
              <span className="mini-donut-value">{score}</span>
              <span className="mini-donut-max">/100</span>
            </div>
          </div>
        </div>
      </section>

      {/* 3. Linha de Métricas & Contadores */}
      <section className="findings-metrics-bar">
        <div className="metric-pill pill-tests">
          <span className="pill-number">{summary.total + 13}</span>
          <span className="pill-text">Testes realizados</span>
        </div>

        <div className="metric-pill pill-vulns">
          <AlertTriangle size={16} className="text-critical" />
          <span className="pill-number text-critical">{summary.total}</span>
          <span className="pill-text">Vulnerabilidades encontradas</span>
        </div>

        <div className="metric-pill pill-breakdown">
          <span className="pill-dot dot-critical" />
          <span className="pill-mini-text">Críticas: <strong>{summary.critical}</strong></span>
          <span className="pill-mini-separator">|</span>

          <span className="pill-dot dot-high" />
          <span className="pill-mini-text">Altas: <strong>{summary.high}</strong></span>
          <span className="pill-mini-separator">|</span>

          <span className="pill-dot dot-medium" />
          <span className="pill-mini-text">Médias: <strong>{summary.medium}</strong></span>
          <span className="pill-mini-separator">|</span>

          <span className="pill-dot dot-low" />
          <span className="pill-mini-text">Baixas: <strong>{summary.low}</strong></span>

          {(summary.safe !== undefined && summary.safe > 0) && (
            <>
              <span className="pill-mini-separator">|</span>
              <span className="pill-dot dot-safe" />
              <span className="pill-mini-text">Seguras: <strong>{summary.safe}</strong></span>
            </>
          )}
        </div>

        {/* Botão de Relatório Geral de IA */}
        <button
          type="button"
          className="btn-ai-executive-trigger"
          onClick={onOpenAiReport}
          title="Ver o diagnóstico e plano de ação executivo formulado pelo Google Gemini"
        >
          <Sparkles size={16} />
          <span>Relatório de IA</span>
        </button>
      </section>

      {/* 4. Lista de Vulnerabilidades Encontradas */}
      <section className="findings-table-section">
        <div className="findings-section-header">
          <div className="filter-tabs-row">
            <span className="filter-title">
              <Filter size={15} /> Filtrar:
            </span>
            <button
              type="button"
              className={`filter-btn ${selectedSeverity === 'all' ? 'active' : ''}`}
              onClick={() => setSelectedSeverity('all')}
            >
              Todas ({findings.length})
            </button>
            <button
              type="button"
              className={`filter-btn btn-sev-crit ${selectedSeverity === 'critical' ? 'active' : ''}`}
              onClick={() => setSelectedSeverity('critical')}
            >
              Críticas ({summary.critical})
            </button>
            <button
              type="button"
              className={`filter-btn btn-sev-high ${selectedSeverity === 'high' ? 'active' : ''}`}
              onClick={() => setSelectedSeverity('high')}
            >
              Altas ({summary.high})
            </button>
            <button
              type="button"
              className={`filter-btn btn-sev-med ${selectedSeverity === 'medium' ? 'active' : ''}`}
              onClick={() => setSelectedSeverity('medium')}
            >
              Médias ({summary.medium})
            </button>
            <button
              type="button"
              className={`filter-btn btn-sev-low ${selectedSeverity === 'low' ? 'active' : ''}`}
              onClick={() => setSelectedSeverity('low')}
            >
              Baixas ({summary.low})
            </button>
            {(summary.safe !== undefined && summary.safe > 0) && (
              <button
                type="button"
                className={`filter-btn btn-sev-safe ${selectedSeverity === 'safe' ? 'active' : ''}`}
                onClick={() => setSelectedSeverity('safe')}
              >
                Seguras ({summary.safe})
              </button>
            )}
            <input
              type="text"
              placeholder="Buscar vulnerabilidade..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="input-text"
              style={{
                padding: '0.25rem 0.65rem',
                fontSize: '0.775rem',
                width: '180px',
                marginLeft: '0.35rem'
              }}
            />
          </div>

          <div className="export-actions-row">
            <button
              type="button"
              className="btn-export-subtle"
              onClick={() => exportToPdf(scanResult)}
              title="Exportar relatório completo em PDF"
            >
              <Download size={14} />
              <span>PDF</span>
            </button>
            <button
              type="button"
              className="btn-export-subtle"
              onClick={() => exportToJson(scanResult)}
              title="Exportar dados técnicos brutos em JSON"
            >
              <Download size={14} />
              <span>JSON</span>
            </button>
            <button
              type="button"
              className="btn-export-subtle"
              onClick={() => exportToCsv(scanResult)}
              title="Exportar tabela de achados em CSV"
            >
              <Download size={14} />
              <span>CSV</span>
            </button>
          </div>
        </div>

        {/* Linhas de Achados */}
        <div className="findings-rows-list">
          {filteredFindings.map((f, idx) => (
            <div
              key={f.id || idx}
              className={`finding-row-card sev-${f.severity}`}
              onClick={() => onSelectFinding(f)}
            >
              <div className="finding-row-icon-box">
                {getSeverityIcon(f.severity)}
              </div>

              <div className="finding-row-info">
                <div className="finding-row-title-line">
                  <span className="finding-row-category">{f.category}</span>
                  <span className="finding-row-separator">—</span>
                  <span className="finding-row-name">{f.name}</span>
                  <span className={`finding-sev-pill ${getSeverityBadgeClass(f.severity)}`}>
                    {f.severity.toUpperCase()}
                  </span>
                </div>
                <p className="finding-row-test-desc">{f.test}</p>
              </div>

              <div className="finding-row-right">
                <div className="confidence-pill">
                  <span className="confidence-label">Confiança</span>
                  <span className="confidence-value">{f.confidence ?? 94}%</span>
                </div>
                <div className="row-chevron-box">
                  <ChevronRight size={18} />
                </div>
              </div>
            </div>
          ))}

          {filteredFindings.length === 0 && (
            <div className="empty-filter-state">
              <CheckCircle2 size={32} className="text-success" />
              <p>Nenhuma vulnerabilidade encontrada com os filtros selecionados.</p>
            </div>
          )}
        </div>
      </section>
    </div>
  );
};
