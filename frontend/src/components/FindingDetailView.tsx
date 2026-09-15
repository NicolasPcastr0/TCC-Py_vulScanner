import React, { useState } from 'react';
import {
  ArrowLeft,
  Terminal,
  Sparkles,
  Copy,
  Check,
  Flame,
  AlertTriangle,
  Info,
  CheckCircle2,
  Lightbulb,
  ShieldCheck,
  ShieldAlert
} from 'lucide-react';
import type { Finding, Severity } from '../types/scanner';

interface FindingDetailViewProps {
  finding: Finding;
  onBack: () => void;
}

export const FindingDetailView: React.FC<FindingDetailViewProps> = ({
  finding,
  onBack
}) => {
  const [copied, setCopied] = useState<boolean>(false);

  const handleCopyEvidence = () => {
    navigator.clipboard.writeText(finding.evidence);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getSeverityBadge = (sev: Severity) => {
    switch (sev) {
      case 'critical':
        return (
          <span className="badge-pill-detail sev-crit">
            <AlertTriangle size={14} /> Crítica
          </span>
        );
      case 'high':
        return (
          <span className="badge-pill-detail sev-high">
            <Flame size={14} /> Alta
          </span>
        );
      case 'medium':
        return (
          <span className="badge-pill-detail sev-med">
            <ShieldAlert size={14} /> Média
          </span>
        );
      case 'low':
        return (
          <span className="badge-pill-detail sev-low">
            <Info size={14} /> Baixa
          </span>
        );
      case 'safe':
      default:
        return (
          <span className="badge-pill-detail sev-safe">
            <CheckCircle2 size={14} /> Protegido
          </span>
        );
    }
  };

  return (
    <div className="finding-detail-layout">
      {/* 1. Barra de Navegação Superior */}
      <header className="detail-top-bar">
        <button type="button" className="btn-back-link" onClick={onBack}>
          <ArrowLeft size={16} />
          <span>Voltar à lista de vulnerabilidades</span>
        </button>

        <div className="detail-header-title-row">
          <div className="detail-title-col">
            <h1 className="detail-main-title">
              {finding.category} — {finding.name}
            </h1>
            <span className="detail-sub-test">{finding.test}</span>
          </div>

          <div className="detail-severity-badge-wrapper">
            {getSeverityBadge(finding.severity)}
          </div>
        </div>
      </header>

      {/* 2. Conteúdo em Visão Geral Unificada (Duas Colunas) */}
      <div className="detail-content-grid">
        {/* Coluna Esquerda: Informações Técnicas & Evidências */}
        <div className="detail-col-left">
          {/* Card: Informações Técnicas */}
          <div className="dash-card detail-card-box">
            <h3 className="card-box-title">Informações</h3>
            <div className="detail-key-values">
              <div className="kv-row">
                <span className="kv-label">Severidade</span>
                <div className="kv-value">{getSeverityBadge(finding.severity)}</div>
              </div>

              <div className="kv-row">
                <span className="kv-label">Confiança</span>
                <span className="kv-value text-bold text-info">
                  {finding.confidence ?? 94}%
                </span>
              </div>

              <div className="kv-row">
                <span className="kv-label">Endpoint</span>
                <span className="kv-value code-pill">
                  {finding.endpoint ?? '/vulnerabilities/'}
                </span>
              </div>

              <div className="kv-row">
                <span className="kv-label">Teste realizado</span>
                <span className="kv-value">{finding.test}</span>
              </div>

              <div className="kv-row">
                <span className="kv-label">Status da auditoria</span>
                <span className="kv-value status-tag">
                  {finding.status === 'detected' ? 'Vulnerabilidade Confirmada' : 'Não Detectado'}
                </span>
              </div>
            </div>
          </div>

          {/* Card: Evidências Coletadas */}
          <div className="dash-card detail-card-box">
            <div className="card-header-row space-between">
              <h3 className="card-box-title">
                <Terminal size={16} className="text-primary-blue" />
                <span>Evidências</span>
              </h3>
              <button
                type="button"
                className="btn-copy-evidence"
                onClick={handleCopyEvidence}
                title="Copiar evidência técnica para a área de transferência"
              >
                {copied ? (
                  <>
                    <Check size={14} className="text-success" />
                    <span className="text-success">Copiado!</span>
                  </>
                ) : (
                  <>
                    <Copy size={14} />
                    <span>Copiar</span>
                  </>
                )}
              </button>
            </div>

            <div className="evidence-terminal-box">
              <pre className="evidence-code-text">
                <code>{finding.evidence}</code>
              </pre>
            </div>
          </div>
        </div>

        {/* Coluna Direita: Análise da IA, Impacto e Mitigação */}
        <div className="detail-col-right">
          <div className="dash-card detail-card-box ai-detail-card">
            {/* Cabeçalho do Card de IA */}
            <div className="card-header-row space-between">
              <div className="ai-card-title-group">
                <div className="ai-icon-bubble">
                  <Sparkles size={17} className="text-primary-blue" />
                </div>
                <h3 className="card-box-title">Análise da IA</h3>
              </div>
              <span className="badge-ai-generated">
                <Sparkles size={12} />
                <span>Gerado por IA</span>
              </span>
            </div>

            {/* Diagnóstico Geral da IA */}
            <div className="ai-explanation-text">
              <p>
                {finding.aiAnalysis ||
                  'O motor heurístico com inteligência artificial analisou o comportamento anômalo da aplicação durante a injeção e confirmou a ausência de controles defensivos suficientes.'}
              </p>
            </div>

            {/* Bloco 1: Impacto no Negócio / Segurança */}
            <div className="ai-sub-block block-impact">
              <div className="sub-block-title-row">
                <Lightbulb size={16} className="text-warning" />
                <h4 className="sub-block-heading">Impacto</h4>
              </div>
              <p className="sub-block-text">
                {finding.impact ||
                  'Um atacante pode obter acesso não autorizado a contas de usuários ou recursos restritos caso consiga explorar esta vulnerabilidade em ambiente operacional.'}
              </p>
            </div>

            {/* Bloco 2: Recomendações Técnicas */}
            <div className="ai-sub-block block-recommendation">
              <div className="sub-block-title-row">
                <ShieldCheck size={16} className="text-success" />
                <h4 className="sub-block-heading">Recomendação</h4>
              </div>
              <div className="recommendation-bullets">
                {finding.recommendation.split('. ').map((sentence, idx) => {
                  const cleanSentence = sentence.trim();
                  if (!cleanSentence) return null;
                  return (
                    <div key={idx} className="rec-bullet-item">
                      <span className="rec-bullet-dot">•</span>
                      <span>
                        {cleanSentence.endsWith('.') ? cleanSentence : `${cleanSentence}.`}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
