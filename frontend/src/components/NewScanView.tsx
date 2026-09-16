import React, { useState } from 'react';
import {
  Globe,
  ShieldAlert,
  Shield,
  CheckSquare,
  Square,
  ArrowRight,
  Server,
  Sparkles,
  Loader2
} from 'lucide-react';
import type { SecurityLevel, ModuleKey, TargetPlatform } from '../types/scanner';

interface NewScanViewProps {
  url: string;
  setUrl: (url: string) => void;
  securityLevel: SecurityLevel;
  setSecurityLevel: (lvl: SecurityLevel) => void;
  targetPlatform: TargetPlatform;
  setTargetPlatform: (p: TargetPlatform) => void;
  isRealBackend: boolean;
  setIsRealBackend: (real: boolean) => void;
  isLoading: boolean;
  currentStep: string;
  progressPercent: number;
  onStartScan: (selectedModules: ModuleKey[]) => void;
}

interface ModuleOption {
  key: ModuleKey;
  code: string;
  name: string;
  description: string;
  severityLabel: string;
  severityClass: string;
  isReady: boolean;
}

export const NewScanView: React.FC<NewScanViewProps> = ({
  url,
  setUrl,
  securityLevel,
  setSecurityLevel,
  targetPlatform,
  setTargetPlatform,
  isRealBackend,
  setIsRealBackend,
  isLoading,
  currentStep,
  progressPercent,
  onStartScan
}) => {
  // Módulos disponíveis com seus respectivos metadados
  const availableModules: ModuleOption[] = [
    {
      key: 'A03',
      code: 'A03 - Injection',
      name: 'Vulnerabilidades de Injeção',
      description: 'Testa injeção de SQL (Error e Boolean), injeção de comandos de SO e XSS refletido com evasão.',
      severityLabel: 'Alta / Crítica',
      severityClass: 'badge-high',
      isReady: true
    },
    {
      key: 'A05',
      code: 'A05 - Security Misconfiguration',
      name: 'Configurações Incorretas',
      description: 'Audita cabeçalhos de segurança HTTP (CSP, XFO, HSTS, MIME) e vazamento de versão do servidor.',
      severityLabel: 'Média / Baixa',
      severityClass: 'badge-medium',
      isReady: true
    },
    {
      key: 'A07',
      code: 'A07 - Authentication Failures',
      name: 'Falhas de Autenticação',
      description: 'Testa força bruta em logins, tolerância a ataques de dicionário e ausência de bloqueio de conta.',
      severityLabel: 'Crítica',
      severityClass: 'badge-critical',
      isReady: true
    }
  ];

  const [selectedModules, setSelectedModules] = useState<ModuleKey[]>(['A03', 'A05', 'A07']);

  const toggleModule = (key: ModuleKey, isReady: boolean) => {
    if (!isReady) return;
    if (selectedModules.includes(key)) {
      if (selectedModules.length > 1) {
        setSelectedModules(selectedModules.filter((m) => m !== key));
      }
    } else {
      setSelectedModules([...selectedModules, key]);
    }
  };

  const handleSelectAll = () => {
    const readyKeys = availableModules.filter((m) => m.isReady).map((m) => m.key);
    if (selectedModules.length === readyKeys.length) {
      setSelectedModules(['A03']); // Mantém pelo menos um ativo
    } else {
      setSelectedModules(readyKeys);
    }
  };

  return (
    <div className="new-scan-layout">
      {/* 1. Cabeçalho */}
      <header className="view-header">
        <div>
          <h1 className="view-title">Nova análise</h1>
          <p className="view-subtitle">
            Configure os parâmetros e selecione os módulos que deseja testar na aplicação alvo.
          </p>
        </div>
      </header>

      {/* 2. Formulário Principal */}
      <div className="new-scan-container">
        {/* Seção 1: Informações da Aplicação */}
        <section className="form-section-card">
          <div className="section-title-row">
            <Globe size={18} className="text-primary-blue" />
            <h2 className="form-section-title">1. Informações da aplicação</h2>
          </div>

          {/* Seletor de Perfil do Alvo (DVWA vs WordPress) */}
          <div style={{ marginBottom: '1.25rem' }}>
            <label className="form-label">Plataforma / Perfil do Alvo</label>
            <div className="execution-mode-toggle" style={{ maxWidth: '440px' }}>
              <button
                type="button"
                className={`mode-pill ${targetPlatform === 'dvwa' ? 'active' : ''}`}
                onClick={() => {
                  setTargetPlatform('dvwa');
                  setUrl('http://192.168.100.165');
                }}
                disabled={isLoading}
              >
                <Shield size={14} />
                <span>DVWA (Lab Didático)</span>
              </button>
              <button
                type="button"
                className={`mode-pill ${targetPlatform === 'wordpress' ? 'active' : ''}`}
                onClick={() => {
                  setTargetPlatform('wordpress');
                  setUrl('http://192.168.100.165:8080');
                }}
                disabled={isLoading}
              >
                <Globe size={14} />
                <span>WordPress (CMS Corporativo)</span>
              </button>
            </div>
            <span className="input-helper-text">
              {targetPlatform === 'dvwa'
                ? 'Laboratório com níveis de segurança configuráveis (Low, Medium, High).'
                : 'CMS WordPress em produção na porta 8080 (REST API, XML-RPC, wp-login).'}
            </span>
          </div>

          <div className="form-grid-inputs">
            {/* Input URL */}
            <div className="form-group flex-2">
              <label htmlFor="target-url" className="form-label">
                URL da aplicação
              </label>
              <div className="input-with-icon">
                <input
                  id="target-url"
                  type="url"
                  className="input-text"
                  placeholder="Exemplo: http://localhost ou http://alvo.com"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  disabled={isLoading}
                />
              </div>
              <span className="input-helper-text">
                {targetPlatform === 'dvwa' ? (
                  <>Alvo padrão: <code>http://192.168.100.165</code> (DVWA em Docker)</>
                ) : (
                  <>Alvo WordPress: <code>http://192.168.100.165:8080</code> (CMS em Docker)</>
                )}
              </span>
            </div>

            {/* Seletor de Nível de Segurança ou Perfil do CMS */}
            <div className="form-group flex-1">
              <label htmlFor="security-level" className="form-label">
                {targetPlatform === 'dvwa' ? 'Nível de Defesa (DVWA)' : 'Perfil de Defesa (CMS)'}
              </label>
              {targetPlatform === 'dvwa' ? (
                <div className="select-wrapper">
                  <select
                    id="security-level"
                    className="input-select"
                    value={securityLevel}
                    onChange={(e) => setSecurityLevel(e.target.value as SecurityLevel)}
                    disabled={isLoading}
                  >
                    <option value="low">Low (Trivial / Sem defesas)</option>
                    <option value="medium">Medium (Defesas parciais / Evasão)</option>
                    <option value="high">High (Defesas avançadas / Evasão complexa)</option>
                  </select>
                </div>
              ) : (
                <input
                  type="text"
                  className="input-text"
                  value="WordPress v6.x (Apache / MariaDB)"
                  readOnly
                  style={{ cursor: 'default', color: '#93c5fd', fontWeight: 600 }}
                />
              )}
              <span className="input-helper-text">
                {targetPlatform === 'dvwa'
                  ? 'Define a robustez das proteções e os vetores de evasão utilizados.'
                  : 'Auditoria de cabeçalhos, REST API, XML-RPC e formulário wp-login.'}
              </span>
            </div>

            {/* Switch de Modo de Execução */}
            <div className="form-group flex-1">
              <label className="form-label">Modo de Execução</label>
              <div className="execution-mode-toggle">
                <button
                  type="button"
                  className={`mode-pill ${!isRealBackend ? 'active' : ''}`}
                  onClick={() => setIsRealBackend(false)}
                  disabled={isLoading}
                >
                  <Sparkles size={14} />
                  <span>Simulação</span>
                </button>
                <button
                  type="button"
                  className={`mode-pill ${isRealBackend ? 'active' : ''}`}
                  onClick={() => setIsRealBackend(true)}
                  disabled={isLoading}
                >
                  <Server size={14} />
                  <span>Backend Real</span>
                </button>
              </div>
              <span className="input-helper-text">
                {isRealBackend
                  ? 'Dispara requisições HTTP reais via Flask e analisa com Gemini API.'
                  : 'Modo seguro para demonstrações instantâneas de TCC sem dependência da VM.'}
              </span>
            </div>
          </div>
        </section>

        {/* Seção 2: Módulos de Análise */}
        <section className="form-section-card">
          <div className="section-title-row space-between">
            <div className="section-title-left">
              <ShieldAlert size={18} className="text-primary-blue" />
              <h2 className="form-section-title">2. Módulos de análise</h2>
            </div>
            <button
              type="button"
              className="btn-text-action"
              onClick={handleSelectAll}
              disabled={isLoading}
            >
              {selectedModules.length === availableModules.filter((m) => m.isReady).length
                ? 'Limpar seleção'
                : 'Selecionar todos'}
            </button>
          </div>

          <div className="modules-cards-grid">
            {availableModules.map((mod) => {
              const isSelected = selectedModules.includes(mod.key);
              const isDisabled = !mod.isReady || isLoading;

              return (
                <div
                  key={mod.key}
                  className={`module-select-card ${isSelected ? 'selected' : ''} ${
                    isDisabled ? 'disabled' : ''
                  }`}
                  onClick={() => toggleModule(mod.key, mod.isReady)}
                >
                  <div className="module-card-header">
                    <div className="module-checkbox-row">
                      {isSelected ? (
                        <CheckSquare size={18} className="checkbox-icon checked" />
                      ) : (
                        <Square size={18} className="checkbox-icon unchecked" />
                      )}
                      <span className="module-code-title">{mod.code}</span>
                    </div>
                    <span className={`module-sev-badge ${mod.severityClass}`}>
                      {mod.severityLabel}
                    </span>
                  </div>

                  <p className="module-description-text">{mod.description}</p>
                </div>
              );
            })}
          </div>
        </section>

        {/* Indicador de Progresso durante a Execução */}
        {isLoading && (
          <section className="form-section-card scanning-progress-box">
            <div className="progress-header-row">
              <div className="progress-info-left">
                <Loader2 size={20} className="spinner-icon" />
                <span className="progress-step-label">{currentStep}</span>
              </div>
              <span className="progress-percent-label">{progressPercent}%</span>
            </div>
            <div className="progress-track">
              <div
                className="progress-fill-bar"
                style={{ width: `${progressPercent}%` }}
              />
            </div>
          </section>
        )}

        {/* Rodapé de Ação: Iniciar Análise */}
        <div className="form-actions-row">
          <button
            type="button"
            className="btn-start-scan"
            onClick={() => onStartScan(selectedModules)}
            disabled={isLoading || !url.trim()}
          >
            {isLoading ? (
              <>
                <Loader2 size={18} className="spinner-icon" />
                <span>Executando auditoria...</span>
              </>
            ) : (
              <>
                <span>Iniciar análise</span>
                <ArrowRight size={18} />
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};
