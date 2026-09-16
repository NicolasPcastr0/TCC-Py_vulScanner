import React, { useState } from 'react';
import { Sidebar } from './components/Sidebar';
import { DashboardView } from './components/DashboardView';
import { NewScanView } from './components/NewScanView';
import { FindingsListView } from './components/FindingsListView';
import { FindingDetailView } from './components/FindingDetailView';
import { AIExecutiveReport } from './components/AIExecutiveReport';
import type { Finding, ModuleKey, ScanResult, SecurityLevel, TabType, TargetPlatform } from './types/scanner';
import { INITIAL_SCAN_RESULT, runMockScan, runRealScan } from './services/scanService';
import { X, Sparkles, Shield, Key } from 'lucide-react';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabType>('dashboard');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [scanResult, setScanResult] = useState<ScanResult>(INITIAL_SCAN_RESULT);
  const [showAiModal, setShowAiModal] = useState<boolean>(false);

  // Estados de entrada do Scanner
  const [url, setUrl] = useState<string>('http://192.168.100.165');
  const [securityLevel, setSecurityLevel] = useState<SecurityLevel>('high');
  const [targetPlatform, setTargetPlatform] = useState<TargetPlatform>('dvwa');
  const [isRealBackend, setIsRealBackend] = useState<boolean>(false);

  // Estados de progresso
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [currentStep, setCurrentStep] = useState<string>('Iniciando análise...');
  const [progressPercent, setProgressPercent] = useState<number>(10);

  // Dispara a execução do scan
  const handleStartScan = async (selectedModules: ModuleKey[]) => {
    setIsLoading(true);
    setCurrentStep('Iniciando conexão com a aplicação alvo...');
    setProgressPercent(10);

    try {
      let result: ScanResult;
      if (isRealBackend) {
        result = await runRealScan(
          url,
          securityLevel,
          (step, percent) => {
            setCurrentStep(step);
            setProgressPercent(percent);
          },
          targetPlatform
        );
      } else {
        result = await runMockScan(
          url,
          securityLevel,
          (step, percent) => {
            setCurrentStep(step);
            setProgressPercent(percent);
          },
          targetPlatform
        );
      }

      // Filtra os achados pelos módulos selecionados
      const filteredFindings = result.findings.filter((f) => {
        const cat = f.category.split(':')[0].trim();
        return selectedModules.some((m) => cat.includes(m));
      });

      const updatedResult: ScanResult = {
        ...result,
        findings: filteredFindings.length > 0 ? filteredFindings : result.findings,
        summary: {
          ...result.summary,
          total: filteredFindings.length > 0 ? filteredFindings.length : result.findings.length
        }
      };

      setScanResult(updatedResult);
      setSelectedFinding(null);
      setActiveTab('findings'); // Redireciona automaticamente para resultados
    } catch (err) {
      console.error('Erro na execução do scan:', err);
    } finally {
      setIsLoading(false);
    }
  };

  // Tratamento da troca de abas pela Sidebar
  const handleSelectTab = (tab: TabType) => {
    setSelectedFinding(null);
    setActiveTab(tab);
  };

  return (
    <div className="app-shell">
      {/* 1. Barra Lateral de Navegação (Fixa à Esquerda) */}
      <Sidebar
        activeTab={activeTab}
        onSelectTab={handleSelectTab}
        findingsCount={scanResult.summary.total}
      />

      {/* 2. Área Central de Conteúdo Dinâmico */}
      <main className="app-main-content">
        {/* Tela 1: Dashboard */}
        {activeTab === 'dashboard' && (
          <DashboardView
            scanResult={scanResult}
            onNavigateToNewScan={() => handleSelectTab('new-scan')}
            onNavigateToFindings={() => handleSelectTab('findings')}
          />
        )}

        {/* Tela 2: Nova Análise */}
        {activeTab === 'new-scan' && (
          <NewScanView
            url={url}
            setUrl={setUrl}
            securityLevel={securityLevel}
            setSecurityLevel={setSecurityLevel}
            targetPlatform={targetPlatform}
            setTargetPlatform={setTargetPlatform}
            isRealBackend={isRealBackend}
            setIsRealBackend={setIsRealBackend}
            isLoading={isLoading}
            currentStep={currentStep}
            progressPercent={progressPercent}
            onStartScan={handleStartScan}
          />
        )}

        {/* Tela 3 & 4: Resultados / Detalhes da Vulnerabilidade */}
        {activeTab === 'findings' && (
          <>
            {selectedFinding ? (
              <FindingDetailView
                finding={selectedFinding}
                onBack={() => setSelectedFinding(null)}
              />
            ) : (
              <FindingsListView
                scanResult={scanResult}
                onBack={() => handleSelectTab('dashboard')}
                onSelectFinding={(f) => setSelectedFinding(f)}
                onOpenAiReport={() => setShowAiModal(true)}
              />
            )}
          </>
        )}

        {/* Tela 5: Configurações do Sistema */}
        {activeTab === 'settings' && (
          <div className="settings-layout">
            <header className="view-header">
              <div>
                <h1 className="view-title">Configurações do SecureScan</h1>
                <p className="view-subtitle">
                  Parâmetros de conexão com IA e ambiente de homologação.
                </p>
              </div>
            </header>

            <div className="settings-grid">
              <div className="dash-card settings-card">
                <div className="settings-header-row">
                  <Key size={18} className="text-primary-blue" />
                  <h3 className="card-heading">API Key da Inteligência Artificial</h3>
                </div>
                <p className="settings-desc">
                  Chave utilizada para alimentar o motor interpretativo Google Gemini.
                </p>
                <div className="settings-input-group">
                  <input
                    type="password"
                    value="AIzaSyA********************"
                    readOnly
                    className="input-text"
                  />
                </div>
                <span className="settings-status-tag">Status: Conectado via OpenRouter/Google AI</span>
              </div>

              <div className="dash-card settings-card">
                <div className="settings-header-row">
                  <Shield size={18} className="text-primary-blue" />
                  <h3 className="card-heading">Alvo Padrão do Laboratório TCC</h3>
                </div>
                <p className="settings-desc">
                  Endereço IP configurado para a máquina virtual do laboratório (DVWA / WordPress em Docker).
                </p>
                <input
                  type="text"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  className="input-text"
                />
              </div>
            </div>
          </div>
        )}
      </main>

      {/* 3. Modal Flutuante para o Relatório Geral da IA */}
      {showAiModal && (
        <div className="modal-backdrop" onClick={() => setShowAiModal(false)}>
          <div className="modal-container" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-title-row">
                <Sparkles size={20} className="text-primary-blue" />
                <h2 className="modal-title">Relatório Técnico Executivo — Google Gemini</h2>
              </div>
              <button
                type="button"
                className="btn-modal-close"
                onClick={() => setShowAiModal(false)}
              >
                <X size={20} />
              </button>
            </div>

            <div className="modal-body-scroll">
              <AIExecutiveReport reportText={scanResult.aiExecutiveReport} />
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default App;
