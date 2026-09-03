import React, { useState } from 'react';
import { Header } from './components/Header';
import { ScanInput } from './components/ScanInput';
import { LoadingIndicator } from './components/LoadingIndicator';
import { MetricsSummary } from './components/MetricsSummary';
import { FindingCard } from './components/FindingCard';
import { AIExecutiveReport } from './components/AIExecutiveReport';
import { ExportButtons } from './components/ExportButtons';
import type { ScanResult, SecurityLevel } from './types/scanner';
import { runMockScan, runRealScan } from './services/scanService';

export const App: React.FC = () => {
  const [url, setUrl] = useState<string>('http://192.168.100.165');
  const [securityLevel, setSecurityLevel] = useState<SecurityLevel>('medium');
  const [isRealBackend, setIsRealBackend] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [currentStep, setCurrentStep] = useState<string>('Iniciando análise...');
  const [progressPercent, setProgressPercent] = useState<number>(10);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);

  const handleStartScan = async () => {
    setIsLoading(true);
    setCurrentStep('Iniciando conexão com a aplicação alvo...');
    setProgressPercent(10);

    try {
      let result: ScanResult;
      if (isRealBackend) {
        result = await runRealScan(url, securityLevel, (step, percent) => {
          setCurrentStep(step);
          setProgressPercent(percent);
        });
      } else {
        result = await runMockScan(url, securityLevel, (step, percent) => {
          setCurrentStep(step);
          setProgressPercent(percent);
        });
      }

      setScanResult(result);
    } catch (err) {
      console.error('Erro na execução do scan:', err);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="app-layout">
      <div className="main-container">
        {/* 1. Cabeçalho */}
        <Header />

        {/* 2. Painel de Entrada */}
        <ScanInput
          url={url}
          setUrl={setUrl}
          securityLevel={securityLevel}
          setSecurityLevel={setSecurityLevel}
          isRealBackend={isRealBackend}
          setIsRealBackend={setIsRealBackend}
          isLoading={isLoading}
          onStartScan={handleStartScan}
        />

        {/* 3. Indicador de Status (Loading) */}
        {isLoading && (
          <LoadingIndicator
            currentStep={currentStep}
            progressPercent={progressPercent}
          />
        )}

        {/* 4. Painel de Resultados (Output) */}
        {scanResult && !isLoading && (
          <main className="results-container">
            {/* Métricas Gerais */}
            <MetricsSummary
              summary={scanResult.summary}
              targetUrl={scanResult.targetUrl}
              securityLevel={scanResult.securityLevel}
              timestamp={scanResult.timestamp}
            />

            {/* Lista de Cards Expansíveis (Accordions) */}
            <section className="findings-section">
              <div className="section-header-row">
                <h3 className="section-heading">
                  Vulnerabilidades Identificadas ({scanResult.findings.length})
                </h3>
                <span className="section-subheading">
                  Clique em cada card para inspecionar a evidência e a recomendação de correção
                </span>
              </div>

              <div className="findings-list">
                {scanResult.findings.map((finding, idx) => (
                  <FindingCard
                    key={finding.id || idx}
                    finding={finding}
                    index={idx + 1}
                  />
                ))}
              </div>
            </section>

            {/* Seção Executiva de IA */}
            {scanResult.aiExecutiveReport && (
              <AIExecutiveReport reportText={scanResult.aiExecutiveReport} />
            )}

            {/* 5. Exportação de Relatórios */}
            <ExportButtons result={scanResult} />
          </main>
        )}

        {/* Rodapé institucional */}
        <footer className="page-footer">
          <p>SecureScan — Sistema de Varredura Automatizada & Interpretação com Inteligência Artificial</p>
          <p>Trabalho de Conclusão de Curso (TCC) em Ciência da Computação — 2026</p>
        </footer>
      </div>
    </div>
  );
};

export default App;
