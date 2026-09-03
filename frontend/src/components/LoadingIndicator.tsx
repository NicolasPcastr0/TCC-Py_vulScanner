import { Loader2 } from 'lucide-react';

interface LoadingIndicatorProps {
  currentStep: string;
  progressPercent: number;
}

export const LoadingIndicator: React.FC<LoadingIndicatorProps> = ({
  currentStep,
  progressPercent
}) => {
  return (
    <div className="loading-card">
      <div className="spinner-wrapper">
        <div className="pulse-ring"></div>
        <Loader2 className="spinner-icon" size={44} />
      </div>

      <div className="loading-text-content">
        <h3 className="loading-title">Executando testes de segurança...</h3>
        <p className="loading-step-text">{currentStep}</p>
      </div>

      <div className="progress-bar-container">
        <div
          className="progress-bar-fill"
          style={{ width: `${progressPercent}%` }}
        ></div>
      </div>
      <div className="progress-footer">
        <span className="step-label">Injeção dinâmica & auditoria de controle</span>
        <span className="percent-label">{progressPercent}%</span>
      </div>
    </div>
  );
};
