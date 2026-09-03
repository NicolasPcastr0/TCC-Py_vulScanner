import { Globe, Play, Sliders } from 'lucide-react';
import type { SecurityLevel } from '../types/scanner';

interface ScanInputProps {
  url: string;
  setUrl: (url: string) => void;
  securityLevel: SecurityLevel;
  setSecurityLevel: (level: SecurityLevel) => void;
  isRealBackend: boolean;
  setIsRealBackend: (real: boolean) => void;
  isLoading: boolean;
  onStartScan: () => void;
}

export const ScanInput: React.FC<ScanInputProps> = ({
  url,
  setUrl,
  securityLevel,
  setSecurityLevel,
  isRealBackend,
  setIsRealBackend,
  isLoading,
  onStartScan
}) => {
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!isLoading && url.trim()) {
      onStartScan();
    }
  };

  return (
    <section className="scan-input-card">
      <form onSubmit={handleSubmit} className="scan-form">
        <div className="input-row">
          <div className="input-group url-input-group">
            <label htmlFor="target-url" className="input-label">
              <Globe size={15} /> URL da Aplicação Alvo
            </label>
            <div className="input-wrapper">
              <input
                id="target-url"
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="Ex: http://192.168.100.165"
                disabled={isLoading}
                className="text-input"
                required
              />
            </div>
          </div>

          <div className="input-group select-group">
            <label htmlFor="security-level" className="input-label">
              <Sliders size={15} /> Nível DVWA
            </label>
            <select
              id="security-level"
              value={securityLevel}
              onChange={(e) => setSecurityLevel(e.target.value as SecurityLevel)}
              disabled={isLoading}
              className="select-input"
            >
              <option value="low">Low (Sem defesas / Exploração trivial)</option>
              <option value="medium">Medium (Defesas parciais / Evasão de filtros)</option>
            </select>
          </div>
        </div>

        <div className="actions-row">
          <div className="mode-toggle-wrapper">
            <label className="mode-toggle-label">
              <input
                type="checkbox"
                checked={isRealBackend}
                onChange={(e) => setIsRealBackend(e.target.checked)}
                disabled={isLoading}
                className="toggle-checkbox"
              />
              <span className="toggle-text">
                {isRealBackend ? 'Conectar ao Backend Real (localhost:5000)' : 'Modo Demonstração / Simulado'}
              </span>
            </label>
          </div>

          <button
            type="submit"
            disabled={isLoading || !url.trim()}
            className="btn-primary"
          >
            <Play size={18} fill="currentColor" />
            <span>{isLoading ? 'Executando...' : 'Iniciar Scan'}</span>
          </button>
        </div>
      </form>
    </section>
  );
};
