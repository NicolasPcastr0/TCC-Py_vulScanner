import React from 'react';
import { ShieldCheck, Activity } from 'lucide-react';

export const Header: React.FC = () => {
  return (
    <header className="header-container">
      <div className="header-content">
        <div className="logo-wrapper">
          <div className="shield-icon-bg">
            <ShieldCheck className="shield-icon" size={32} />
          </div>
          <div>
            <div className="title-row">
              <h1 className="main-title">SECURESCAN</h1>
              <span className="version-badge">v1.0.0</span>
            </div>
            <p className="subtitle">Auditoria Dinâmica de Segurança em Aplicações Web</p>
          </div>
        </div>

        <div className="status-pill">
          <Activity size={14} className="pulse-icon" />
          <span>OWASP Top 10 + Camada de IA</span>
        </div>
      </div>
    </header>
  );
};
