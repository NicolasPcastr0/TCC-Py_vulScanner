import React from 'react';
import {
  LayoutDashboard,
  PlayCircle,
  ShieldAlert,
  Settings,
  Shield,
  LogOut,
  User
} from 'lucide-react';
import type { TabType } from '../types/scanner';

interface SidebarProps {
  activeTab: TabType;
  onSelectTab: (tab: TabType) => void;
  findingsCount?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onSelectTab,
  findingsCount = 0
}) => {
  const navItems = [
    {
      id: 'dashboard' as TabType,
      label: 'Dashboard',
      icon: LayoutDashboard
    },
    {
      id: 'new-scan' as TabType,
      label: 'Nova análise',
      icon: PlayCircle
    },
    {
      id: 'findings' as TabType,
      label: 'Vulnerabilidades',
      icon: ShieldAlert,
      badge: findingsCount > 0 ? findingsCount : undefined
    },
    {
      id: 'settings' as TabType,
      label: 'Configurações',
      icon: Settings
    }
  ];

  return (
    <aside className="app-sidebar">
      {/* 1. Logotipo Superior */}
      <div className="sidebar-brand">
        <div className="brand-icon-wrapper">
          <Shield className="brand-icon" size={24} />
        </div>
        <div className="brand-text">
          <span className="brand-title">SecureScan</span>
        </div>
      </div>

      {/* 2. Menu de Navegação */}
      <nav className="sidebar-nav">
        <ul className="nav-list">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <li key={item.id} className="nav-item">
                <button
                  type="button"
                  className={`nav-button ${isActive ? 'active' : ''}`}
                  onClick={() => onSelectTab(item.id)}
                >
                  <Icon size={19} className="nav-icon" />
                  <span className="nav-label">{item.label}</span>
                  {item.badge !== undefined && (
                    <span className="nav-badge">{item.badge}</span>
                  )}
                </button>
              </li>
            );
          })}
        </ul>
      </nav>

      {/* 3. Perfil do Usuário no Rodapé */}
      <div className="sidebar-user-footer">
        <div className="user-info-row">
          <div className="user-avatar">
            <User size={18} />
          </div>
          <div className="user-details">
            <span className="user-name">Nicolas</span>
            <span className="user-role">Desenvolvedor</span>
          </div>
        </div>
        <button
          type="button"
          className="btn-user-action"
          title="Encerrar sessão"
          onClick={() => alert('Sessão ativa no ambiente local do SecureScan.')}
        >
          <LogOut size={16} />
        </button>
      </div>
    </aside>
  );
};
