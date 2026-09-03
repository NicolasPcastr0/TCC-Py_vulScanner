import React from 'react';
import { FileJson, FileSpreadsheet, Printer } from 'lucide-react';
import type { ScanResult } from '../types/scanner';
import { exportToJson, exportToCsv } from '../services/scanService';

interface ExportButtonsProps {
  result: ScanResult;
}

export const ExportButtons: React.FC<ExportButtonsProps> = ({ result }) => {
  const handlePrint = () => {
    window.print();
  };

  return (
    <footer className="export-footer">
      <div className="export-title-row">
        <h4 className="export-heading">Exportar Relatório de Auditoria</h4>
        <p className="export-subtext">Faça o download dos artefatos estruturados para documentação do TCC e conformidade</p>
      </div>

      <div className="export-actions-row">
        <button
          onClick={() => exportToJson(result)}
          className="btn-export btn-json"
          title="Baixar em formato JSON estruturado (machine-readable)"
        >
          <FileJson size={18} />
          <span>Baixar Relatório (.JSON)</span>
        </button>

        <button
          onClick={() => exportToCsv(result)}
          className="btn-export btn-csv"
          title="Baixar em formato CSV para planilhas Excel"
        >
          <FileSpreadsheet size={18} />
          <span>Baixar Relatório (.CSV)</span>
        </button>

        <button
          onClick={handlePrint}
          className="btn-export btn-print"
          title="Salvar ou imprimir relatório em PDF"
        >
          <Printer size={18} />
          <span>Imprimir / PDF</span>
        </button>
      </div>
    </footer>
  );
};
