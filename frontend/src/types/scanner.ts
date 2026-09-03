export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'safe';

export type Status = 'detected' | 'not_detected' | 'error';

export type SecurityLevel = 'low' | 'medium';

export interface Finding {
  id: string;
  category: string;
  name: string;
  test: string;
  status: Status;
  severity: Severity;
  evidence: string;
  recommendation: string;
}

export interface ScanSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  safe: number;
}

export interface ScanResult {
  targetUrl: string;
  securityLevel: SecurityLevel;
  timestamp: string;
  durationSeconds: number;
  summary: ScanSummary;
  findings: Finding[];
  aiExecutiveReport?: string;
}
