export type Severity = 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';

export interface Finding {
  rule_id: string;
  title: string;
  severity: Severity;
  weight: number;
  explanation: string;
  evidence: string;
  remediation: string;
  confidence: number;
}

export interface RiskScoreBreakdown {
  total_score: number;
  severity: Severity;
  raw_weighted_sum: number;
  normalized_score: number;
  contributing_findings: Finding[];
  rule_counts_by_severity: Record<string, number>;
  important_limitations: string[];
  recommended_actions: string[];
}

export interface UrlDetails {
  raw_url: string;
  scheme: string;
  hostname: string;
  registered_domain: string;
  subdomains: string[];
  port: number | null;
  path: string;
  query_param_count: number;
  is_ip_address: boolean;
  is_shortener: boolean;
  is_punycode: boolean;
  shannon_entropy: number;
  suspicious_keywords_found: string[];
  has_credentials_in_url: boolean;
  lookalike_target: string | null;
}

export interface EmailDetails {
  sender: string | null;
  sender_domain: string | null;
  display_name: string | null;
  reply_to: string | null;
  subject: string | null;
  extracted_urls: string[];
  suspicious_keywords: string[];
  urgency_detected: boolean;
  credential_harvest_detected: boolean;
  financial_fraud_detected: boolean;
  attachments_referenced: string[];
  spoofing_indicators: string[];
  headers_parsed: Record<string, unknown>;
}

export interface MessageDetails {
  message_type: string;
  char_count: number;
  extracted_urls: string[];
  urgency_indicators: string[];
  delivery_scam_detected: boolean;
  banking_scam_detected: boolean;
  otp_theft_detected: boolean;
  suspicious_action_call: boolean;
}

export interface ThreatIntelResult {
  provider: string;
  status: string;
  indicator: string;
  verdict: string | null;
  positives: number | null;
  total_engines: number | null;
  timestamp: string;
  is_live: boolean;
  details: string;
}

export interface MLPredictionResult {
  model_name: string;
  is_available: boolean;
  prediction: string | null;
  phishing_probability: number | null;
  confidence_interval: string | null;
  features_extracted: Record<string, number> | null;
  model_metrics: Record<string, unknown> | null;
  notes: string;
}

export interface ScanResult {
  scan_id: string;
  scan_type: string;
  timestamp: string;
  input_preview: string;
  risk_score: number;
  severity: Severity;
  analysis_mode: string;
  summary: string;
  findings: Finding[];
  risk_breakdown: RiskScoreBreakdown;
  url_details: UrlDetails | null;
  email_details: EmailDetails | null;
  message_details: MessageDetails | null;
  ml_result: MLPredictionResult | null;
  threat_intel: ThreatIntelResult[];
  checks_completed: string[];
  checks_not_performed: string[];
  limitations: string[];
  recommendations: string[];
}

export interface ScanHistorySummary {
  scan_id: string;
  timestamp: string;
  scan_type: string;
  input_preview: string;
  risk_score: number;
  severity: Severity;
  finding_count: number;
  analysis_mode: string;
  summary: string;
}

export interface DashboardStats {
  total_scans: number;
  low_risk_count: number;
  moderate_risk_count: number;
  high_risk_count: number;
  critical_risk_count: number;
  scans_by_type: Record<string, number>;
  severity_distribution: Record<string, number>;
  top_triggered_rules: Array<Record<string, unknown>>;
  recent_trend: Array<Record<string, unknown>>;
}

export interface HealthStatus {
  status: string;
  ml_model: {
    loaded: boolean;
    path: string;
  };
  database: {
    connected: boolean;
  };
  threat_intel: {
    virustotal_configured: boolean;
    safe_browsing_configured: boolean;
  };
}

export interface DemoSample {
  type: string;
  label: string;
  input: Record<string, string>;
}
