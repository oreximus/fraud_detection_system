export const THREAT_SCORE_ALLOW = 0.30;
export const THREAT_SCORE_WARN = 0.60;
export const THREAT_SCORE_QUARANTINE = 0.85;
export const THREAT_SCORE_BLOCK = 1.00;

export enum ThreatLevel {
  SAFE = 'SAFE',
  SUSPICIOUS = 'SUSPICIOUS',
  PHISHING = 'PHISHING',
  SCAM = 'SCAM',
}

export enum ActionType {
  ALLOW = 'ALLOW',
  WARN = 'WARN',
  QUARANTINE = 'QUARANTINE',
  BLOCK = 'BLOCK',
}

export enum NotificationLevel {
  NONE = 'NONE',
  SOFT = 'SOFT',
  ALERT = 'ALERT',
  FULL = 'FULL',
}

export interface ThreatScore {
  score: number;
  level: ThreatLevel;
  confidence: number;
}

export interface DetectionResult {
  id: string;
  timestamp: number;
  source: MessageSource;
  content: string;
  threatScore: ThreatScore;
  action: ActionType;
  notificationLevel: NotificationLevel;
  explanation: string;
  detectedIndicators: Indicator[];
}

export interface Indicator {
  type: IndicatorType;
  value: string;
  description: string;
}

export enum IndicatorType {
  URL = 'URL',
  PHONE = 'PHONE',
  EMAIL = 'EMAIL',
  KEYWORD = 'KEYWORD',
  PATTERN = 'PATTERN',
}

export enum MessageSource {
  SMS = 'SMS',
  EMAIL = 'EMAIL',
  BROWSER = 'BROWSER',
}

export interface CommunityReport {
  id: string;
  hash: string;
  threatScore: number;
  timestamp: number;
  source: MessageSource;
  indicatorType: IndicatorType;
}

export interface DetectionPipelineConfig {
  enableQuickScan: boolean;
  enableDeepScan: boolean;
  enableCommunityReporting: boolean;
  mlModelTimeout: number;
  maxIndicators: number;
}

export const DEFAULT_PIPELINE_CONFIG: DetectionPipelineConfig = {
  enableQuickScan: true,
  enableDeepScan: true,
  enableCommunityReporting: true,
  mlModelTimeout: 5000,
  maxIndicators: 10,
};

export function scoreToAction(score: number): ActionType {
  if (score <= THREAT_SCORE_ALLOW) return ActionType.ALLOW;
  if (score <= THREAT_SCORE_WARN) return ActionType.WARN;
  if (score <= THREAT_SCORE_QUARANTINE) return ActionType.QUARANTINE;
  return ActionType.BLOCK;
}

export function scoreToNotificationLevel(score: number): NotificationLevel {
  if (score <= THREAT_SCORE_ALLOW) return NotificationLevel.NONE;
  if (score <= THREAT_SCORE_WARN) return NotificationLevel.SOFT;
  if (score <= THREAT_SCORE_QUARANTINE) return NotificationLevel.ALERT;
  return NotificationLevel.FULL;
}

export function scoreToThreatLevel(score: number): ThreatLevel {
  if (score <= THREAT_SCORE_ALLOW) return ThreatLevel.SAFE;
  if (score <= THREAT_SCORE_WARN) return ThreatLevel.SUSPICIOUS;
  if (score <= THREAT_SCORE_QUARANTINE) return ThreatLevel.PHISHING;
  return ThreatLevel.SCAM;
}

export function generateDetectionId(): string {
  return `det_${Date.now()}_${Math.random().toString(36).substring(2, 11)}`;
}

export function generateReportId(): string {
  return `rpt_${Date.now()}_${Math.random().toString(36).substring(2, 11)}`;
}