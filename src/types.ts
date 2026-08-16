export type Priority = 'P0' | 'P1' | 'P2' | 'P3'
export type AssetTier = 'Crown jewel' | 'Critical' | 'Important' | 'Standard'
export type Exposure = 'Internet-facing' | 'Partner-facing' | 'Internal' | 'Isolated'
export interface Asset { id: string; name: string; type: string; owner: string; tier: AssetTier; exposure: Exposure; businessImpact: number; dataSensitivity: string }
export interface ThreatSignal { id: string; vulnerabilityId: string; velocity: number; epssMomentum: number; source: string; observedAt: string }
export interface Vulnerability { id: string; title: string; product: string; cvss: number; epss: number; kev: boolean; cwe: string; exploitAvailability: number; threatActivity: number; publishedAt: string; assetId: string; exploited: boolean; status: 'Open' | 'Testing' | 'Remediated'; recommendation: string }
export interface FactorContribution { label: string; value: number; weight: number; points: number }
export interface Forecast { day30: number; day60: number; day90: number }
export interface AttackPath { vulnerabilityId: string; assetId: string; route: string[]; probability: number; adjustment: number; reachableCrownJewel: boolean }
export interface RiskResult { vulnerabilityId: string; score: number; priority: Priority; baseScore: number; attackPath: AttackPath; forecast: Forecast; contributions: FactorContribution[]; explanation: string }
export interface PatchTest { vulnerabilityId: string; outcome: 'passed' | 'failed'; canaryCoverage: number; riskReduction: number; note: string }
export interface BenchmarkResult { model: string; precisionAtK: number; recallAtK: number; f1: number; rocAuc: number; prAuc: number; spearman: number; topKHits: number; falsePriorityRate: number; workloadReduction: number }
