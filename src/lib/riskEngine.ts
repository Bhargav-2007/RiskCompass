import { assetLinks, assets, threatSignals } from '../data/demoData'
import type { Asset, AttackPath, FactorContribution, Forecast, Priority, RiskResult, Vulnerability } from '../types'

const clamp = (value: number, min = 0, max = 100) => Math.min(max, Math.max(min, value))
const assetCriticality: Record<Asset['tier'], number> = { 'Crown jewel': 100, Critical: 80, Important: 55, Standard: 25 }
const exposureScore: Record<Asset['exposure'], number> = { 'Internet-facing': 100, 'Partner-facing': 70, Internal: 35, Isolated: 5 }

export const priorityFor = (score: number): Priority => score >= 85 ? 'P0' : score >= 70 ? 'P1' : score >= 45 ? 'P2' : 'P3'
export const vulnerabilityAgeRisk = (publishedAt: string, today = new Date('2026-08-16')) => clamp((today.getTime() - new Date(publishedAt).getTime()) / 86_400_000 / 3.65)

export function forecastFor(vulnerability: Vulnerability): Forecast {
  const momentum = threatSignals.find(signal => signal.vulnerabilityId === vulnerability.id)?.epssMomentum ?? 0
  const seed = vulnerability.epss * 100 * 0.55 + vulnerability.threatActivity * 0.18 + vulnerability.exploitAvailability * 0.14 + (vulnerability.kev ? 16 : 0) + momentum * 0.45
  const day30 = clamp(seed)
  return { day30: Math.round(day30), day60: Math.round(clamp(day30 + 9 + momentum * 0.3)), day90: Math.round(clamp(day30 + 18 + momentum * 0.55)) }
}

export function attackPathFor(vulnerability: Vulnerability, asset: Asset): AttackPath {
  const crownJewels = new Set(assets.filter(candidate => candidate.tier === 'Crown jewel').map(candidate => candidate.id))
  const visited = new Set([asset.id]); const queue: { id: string; route: string[] }[] = [{ id: asset.id, route: [asset.name] }]
  while (queue.length) {
    const current = queue.shift()!
    if (crownJewels.has(current.id)) {
      const probability = clamp(30 + vulnerability.exploitAvailability * .3 + vulnerability.threatActivity * .25 - (current.route.length - 1) * 9)
      return { vulnerabilityId: vulnerability.id, assetId: asset.id, route: current.route, probability: Math.round(probability), adjustment: Math.round(Math.min(8, probability * .08)), reachableCrownJewel: true }
    }
    for (const [left, right] of assetLinks) {
      const next = left === current.id ? right : right === current.id ? left : undefined
      if (next && !visited.has(next)) { visited.add(next); queue.push({ id: next, route: [...current.route, assets.find(candidate => candidate.id === next)!.name] }) }
    }
  }
  return { vulnerabilityId: vulnerability.id, assetId: asset.id, route: [asset.name], probability: 8, adjustment: 1, reachableCrownJewel: false }
}

export function scoreVulnerability(vulnerability: Vulnerability, asset: Asset): RiskResult {
  const values: [string, number, number][] = [
    ['CVSS severity', vulnerability.cvss * 10, .18], ['EPSS likelihood', vulnerability.epss * 100, .22], ['CISA KEV status', vulnerability.kev ? 100 : 0, .12],
    ['Asset criticality', assetCriticality[asset.tier], .14], ['Asset exposure', exposureScore[asset.exposure], .10], ['Exploit availability', vulnerability.exploitAvailability, .08],
    ['Threat activity', vulnerability.threatActivity, .08], ['Vulnerability age', vulnerabilityAgeRisk(vulnerability.publishedAt), .03], ['Business impact', asset.businessImpact, .05]
  ]
  const contributions: FactorContribution[] = values.map(([label, value, weight]) => ({ label, value: Math.round(value), weight, points: Number((value * weight).toFixed(1)) }))
  const baseScore = contributions.reduce((total, item) => total + item.points, 0)
  const attackPath = attackPathFor(vulnerability, asset); const score = Math.round(clamp(baseScore + attackPath.adjustment))
  const topFactors = [...contributions].sort((a, b) => b.points - a.points).slice(0, 3).map(item => item.label.toLowerCase())
  const priority = priorityFor(score)
  return { vulnerabilityId: vulnerability.id, score, priority, baseScore: Number(baseScore.toFixed(1)), attackPath, forecast: forecastFor(vulnerability), contributions, explanation: `${priority} priority because ${topFactors.join(', ')} materially increase exploitation impact${attackPath.reachableCrownJewel ? ' and a path to a crown-jewel asset is reachable' : ''}.` }
}

export function baselineScore(vulnerability: Vulnerability, mode: 'cvss' | 'cvssEpss' | 'cvssEpssKev') {
  const cvss = vulnerability.cvss * 10; const epss = vulnerability.epss * 100; const kev = vulnerability.kev ? 100 : 0
  return mode === 'cvss' ? cvss : mode === 'cvssEpss' ? cvss * .6 + epss * .4 : cvss * .5 + epss * .3 + kev * .2
}
