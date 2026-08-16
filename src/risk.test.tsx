import { describe, expect, it } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import App from './App'
import { assets, vulnerabilities } from './data/demoData'
import { benchmarks } from './lib/metrics'
import { attackPathFor, forecastFor, priorityFor, scoreVulnerability } from './lib/riskEngine'

describe('RiskCompass scoring and UI', () => {
  it('normalizes contextual scores and caps attack-path adjustment', () => { const v=vulnerabilities[1], result=scoreVulnerability(v,assets.find(a=>a.id===v.assetId)!); expect(result.contributions).toHaveLength(9); expect(result.score).toBeLessThanOrEqual(100); expect(result.attackPath.adjustment).toBeLessThanOrEqual(8) })
  it('assigns priority thresholds and bounded forecasts', () => { expect(priorityFor(85)).toBe('P0'); expect(priorityFor(70)).toBe('P1'); expect(priorityFor(45)).toBe('P2'); expect(priorityFor(44)).toBe('P3'); const f=forecastFor(vulnerabilities[0]); expect(f.day30).toBeGreaterThanOrEqual(0); expect(f.day90).toBeLessThanOrEqual(100) })
  it('handles an isolated asset path', () => { const v=vulnerabilities.find(v=>v.assetId==='a5')!, p=attackPathFor(v,assets.find(a=>a.id==='a5')!); expect(p.probability).toBeGreaterThanOrEqual(0); expect(p.adjustment).toBeLessThanOrEqual(8) })
  it('calculates every evaluation baseline', () => { const values=benchmarks(vulnerabilities,assets); expect(values).toHaveLength(4); values.forEach(v=>expect(v.rocAuc).toBeLessThanOrEqual(1)) })
  it('filters and runs a local patch canary', () => { render(<App/>); expect(screen.getByText(/Seeded synthetic demo data/i)).toBeInTheDocument(); fireEvent.change(screen.getByLabelText(/Filter by priority/i),{target:{value:'P0'}}); expect(screen.getAllByText('P0').length).toBeGreaterThan(0); fireEvent.click(screen.getByRole('button',{name:/Run 20% patch canary/i})); expect(screen.getByText(/Canary regression|20% canary healthy/i)).toBeInTheDocument() })
})
