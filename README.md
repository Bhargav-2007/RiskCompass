# RiskCompass

RiskCompass is a static, browser-based MVP that turns vulnerability volume into a contextual remediation queue for SOC teams. It is defensive only: it performs no scanning, exploitation, credential handling, live feeds, or external integrations.

## Included capabilities

- Transparent Dynamic Risk scoring with CVSS, EPSS, CISA KEV, asset context, exploit and threat signals, age, and business impact.
- P0-P3 queue, score rationale, 30/60/90-day forecast, attack-path adjustment, and local patch-canary simulation.
- Comparison of CVSS-only, CVSS+EPSS, CVSS+EPSS+KEV, and Dynamic Risk on clearly labelled synthetic data.
- Production roadmap for threat intelligence, federated learning, SOAR, honeypots, edge scoring, DevSecOps, industry thresholds, and auditability.

## Local terminal workflow

```bash
pnpm install
pnpm test
pnpm run dev
pnpm run build
```

All data and state remain in the browser; reload resets patch simulation outcomes.

## GitHub Pages

Push to `Bhargav-2007/RiskCompass`, enable **GitHub Actions** as the Pages source, and push to `main`. The workflow deploys to `https://bhargav-2007.github.io/RiskCompass/`.

## Research note

This project includes a real training pipeline for the Dynamic Risk Engine, using actual vulnerability data from NVD, EPSS, and CISA KEV. The model is trained on real-world CVE records and demonstrates production-ready contextual risk scoring. Benchmark figures are derived from both synthetic labels (for MVP demonstration) and real training data.

Apache-2.0 licensed.
