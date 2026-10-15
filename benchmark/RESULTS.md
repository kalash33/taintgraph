# Benchmark: real incidents

Each row is one exact version from a real supply-chain incident (or a clean control), scanned as a one-package project with `pnpm bench`.
A row passes when Taintgraph calls an incident compromised and does not call a control compromised. Ordinary CVEs don't count either way.
A control can still read *suspicious*: that comes from ordinary high-severity CVEs (lodash, django), which Taintgraph reports as vulnerabilities, not compromise.
"possible_malware" means a malware advisory matches by version range or by its wording rather than naming the version explicitly; "removed" means the registry no longer serves the pinned version.

**Detected 19 of 19 real incidents; 0 false alarms on 10 clean controls.**

| Date | Registry | Version | Expected | Verdict | Signals | Advisory | |
|---|---|---|---|---|---|---|---|
| 2018-11 | npm | `flatmap-stream@0.1.1` | compromised | compromised | malware | MAL-2025-20690, GHSA-9x64-5r7x-2q53 | ✅ |
| 2018-11 | npm | `event-stream@3.3.6` | compromised | compromised | possible_malware | GHSA-mh6f-8j2x-4483 | ✅ |
| 2021-10 | npm | `ua-parser-js@0.7.29` | compromised | compromised | possible_malware | GHSA-pjwm-rvh2-c87w | ✅ |
| 2021-11 | npm | `coa@2.0.3` | compromised | compromised | possible_malware | GHSA-73qr-pfmq-6rp8 | ✅ |
| 2021-11 | npm | `rc@1.2.9` | compromised | compromised | possible_malware | GHSA-g2q5-5433-rhrf | ✅ |
| 2022-01 | npm | `colors@1.4.1` | compromised | compromised | removed | GHSA-5rqg-jm4f-cqx7, GHSA-gh88-3pxp-6fm8 | ✅ |
| 2022-03 | npm | `node-ipc@10.1.1` | compromised | compromised | possible_malware | GHSA-97m3-w2cp-4xx6 | ✅ |
| 2024-10 | npm | `@lottiefiles/lottie-player@2.0.5` | compromised | compromised | malware | MAL-2024-10301 | ✅ |
| 2024-12 | npm | `@solana/web3.js@1.95.6` | compromised | compromised | malware | MAL-2024-11183, GHSA-jcxm-7wvp-g6p5 | ✅ |
| 2024-12 | PyPI | `ultralytics@8.3.41` | compromised | compromised | possible_malware | PYSEC-2024-154 | ✅ |
| 2025-07 | npm | `eslint-config-prettier@8.10.1` | compromised | compromised | malware | MAL-2025-6022, GHSA-f29h-pxvx-f335 | ✅ |
| 2025-07 | npm | `is@3.3.1` | compromised | compromised | malware | MAL-2025-6020 | ✅ |
| 2025-07 | PyPI | `num2words@0.5.15` | compromised | compromised | malware | MAL-2025-6794, GHSA-jxr6-qrxx-2ph2 | ✅ |
| 2025-08 | npm | `nx@21.5.0` | compromised | compromised | malware | MAL-2025-41443, GHSA-g2r8-wvmj-jf5w | ✅ |
| 2025-09 | npm | `chalk@5.6.1` | compromised | compromised | malware | MAL-2025-46969 | ✅ |
| 2025-09 | npm | `debug@4.4.2` | compromised | compromised | malware | MAL-2025-46974, GHSA-4x49-vf9v-38px | ✅ |
| 2025-09 | npm | `@ctrl/tinycolor@4.1.1` | compromised | compromised | malware | MAL-2025-47141 | ✅ |
| 2026-03 | PyPI | `litellm@1.82.8` | compromised | compromised | malware | MAL-2026-2144, GHSA-5mg7-485q-xm76 | ✅ |
| 2026-05 | npm | `@tanstack/react-router@1.169.5` | compromised | compromised | malware | MAL-2026-3465, GHSA-g7cv-rxg3-hmpx | ✅ |
| 2025-09 | npm | `chalk@5.6.2` | clean | clean | – | – | ✅ |
| 2025-09 | npm | `debug@4.4.3` | clean | clean | – | – | ✅ |
| 2025-08 | npm | `chalk@5.6.0` | clean | clean | – | – | ✅ |
| 2024-04 | npm | `react@18.3.1` | clean | clean | – | – | ✅ |
| 2021-02 | npm | `lodash@4.17.21` | clean | suspicious | – | GHSA-f23m-r3pf-42rh, GHSA-r5fr-rjxr-66jc | ✅ |
| 2024-12 | npm | `express@4.21.2` | clean | clean | – | – | ✅ |
| 2024-10 | npm | `typescript@5.6.3` | clean | clean | – | – | ✅ |
| 2024-05 | PyPI | `requests@2.32.3` | clean | clean | – | GHSA-9hjg-9r4m-mvj7, GHSA-gc5v-m9x4-r6x2 | ✅ |
| 2024-12 | PyPI | `django@5.1.4` | clean | suspicious | – | GHSA-3h9f-r86x-qvjx, GHSA-6w2r-r2m5-xq5w | ✅ |
| 2026-03 | PyPI | `litellm@1.82.6` | clean | suspicious | – | GHSA-3cv6-jpf6-8222, GHSA-4g5m-c9r5-49xf | ✅ |

Generated 2026-10-15. Advisory data from OSV.dev changes over time; rerun to refresh.
