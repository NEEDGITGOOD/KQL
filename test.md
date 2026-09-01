# Microsoft Sentinel Detection Quality & Health Workbook

## Files
- `Sentinel-Detection-Quality-Health.workbook.json` — Gallery Template / Advanced Editor workbook JSON.
- `Sentinel-Detection-Quality-Health.arm.json` — ARM template that deploys the workbook as a shared Sentinel workbook associated with a Log Analytics workspace.

## Fastest import (Defender portal or Azure portal)
1. Open Microsoft Sentinel > Threat management > Workbooks.
2. Add a workbook / open a blank workbook.
3. Select **Edit** > **Advanced editor (`</>`)**.
4. Select **Gallery Template**.
5. Replace the JSON with `Sentinel-Detection-Quality-Health.workbook.json`.
6. Select **Apply**, then **Save As**.

The workbook uses the current workspace context; there are no hard-coded tenant/subscription/workspace IDs.

## ARM deployment
Deploy `Sentinel-Detection-Quality-Health.arm.json` to the resource group that contains (or can reference) the Sentinel workspace. Supply `workspaceName`. The workbook resource uses `sourceId` pointing to that workspace and category `sentinel`.

## Required data
Core views:
- `SecurityIncident`
- `SecurityAlert`

Optional Health & Audit view:
- `SentinelHealth`
- `SentinelAudit`

## Definitions
- **FP %** = FalsePositive / (TruePositive + BenignPositive + FalsePositive)
- **Noise %** = (FalsePositive + BenignPositive) / (TruePositive + BenignPositive + FalsePositive)
- **Malicious yield %** = TruePositive / (TruePositive + BenignPositive + FalsePositive)
- **Classification coverage %** = conclusive classifications / closed incidents

`Undetermined` and unclassified incidents are excluded from the FP/noise/yield denominators.

## Attribution
Incident-to-rule attribution uses `SecurityIncident.RelatedAnalyticRuleIds`. A multi-rule incident contributes its final incident classification to each associated rule. SOC-wide incident KPI tiles deduplicate by `IncidentName`; per-rule rows intentionally do not.

Alert volume is restricted to Sentinel analytics-rule alerts (`ProviderName` = `ASI Scheduled Alerts` or `CustomAlertRule`) so Defender/product alerts are not mixed into Analytics Rule counts.

## Known limitations / interpretation
- Sentinel incident classification is incident-level, not alert/rule-level. Multi-rule incidents therefore cannot prove which individual alert was FP.
- `FirstModifiedTime` and incident history are proxies for analyst effort; automation can distort them.
- Recent incident cohorts can be under-classified. Use Classification Coverage alongside FP/Noise trends.
- Health/Audit data starts only after monitoring is enabled and is not retroactive.
- Rules that never generated an alert/incident in retained data are not a complete rule inventory. For mature reporting, snapshot the Alert Rules REST API into a custom table or watchlist.