Yes. This is very feasible in Sentinel, but I would structure it as a detection-quality / detection-health model rather than a dashboard that simply calculates “false-positive rate.”

The most important design decision is to make Analytics Rule ID the primary key and build a normalized relationship:

SecurityIncident
      |
      | AlertIds
      v
SecurityAlert --------------------> Analytics Rule
   SystemAlertId                     AlertType = Rule ID
                                     
SecurityIncident -----------------> Analytics Rule
   RelatedAnalyticRuleIds            direct incident→rule mapping

Analytics Rule ID
      |
      +---- SentinelHealth   -> executions / failures / alerts generated
      +---- SentinelAudit    -> tuning/change history
      +---- Alert Rules API  -> rule metadata/configuration

Microsoft now exposes AlertIds and RelatedAnalyticRuleIds in SecurityIncident. For scheduled rule alerts, SecurityAlert.AlertType contains the analytics rule ID and AlertName contains the rule name. This gives you a defensible rule-centric data model. 

1. Recommended data model

I would use four Sentinel tables plus an optional rule-inventory table.

Source	Purpose

SecurityIncident	Incident outcome, classification, severity, timestamps, owner, incident→rule relationship
SecurityAlert	Alert count and alert→rule mapping
SentinelHealth	Analytics-rule executions, failures, generated alerts, query results, entity mapping issues
SentinelAudit	Analytics-rule changes/tuning history
Rule REST API / custom inventory	Current rule metadata: name, enabled, MITRE, query frequency, last modified, etc.


SecurityIncident is effectively an audit/history table: every create or update adds another row. Therefore never count raw SecurityIncident rows as incidents. Microsoft explicitly recommends selecting the latest record using arg_max(). 

A standard building block should therefore be:

let Start = ago(30d);
let End = now();

let LatestIncidents =
    SecurityIncident
    // Include later updates so an incident created during the period
    // can have its latest classification/closure state.
    | where TimeGenerated >= Start
    | summarize arg_max(TimeGenerated, *) by IncidentName
    | where CreatedTime between (Start .. End);

LatestIncidents

Use IncidentName, rather than title or incident number, as the stable incident key.

Incident → Analytics Rule mapping

For most incident-level statistics, I would start with RelatedAnalyticRuleIds:

let IncidentRule =
    LatestIncidents
    | mv-expand RuleResourceId = RelatedAnalyticRuleIds to typeof(string)
    | extend RuleId =
        coalesce(
            extract(@"/alertRules/([^/]+)$", 1, RuleResourceId),
            RuleResourceId
        )
    | distinct
        IncidentName,
        IncidentNumber,
        RuleId,
        CreatedTime,
        ClosedTime,
        FirstModifiedTime,
        Severity,
        Status,
        Classification,
        ClassificationReason,
        IncidentUrl;

IncidentRule

RelatedAnalyticRuleIds contains ARM IDs of the rules associated with the incident. 

For alert counts, use SecurityAlert. For scheduled Sentinel rules, AlertType is the rule ID and AlertName derives from the rule name. 

SecurityAlert
| where TimeGenerated between (Start .. End)
| where ProviderName in ("ASI Scheduled Alerts", "CustomAlertRule")
| summarize
    Alerts = dcount(SystemAlertId),
    arg_max(TimeGenerated, AlertName)
    by RuleId = AlertType
| project
    RuleId,
    RuleName = AlertName,
    Alerts

In a production implementation I would improve this further by joining AlertType against an inventory of known Sentinel rule IDs rather than relying solely on ProviderName, because SecurityAlert also contains alerts ingested from Defender and other products. Microsoft documents that AlertType has different semantics for scheduled Sentinel alerts versus externally ingested alerts. 


---

2. False-positive definition

This deserves more attention than the visualization itself.

Strictly speaking, what SOC dashboards usually call false-positive rate isn't actually the classical statistical false-positive rate:

Classical FPR = FP / (FP + TN)

You don't know the number of true negatives because Sentinel doesn't record every piece of activity that correctly did not alert.

What you can calculate is closer to:

FP share = FP / classified alerts/incidents

I would therefore label the KPI FP % or False-positive share, rather than mathematically calling it FPR.

Sentinel classifications

Sentinel currently supports:

Classification	Meaning	How I would interpret it

TruePositive	Suspicious activity	Detection produced security value
BenignPositive	Suspicious but expected	Detection logic worked, activity was legitimate
FalsePositive	Incorrect alert logic / inaccurate data	Detection correctness problem
Undetermined	Unable to determine	Do not treat as TP or FP
empty/open	No final disposition yet	Exclude from quality denominator


Sentinel additionally distinguishes IncorrectAlertLogic, InaccurateData, SuspiciousActivity, and SuspiciousButExpected through ClassificationReason. 

I would calculate three different quality measures.

Strict FP %

FP % =
FalsePositive
/
(TruePositive + BenignPositive + FalsePositive)

This specifically answers:

> How often was the detection actually wrong?



Operational noise %

Noise % =
(FalsePositive + BenignPositive)
/
(TruePositive + BenignPositive + FalsePositive)

This answers:

> How much analyst workload does this detection produce without finding malicious activity?



This distinction is extremely useful.

For example:

Rule A
90% BenignPositive
5% FalsePositive
5% TruePositive

The rule isn't technically badly written. It is detecting exactly what it was intended to detect.

But operationally it is terrible.

Malicious yield / actionability %

Malicious Yield =
TruePositive
/
(TruePositive + BenignPositive + FalsePositive)

I would avoid calling this "True Positive Rate" because true-positive rate/sensitivity normally requires knowledge of false negatives:

TPR = TP / (TP + FN)

Sentinel incident data can't tell you how many attacks the rule missed.

That is one of the largest limitations of using FP statistics as a detection-quality metric.


---

3. Multi-rule incidents

This is probably the largest technical problem in the design.

A Sentinel incident can contain:

Incident 1234
    Alert A -> Rule X
    Alert B -> Rule X
    Alert C -> Rule Y

The incident then receives exactly one closure classification:

FalsePositive

You do not know whether:

Rule X was FP
Rule Y was useful

or

both were FP

Sentinel classification is fundamentally incident-level, not analytics-rule-level.

Therefore I recommend two accounting models.

Rule-quality statistics

Use an IncidentRule pair:

Incident 1234 + Rule X
Incident 1234 + Rule Y

Both inherit the final incident disposition.

This is acceptable for tuning analysis because you're asking:

> How often does this rule participate in incidents ultimately classified as noise?



But do not sum these numbers to obtain total SOC incidents because one incident can appear under multiple rules.

SOC-wide totals

Always:

dcount(IncidentName)

not:

sum(per-rule incidents)

Effort allocation

If you want to estimate investigation effort by rule, a multi-rule incident creates the same problem.

For an incident involving N rules, you could fractionally allocate:

Incident effort / N

That preserves the overall effort total.

But it is only an approximation.

A more mature implementation should collect rule-level analyst disposition, for example:

IncidentId
AlertId
RuleId
Disposition
Analyst
Reason
Timestamp
EffortMinutes

into a custom table such as:

DetectionOutcome_CL

That would eliminate this ambiguity completely.


---

4. Core metrics I would track

I would divide them into volume, quality, effort, health and change metrics.

Metric	Why it matters

Alerts	Raw detection volume
Incident-rule occurrences	Rule contribution to incidents
Unique incidents	Overall SOC volume
TP	Confirmed malicious findings
BP	Correct but expected detections
FP	Incorrect detection
Undetermined	Investigation quality/data issue
Open/unclassified	Classification backlog
FP %	Detection correctness
Noise %	Operational burden
Malicious yield %	Actual security value
Classification coverage	Reliability of the KPI
Alerts/day	Noise intensity
Incidents/day	Investigation workload
Alerts per incident	Grouping/compression effectiveness
TP per 100 alerts	Detection yield
Median/P90 triage time	SOC response
Median/P90 closure time	Investigation lifecycle
Analyst touches	Effort proxy
Comments/tasks	Investigation complexity proxy
Rule execution failures	Detection reliability
Alerts/generated run	Detection behaviour
Entity mapping drops	Detection engineering defect
7/30-day trend	Degradation/improvement
Last rule modification	Tuning context
Before/after tuning delta	Tuning effectiveness


SentinelHealth is particularly valuable here. For analytics rules it can expose rule ID, executions, alerts generated, query result counts, dropped entities, suppression configuration, execution success/failure and other execution information. 


---

5. Classification quality itself should be a KPI

This one is easy to overlook.

Suppose:

Rule A
40 FP
10 TP

looks terrible.

But suppose Rule B has:

1 FP
2 TP
97 Undetermined

Its apparent FP % looks better, but its data quality is useless.

Add:

Conclusive Classification Coverage =
(TP + BP + FP)
/
Closed Incidents

and separately show:

Undetermined %
Open %

I would suppress or gray out rankings where:

Classified incidents < 10

or whatever threshold makes sense for your volume.

A rule with:

1 FP / 1 classified incident = 100%

should not outrank:

300 FP / 500 classified incidents = 60%

for tuning priority.


---

6. KQL for rule quality

A usable first version:

let Start = ago(30d);
let End = now();

let LatestIncidents =
    SecurityIncident
    | where TimeGenerated >= Start
    | summarize arg_max(TimeGenerated, *) by IncidentName
    | where CreatedTime between (Start .. End);

let IncidentRule =
    LatestIncidents
    | mv-expand RuleResourceId = RelatedAnalyticRuleIds to typeof(string)
    | extend RuleId =
        coalesce(
            extract(@"/alertRules/([^/]+)$", 1, RuleResourceId),
            RuleResourceId
        )
    | distinct
        IncidentName,
        RuleId,
        CreatedTime,
        ClosedTime,
        FirstModifiedTime,
        Severity,
        Status,
        Classification,
        ClassificationReason;

IncidentRule
| summarize
    Incidents = dcount(IncidentName),
    TP = dcountif(IncidentName, Classification == "TruePositive"),
    BP = dcountif(IncidentName, Classification == "BenignPositive"),
    FP = dcountif(IncidentName, Classification == "FalsePositive"),
    Undetermined = dcountif(IncidentName, Classification == "Undetermined"),
    OpenOrUnclassified =
        dcountif(
            IncidentName,
            Status != "Closed" or isempty(Classification)
        )
    by RuleId
| extend Classified = TP + BP + FP
| extend
    FPPercent =
        round(100.0 * FP / max_of(Classified, 1), 1),
    NoisePercent =
        round(100.0 * (FP + BP) / max_of(Classified, 1), 1),
    MaliciousYieldPercent =
        round(100.0 * TP / max_of(Classified, 1), 1)
| extend SufficientSample = Classified >= 10
| order by FP desc

That query alone gives you most of the MVP.


---

7. FP reasons

Do not only show:

FalsePositive = 183

Break it down into:

IncorrectAlertLogic
InaccurateData

For example:

IncidentRule
| where Classification == "FalsePositive"
| summarize Incidents=dcount(IncidentName)
    by RuleId, ClassificationReason
| order by Incidents desc

That immediately tells detection engineering whether they have:

bad query logic

vs.

bad/misleading telemetry

Likewise, BenignPositive + SuspiciousButExpected is an obvious candidate for allowlisting, context enrichment or threshold tuning.


---

8. Trend over time

There are two legitimate ways to trend quality.

Detection cohort trend

bin(CreatedTime, 7d)

This answers:

> How good were incidents generated during this period?



This is what I would normally use for detection engineering.

IncidentRule
| where Classification in
    ("TruePositive", "BenignPositive", "FalsePositive")
| summarize
    TP=dcountif(IncidentName, Classification=="TruePositive"),
    BP=dcountif(IncidentName, Classification=="BenignPositive"),
    FP=dcountif(IncidentName, Classification=="FalsePositive")
    by RuleId, Week=bin(CreatedTime, 7d)
| extend Classified=TP+BP+FP
| extend
    FPPercent=100.0*FP/max_of(Classified,1),
    NoisePercent=100.0*(FP+BP)/max_of(Classified,1)

However, recent periods suffer from right-censoring: yesterday's incidents haven't necessarily been closed yet.

Therefore always display classification coverage alongside the trend.

Closure trend

Alternatively:

bin(ClosedTime, 7d)

This avoids unresolved cases, but now you are measuring when analysts completed investigations rather than when the detection fired.

For tuning analysis, I prefer CreatedTime cohorts.


---

9. Before/after tuning

This is where SentinelAudit becomes extremely useful.

After auditing is enabled, analytics-rule writes and deletes are recorded. For changes, the audit event can contain the original resource state, updated state and list of changed properties. 

Example:

SentinelAudit
| where OperationName =~ "Microsoft.SecurityInsights/alertRules/Write"
| extend
    RuleResourceId=tostring(ExtendedProperties["ResourceId"]),
    RuleId=extract(
        @"/alertRules/([^/]+)$",
        1,
        tostring(ExtendedProperties["ResourceId"])
    ),
    RuleName=tostring(ExtendedProperties["ResourceDisplayName"]),
    ChangedFields=ExtendedProperties["ResourceDiffMemberNames"],
    OriginalState=ExtendedProperties["OriginalResourceState"],
    UpdatedState=ExtendedProperties["UpdatedResourceState"]
| project
    TuningTime=TimeGenerated,
    RuleId,
    RuleName,
    ChangedFields,
    OriginalState,
    UpdatedState
| order by TuningTime desc

Then select a tuning event:

Rule X modified: 2026-08-01

Before:
2026-07-18 -> 2026-07-31

After:
2026-08-02 -> 2026-08-15

and compare:

Alerts/day
Incidents/day
FP %
Noise %
TP count
Malicious yield

This creates a very useful tuning effectiveness view.

I would also calculate:

Alert reduction = -42%
FP incidents = -63%
True positives = -5%

The ideal tuning result isn't simply:

alerts down

It's:

noise down significantly
TP retention approximately unchanged


---

10. SentinelHealth should be part of the dashboard

This moves the project from "FP dashboard" toward a genuine Detection Health dashboard.

Health/audit monitoring isn't necessarily enabled by default. It must be enabled in Sentinel settings / diagnostic settings. Microsoft notes that SentinelHealth and SentinelAudit are created once matching events begin flowing. 

Example:

let Start = ago(30d);

SentinelHealth
| where TimeGenerated >= Start
| where SentinelResourceType =~ "Analytics rule"
| where OperationName in
    ("Scheduled analytics rule run", "NRT analytics rule run")
| extend
    RuleId=tostring(ExtendedProperties["RuleId"]),
    AlertsGenerated=toint(ExtendedProperties["AlertsGeneratedAmount"]),
    QueryResults=toint(ExtendedProperties["QueryResultAmount"]),
    EntitiesGenerated=toint(ExtendedProperties["EntitiesGeneratedAmount"]),
    EntitiesDropped=
        toint(ExtendedProperties["EntitiesDroppedDueToMappingIssuesAmount"])
| summarize
    Runs=count(),
    FailedRuns=countif(Status=="Failure"),
    AlertsGenerated=sum(AlertsGenerated),
    QueryResults=sum(QueryResults),
    EntitiesGenerated=sum(EntitiesGenerated),
    EntitiesDropped=sum(EntitiesDropped)
    by RuleId, RuleName=SentinelResourceName
| extend
    FailurePercent=100.0*FailedRuns/max_of(Runs,1),
    EntityDropPercent=
        100.0*EntitiesDropped/
        max_of(EntitiesGenerated+EntitiesDropped,1)
| order by FailedRuns desc

This catches rules that aren't merely noisy, but actually broken.

For example:

Rule             FPR     Health
---------------------------------
Rule A           40%     OK
Rule B            3%     OK
Rule C            0%     70% execution failures

A dashboard focused purely on FP % would incorrectly tell you Rule C is excellent.


---

11. Analyst investigation effort

Sentinel gives you useful latency metrics:

FirstModifiedTime - CreatedTime
ClosedTime - CreatedTime

Microsoft's own SOC efficiency guidance uses these to calculate time to triage and time to closure. 

For example:

IncidentRule
| where isnotnull(ClosedTime)
| extend
    TriageMinutes=(FirstModifiedTime-CreatedTime)/1m,
    ClosureMinutes=(ClosedTime-CreatedTime)/1m
| summarize
    MedianTriage=percentile(TriageMinutes,50),
    P90Triage=percentile(TriageMinutes,90),
    MedianClosure=percentile(ClosureMinutes,50),
    P90Closure=percentile(ClosureMinutes,90)
    by RuleId

But I would not call this analyst effort.

An incident sitting open for six hours doesn't mean an analyst spent six hours investigating it.

Also, automation can modify incidents immediately, which can distort FirstModifiedTime.

Sentinel-only effort proxies could include:

number of incident updates
number of comments
number of tasks
number of ownership changes
reopen count

SecurityIncident now contains incident tasks and their timestamps/owners, and incident history lets you inspect changes over the incident lifecycle. 

For true effort measurement, I would integrate case-management/ticketing data or collect an explicit effort metric.


---

12. Rule inventory

There is one significant missing piece in normal KQL reporting:

> What are all of our rules, including rules that generated zero alerts?



SecurityAlert can't tell you that.

Use the Sentinel Alert Rules REST API.

The current API exposes information such as:

Rule ID
displayName
enabled
severity
tactics
techniques
query
queryFrequency
queryPeriod
suppression
lastModifiedUtc
event grouping



For an MVP you can query the current rule inventory externally.

For the mature implementation I would run something like:

Logic App / Function / Automation
        |
        | once per day
        v
Sentinel Alert Rules REST API
        |
        v
DetectionRuleInventory_CL

Example schema:

SnapshotTime
RuleId
RuleName
RuleKind
Enabled
Severity
Tactics
Techniques
QueryFrequency
QueryPeriod
LastModifiedUtc
ConfigHash
Owner
Service
RiskTier

Owner, Service, RiskTier, etc. could come from a Sentinel Watchlist or your Detection-as-Code repository.

That becomes your detection catalog.


---

13. Historical configuration is important

The REST API gives you the current configuration.

SentinelAudit gives you changes after auditing was enabled.

It is not a substitute for indefinite historical rule snapshots. Auditing/health monitoring must first be enabled; it isn't retroactive. 

Therefore, if you want reliable long-term analytics such as:

FPR before threshold changed from 5 to 20

FPR before allowlist was introduced

FPR before entity mapping changed

persist snapshots.

I would retain:

RuleId
SnapshotTime
ConfigHash
QueryHash
Configuration

Then you know exactly which version produced an incident.


---

14. Dashboard layout I would build

Page 1 — Detection overview

Top KPI tiles:

Alerts
Incidents
True Positives
False Positives
Benign Positives

FP %
Noise %
Malicious Yield %
Classification Coverage

Median Triage
Median Closure

Rules Failing
Rules Changed

Then a ranked table:

Rule	Alerts	Incidents	TP	BP	FP	FP %	Noise %	TP Yield	Trend




---

Page 2 — Tuning candidates

I'd make this the most useful SOC-engineering page.

Rank by something approximating:

Noise volume
+
Noise percentage
+
Investigation effort
+
Negative trend

Conceptually:

High volume + High noise = urgent tuning

High volume + High TP yield = important detection, tune carefully

Low volume + 100% FP = probably low priority

Zero volume = validation / coverage question

Don't rank purely on percentage.


---

Page 3 — Detection value

Show:

Top rules by True Positives

True positives / 100 alerts

True positives / incident

TP severity distribution

MITRE tactics / techniques generating TP activity

This makes sure the project doesn't turn into an exercise in minimizing alerts.


---

Page 4 — Trends

For each week/month:

alerts
incidents
TP
BP
FP
FP %
Noise %
Classification coverage

Allow rule selection.


---

Page 5 — Rule drill-down

For one rule:

Rule metadata

Current configuration
Last modification
MITRE mapping
Enabled/disabled

Alerts/day
Incidents/day

TP/BP/FP
FP %
Noise %
TP yield

Severity distribution

Classification reasons

Top entities causing noise

Median/P90 triage
Median/P90 close

Execution failures
Entity mapping failures

Recent tuning changes

Then underneath, a grid containing the actual incidents with links back into Sentinel.


---

Page 6 — Tuning effectiveness

Show rule modifications from SentinelAudit.

For selected change:

14d before     14d after

Alerts       3200 -> 1100
Incidents     410 -> 120
False pos.    300 ->  52
Benign         70 ->  25
True pos.      40 ->  43

FP %          73% -> 43%
Noise %       90% -> 64%

That's probably the most valuable long-term feature.


---

15. Workbook filters

I would expose:

Time Range
Analytics Rule
Rule Kind
Enabled / Disabled
Severity
Classification
Classification Reason
MITRE Tactic
MITRE Technique
Detection Owner
Data Source / Product

Microsoft Sentinel workbooks support parameterized time ranges, dropdowns, multi-selects, resource selectors and KQL-driven parameters. 


---

16. Sentinel Workbook vs Azure Monitor Workbook vs Power BI

My recommendation is unambiguous for the initial implementation:

Option	Verdict	Reason

Microsoft Sentinel Workbook	Best choice	Native SOC workflow, KQL, Sentinel permissions/context, interactive filters
Azure Monitor Workbook	Essentially same technology	Useful when dashboard spans many Azure services
Power BI	Phase 2/3	Better executive reporting, semantic modeling, long history, external sharing
Pure KQL	Foundation	Excellent query layer, not really a dashboard


Microsoft Sentinel workbooks are themselves based on Azure Monitor Workbooks, so the first two aren't fundamentally different technologies. 

For a SOC already living in Sentinel, I would build:

KQL functions
      +
Sentinel Workbook

first.

Power BI becomes attractive when you need:

multi-workspace reporting
management reporting
long-term historical models
cross-security-platform data
executive dashboards
sharing without Sentinel access

Microsoft officially supports exporting Log Analytics KQL into Power BI datasets/reports. 


---

17. Tuning priority

I wouldn't create a complicated magic score initially.

Start with four dimensions:

Noise Volume
Noise %
Analyst Effort
Trend

A simple rule table could classify:

Condition	Priority

High FP/BP count + high noise % + rising	Critical
High volume + moderate noise	High
Low volume + high noise %	Medium
High TP + high volume	Review carefully
Very small sample	Insufficient data


Once you have enough historical data, you could calculate:

TuningScore =
  35% NoiseVolumePercentile
+ 25% NoiseRate
+ 20% EffortPercentile
+ 10% NegativeTrend
+ 10% DetectionHealthPenalty

But the weights are organizational decisions, not universal truth.


---

18. Metrics that are more important than FPR alone

This is where I would challenge the original objective.

A rule can have:

0 incidents
0 false positives

and therefore appear perfect.

But it might simply not detect anything.

Conversely:

1000 alerts
200 false positives
100 confirmed compromises

might be one of the most valuable detections you own.

Therefore detection quality needs at least four axes:

Fidelity
    FP / BP / TP

Value
    confirmed malicious detections

Operational Cost
    volume + analyst workload

Reliability
    rule execution / telemetry / entity mapping health

And there is a fifth dimension Sentinel incidents can't tell you:

Coverage / Recall

You need detection validation to measure that.

For example:

Attack simulation executed
        ↓
Expected analytics rule
        ↓
Did it fire?
        ↓
Was correct entity mapped?
        ↓
Was incident generated?

Store results such as:

RuleId
TestTechnique
LastTested
TestPassed
DetectionLatency
ExpectedEntities
EntitiesObserved

Then your mature dashboard can say:

Detection Health
----------------------------------
Fidelity              92%
Noise                  18%
Rule health            100%
Last validation        14 days ago
Validation result      PASS
MITRE                  T1059.001

That is substantially more meaningful than a standalone FP percentage.


---

19. Concrete architecture I would recommend

For your environment, I would build it in three stages.

MVP

SecurityIncident
SecurityAlert
       |
       v
Reusable KQL
       |
       v
Sentinel Workbook

Implement:

alert volume
incident volume
TP/BP/FP
FP %
Noise %
TP yield
classification coverage
weekly trends
rule drilldown

Use RelatedAnalyticRuleIds as the main incident→rule relationship and SecurityAlert for actual alert counts.

Also enforce a SOC closure standard:

TP  = malicious/suspicious confirmed
BP  = rule was correct, activity expected
FP  = alert logic/data incorrect
Undetermined = genuinely unresolved

Without consistent analyst classification, the dashboard will mostly measure analyst habits.


---

Phase 2 — Detection Health

Enable and integrate:

SentinelHealth
SentinelAudit

Microsoft requires auditing/health monitoring to be enabled before those records start being collected. 

Add:

execution failure rate
entity mapping failures
rule changes
before/after tuning
last modified
alert generation/run

Then pull the current rule catalog through the Sentinel Alert Rules REST API.


---

Phase 3 — Detection Engineering platform

I'd evolve the architecture into:

SentinelHealth
                         |
SecurityIncident --- Detection metrics
       |                 |
SecurityAlert -----------+
       |                 |
SentinelAudit -----------+
       |                 |
Rule REST API -----------+
       |                 |
Detection Tests ---------+
       |                 |
Ticket/Effort data ------+
                         |
                         v
              Curated detection model
                         |
               +---------+---------+
               |                   |
       Sentinel Workbook       Power BI
       operational SOC         long-term/reporting

Persist something like:

DetectionRuleInventory_CL
DetectionOutcome_CL
DetectionValidation_CL

At that point you no longer have an "FP dashboard."

You have a genuine Detection Engineering / Detection Health dashboard.

One additional future-proofing point: Microsoft is increasingly converging Sentinel SIEM and Defender XDR detections, and Microsoft's current guidance identifies Defender XDR custom detections as the unified direction for new detections. I would therefore use a generic key such as DetectionId + DetectionSource internally rather than designing the model so tightly around SecurityAlert.AlertType that it can never accommodate Defender XDR custom detections later. 

Recommended end state

For the current requirement, I would choose:

Sentinel Workbook
+
SecurityIncident
+
SecurityAlert
+
SentinelHealth
+
SentinelAudit
+
daily Analytics Rule inventory snapshot

with FP %, Noise %, Malicious Yield %, Classification Coverage and TP volume treated as the five primary quality KPIs.

That gives you a much more defensible answer to “which detections should we tune?” than false-positive rate alone.