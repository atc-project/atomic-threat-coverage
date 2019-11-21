| Title                | Whoami Execution                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the execution of whoami, which is often used by attackers after exloitation / privilege escalation but rarely used by administrators                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1033: System Owner/User Discovery](https://attack.mitre.org/techniques/T1033)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1033: System Owner/User Discovery](../Triggers/T1033.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Admin activity</li><li>Scripts and administrative tools used in the monitored environment</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://brica.de/alerts/alert/public/1247926/agent-tesla-keylogger-delivered-inside-a-power-iso-daa-archive/](https://brica.de/alerts/alert/public/1247926/agent-tesla-keylogger-delivered-inside-a-power-iso-daa-archive/)</li><li>[https://app.any.run/tasks/7eaba74e-c1ea-400f-9c17-5e30eee89906/](https://app.any.run/tasks/7eaba74e-c1ea-400f-9c17-5e30eee89906/)</li></ul>  |
| Author               | Florian Roth |
| Other Tags           | <ul><li>car.2016-03-001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Whoami Execution
id: e28a5a99-da44-436d-b7a0-2afc20a5f413
status: experimental
description: Detects the execution of whoami, which is often used by attackers after exloitation / privilege escalation but rarely used by administrators
references:
    - https://brica.de/alerts/alert/public/1247926/agent-tesla-keylogger-delivered-inside-a-power-iso-daa-archive/
    - https://app.any.run/tasks/7eaba74e-c1ea-400f-9c17-5e30eee89906/
author: Florian Roth
date: 2018/08/13
tags:
    - attack.discovery
    - attack.t1033
    - car.2016-03-001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\whoami.exe'
    selection2:
        OriginalFileName: 'whoami.exe'
    condition: selection or selection2
falsepositives:
    - Admin activity
    - Scripts and administrative tools used in the monitored environment
level: high

```





### splunk
    
```
(Image="*\\\\whoami.exe" OR OriginalFileName="whoami.exe")
```



