| Title                | Suspicious Reconnaissance Activity                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious command line activity on Windows systems                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1087: Account Discovery](https://attack.mitre.org/techniques/T1087)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1087: Account Discovery](../Triggers/T1087.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Inventory tool runs</li><li>Penetration tests</li><li>Administrative activity</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious Reconnaissance Activity
id: d95de845-b83c-4a9a-8a6a-4fc802ebf6c0
status: experimental
description: Detects suspicious command line activity on Windows systems
author: Florian Roth
tags:
    - attack.discovery
    - attack.t1087
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - net group "domain admins" /domain
            - net localgroup administrators
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Inventory tool runs
    - Penetration tests
    - Administrative activity
analysis:
    recommendation: Check if the user that executed the commands is suspicious (e.g. service accounts, LOCAL_SYSTEM)
level: medium

```





### splunk
    
```
(CommandLine="net group \\"domain admins\\" /domain" OR CommandLine="net localgroup administrators") | table CommandLine,ParentCommandLine
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Suspicious Reconnaissance Activity]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:  \
CommandLine: $result.CommandLine$ \
ParentCommandLine: $result.ParentCommandLine$  \
title: Suspicious Reconnaissance Activity status: experimental \
description: Detects suspicious command line activity on Windows systems \
references:  \
tags: ['attack.discovery', 'attack.t1087'] \
author: Florian Roth \
date:  \
falsepositives: ['Inventory tool runs', 'Penetration tests', 'Administrative activity'] \
level: medium
action.email.useNSSubject = 1
alert.severity = 1
alert.suppress = 0
alert.track = 1
alert.expires = 24h
counttype = number of events
cron_schedule = */10 * * * *
allow_skew = 50%
schedule_window = auto
description = Detects suspicious command line activity on Windows systems
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (CommandLine="net group \"domain admins\" /domain" OR CommandLine="net localgroup administrators") | table CommandLine,ParentCommandLine,host | search NOT [| inputlookup Suspicious_Reconnaissance_Activity_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.discovery,sigma_tag=attack.t1087,level=medium"
```
