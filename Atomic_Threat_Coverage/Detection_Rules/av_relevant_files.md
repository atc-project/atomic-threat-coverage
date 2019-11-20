| Title                | Antivirus Relevant File Paths Alerts                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects an Antivirus alert in a highly relevant file path or with a relevant file name                                                                                                                                           |
| ATT&amp;CK Tactic    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          | <ul><li>[DN_0084_av_alert](../Data_Needed/DN_0084_av_alert.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | high |
| False Positives      | <ul><li>Unlikely</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/](https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Antivirus Relevant File Paths Alerts
id: c9a88268-0047-4824-ba6e-4d81ce0b907c
description: Detects an Antivirus alert in a highly relevant file path or with a relevant file name
date: 2018/09/09
modified: 2019/10/04
author: Florian Roth
references:
    - https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/
logsource:
    product: antivirus
detection:
    selection:
        FileName:
            - 'C:\Windows\Temp\\*'
            - 'C:\Temp\\*'
            - '*\\Client\\*'
            - 'C:\PerfLogs\\*'
            - 'C:\Users\Public\\*'
            - 'C:\Users\Default\\*'
            - '*.ps1'
            - '*.vbs'
            - '*.bat'
            - '*.chm'
            - '*.xml'
            - '*.txt'
            - '*.jsp'
            - '*.jspx'
            - '*.asp'
            - '*.aspx'
            - '*.php'
            - '*.war'
            - '*.hta'
            - '*.lnk'
            - '*.scf'
            - '*.wsf'
            - '*.wsh'
    condition: selection
fields:
    - Signature
    - User
falsepositives:
    - Unlikely
level: high

```





### splunk
    
```
(FileName="C:\\\\Windows\\\\Temp\\\\*" OR FileName="C:\\\\Temp\\\\*" OR FileName="*\\\\Client\\\\*" OR FileName="C:\\\\PerfLogs\\\\*" OR FileName="C:\\\\Users\\\\Public\\\\*" OR FileName="C:\\\\Users\\\\Default\\\\*" OR FileName="*.ps1" OR FileName="*.vbs" OR FileName="*.bat" OR FileName="*.chm" OR FileName="*.xml" OR FileName="*.txt" OR FileName="*.jsp" OR FileName="*.jspx" OR FileName="*.asp" OR FileName="*.aspx" OR FileName="*.php" OR FileName="*.war" OR FileName="*.hta" OR FileName="*.lnk" OR FileName="*.scf" OR FileName="*.wsf" OR FileName="*.wsh") | table Signature,User
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Antivirus Relevant File Paths Alerts]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:  \
Signature: $result.Signature$ \
User: $result.User$  \
title: Antivirus Relevant File Paths Alerts status:  \
description: Detects an Antivirus alert in a highly relevant file path or with a relevant file name \
references: ['https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/'] \
tags:  \
author: Florian Roth \
date:  \
falsepositives: ['Unlikely'] \
level: high
action.email.useNSSubject = 1
alert.severity = 1
alert.suppress = 0
alert.track = 1
alert.expires = 24h
counttype = number of events
cron_schedule = */10 * * * *
allow_skew = 50%
schedule_window = auto
description = Detects an Antivirus alert in a highly relevant file path or with a relevant file name
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (FileName="C:\\Windows\\Temp\\*" OR FileName="C:\\Temp\\*" OR FileName="*\\Client\\*" OR FileName="C:\\PerfLogs\\*" OR FileName="C:\\Users\\Public\\*" OR FileName="C:\\Users\\Default\\*" OR FileName="*.ps1" OR FileName="*.vbs" OR FileName="*.bat" OR FileName="*.chm" OR FileName="*.xml" OR FileName="*.txt" OR FileName="*.jsp" OR FileName="*.jspx" OR FileName="*.asp" OR FileName="*.aspx" OR FileName="*.php" OR FileName="*.war" OR FileName="*.hta" OR FileName="*.lnk" OR FileName="*.scf" OR FileName="*.wsf" OR FileName="*.wsh") | table Signature,User,host | search NOT [| inputlookup Antivirus_Relevant_File_Paths_Alerts_whitelist.csv]
```
