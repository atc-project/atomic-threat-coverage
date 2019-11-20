| Title                | Cmdkey Cached Credentials Recon                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects usage of cmdkey to look for cached credentials                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>Legitimate administrative tasks.</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.peew.pw/blog/2017/11/26/exploring-cmdkey-an-edge-case-for-privilege-escalation](https://www.peew.pw/blog/2017/11/26/exploring-cmdkey-an-edge-case-for-privilege-escalation)</li><li>[https://technet.microsoft.com/en-us/library/cc754243(v=ws.11).aspx](https://technet.microsoft.com/en-us/library/cc754243(v=ws.11).aspx)</li></ul>  |
| Author               | jmallette |


## Detection Rules

### Sigma rule

```
title: Cmdkey Cached Credentials Recon
id: 07f8bdc2-c9b3-472a-9817-5a670b872f53
status: experimental
description: Detects usage of cmdkey to look for cached credentials
references:
    - https://www.peew.pw/blog/2017/11/26/exploring-cmdkey-an-edge-case-for-privilege-escalation
    - https://technet.microsoft.com/en-us/library/cc754243(v=ws.11).aspx
author: jmallette
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\cmdkey.exe'
        CommandLine: '* /list *'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
    - User
falsepositives:
    - Legitimate administrative tasks.
level: low

```





### splunk
    
```
(Image="*\\\\cmdkey.exe" CommandLine="* /list *") | table CommandLine,ParentCommandLine,User
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Cmdkey Cached Credentials Recon]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:  \
CommandLine: $result.CommandLine$ \
ParentCommandLine: $result.ParentCommandLine$ \
User: $result.User$  \
title: Cmdkey Cached Credentials Recon status: experimental \
description: Detects usage of cmdkey to look for cached credentials \
references: ['https://www.peew.pw/blog/2017/11/26/exploring-cmdkey-an-edge-case-for-privilege-escalation', 'https://technet.microsoft.com/en-us/library/cc754243(v=ws.11).aspx'] \
tags: ['attack.credential_access', 'attack.t1003'] \
author: jmallette \
date:  \
falsepositives: ['Legitimate administrative tasks.'] \
level: low
action.email.useNSSubject = 1
alert.severity = 1
alert.suppress = 0
alert.track = 1
alert.expires = 24h
counttype = number of events
cron_schedule = */10 * * * *
allow_skew = 50%
schedule_window = auto
description = Detects usage of cmdkey to look for cached credentials
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (Image="*\\cmdkey.exe" CommandLine="* /list *") | table CommandLine,ParentCommandLine,User,host | search NOT [| inputlookup Cmdkey_Cached_Credentials_Recon_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.credential_access,sigma_tag=attack.t1003,level=low"
```
