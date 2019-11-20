| Title                | IIS Native-Code Module Command Line Installation                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious IIS native-code module installations via command line                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1100: Web Shell](https://attack.mitre.org/techniques/T1100)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1100: Web Shell](../Triggers/T1100.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Unknown as it may vary from organisation to arganisation how admins use to install IIS modules</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://researchcenter.paloaltonetworks.com/2018/01/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/](https://researchcenter.paloaltonetworks.com/2018/01/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: IIS Native-Code Module Command Line Installation
id: 9465ddf4-f9e4-4ebd-8d98-702df3a93239
description: Detects suspicious IIS native-code module installations via command line
status: experimental
references:
    - https://researchcenter.paloaltonetworks.com/2018/01/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/
author: Florian Roth
modified: 2012/12/11
tags:
    - attack.persistence
    - attack.t1100
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '*\APPCMD.EXE install module /name:*'
    condition: selection
falsepositives:
    - Unknown as it may vary from organisation to arganisation how admins use to install IIS modules
level: medium

```





### splunk
    
```
(CommandLine="*\\\\APPCMD.EXE install module /name:*")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[IIS Native-Code Module Command Line Installation]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: IIS Native-Code Module Command Line Installation status: experimental \
description: Detects suspicious IIS native-code module installations via command line \
references: ['https://researchcenter.paloaltonetworks.com/2018/01/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/'] \
tags: ['attack.persistence', 'attack.t1100'] \
author: Florian Roth \
date:  \
falsepositives: ['Unknown as it may vary from organisation to arganisation how admins use to install IIS modules'] \
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
description = Detects suspicious IIS native-code module installations via command line
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (CommandLine="*\\APPCMD.EXE install module /name:*") | stats values(*) AS * by _time | search NOT [| inputlookup IIS_Native-Code_Module_Command_Line_Installation_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.persistence,sigma_tag=attack.t1100,level=medium"
```
