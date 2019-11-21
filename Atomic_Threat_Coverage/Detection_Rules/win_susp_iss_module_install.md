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



