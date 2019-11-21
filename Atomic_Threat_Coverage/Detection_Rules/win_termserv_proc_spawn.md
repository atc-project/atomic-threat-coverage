| Title                | Terminal Service Process Spawn                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a process spawned by the terminal service server process (this could be an indicator for an exploitation of CVE-2019-0708)                                                                                                                                           |
| ATT&amp;CK Tactic    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/rdp-stands-for-really-do-patch-understanding-the-wormable-rdp-vulnerability-cve-2019-0708/](https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/rdp-stands-for-really-do-patch-understanding-the-wormable-rdp-vulnerability-cve-2019-0708/)</li></ul>  |
| Author               | Florian Roth |
| Other Tags           | <ul><li>car.2013-07-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Terminal Service Process Spawn
id: 1012f107-b8f1-4271-af30-5aed2de89b39
status: experimental
description: Detects a process spawned by the terminal service server process (this could be an indicator for an exploitation of CVE-2019-0708)
references:
    - https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/rdp-stands-for-really-do-patch-understanding-the-wormable-rdp-vulnerability-cve-2019-0708/
author: Florian Roth
date: 2019/05/22
tags:
    - car.2013-07-002
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentCommandLine: '*\svchost.exe*termsvcs'
    filter:
        Image: '*\rdpclip.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high


```





### splunk
    
```
(ParentCommandLine="*\\\\svchost.exe*termsvcs" NOT (Image="*\\\\rdpclip.exe"))
```



