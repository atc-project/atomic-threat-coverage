| Title                | DHCP Server Loaded the CallOut DLL                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | This rule detects a DHCP server in which a specified Callout DLL (in registry) was loaded                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1073: DLL Side-Loading](https://attack.mitre.org/techniques/T1073)</li></ul>  |
| Data Needed          | <ul><li>[DN_0048_1033_dhcp_service_successfully_loaded_callout_dlls](../Data_Needed/DN_0048_1033_dhcp_service_successfully_loaded_callout_dlls.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1073: DLL Side-Loading](../Triggers/T1073.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html](https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html)</li><li>[https://technet.microsoft.com/en-us/library/cc726884(v=ws.10).aspx](https://technet.microsoft.com/en-us/library/cc726884(v=ws.10).aspx)</li><li>[https://msdn.microsoft.com/de-de/library/windows/desktop/aa363389(v=vs.85).aspx](https://msdn.microsoft.com/de-de/library/windows/desktop/aa363389(v=vs.85).aspx)</li></ul>  |
| Author               | Dimitrios Slamaris |


## Detection Rules

### Sigma rule

```
title: DHCP Server Loaded the CallOut DLL
id: 13fc89a9-971e-4ca6-b9dc-aa53a445bf40
status: experimental
description: This rule detects a DHCP server in which a specified Callout DLL (in registry) was loaded
references:
    - https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html
    - https://technet.microsoft.com/en-us/library/cc726884(v=ws.10).aspx
    - https://msdn.microsoft.com/de-de/library/windows/desktop/aa363389(v=vs.85).aspx
date: 2017/05/15
author: Dimitrios Slamaris
tags:
    - attack.defense_evasion
    - attack.t1073
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 1033
    condition: selection
falsepositives: 
    - Unknown
level: critical

```





### splunk
    
```
EventID="1033"
```



