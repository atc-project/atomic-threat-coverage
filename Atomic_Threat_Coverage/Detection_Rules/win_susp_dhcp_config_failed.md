| Title                | DHCP Server Error Failed Loading the CallOut DLL                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | This rule detects a DHCP server error in which a specified Callout DLL (in registry) could not be loaded                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1073: DLL Side-Loading](https://attack.mitre.org/techniques/T1073)</li></ul>  |
| Data Needed          | <ul><li>[DN_0049_1034_dhcp_service_failed_to_load_callout_dlls](../Data_Needed/DN_0049_1034_dhcp_service_failed_to_load_callout_dlls.md)</li><li>[DN_0046_1031_dhcp_service_callout_dll_file_has_caused_an_exception](../Data_Needed/DN_0046_1031_dhcp_service_callout_dll_file_has_caused_an_exception.md)</li><li>[DN_0047_1032_dhcp_service_callout_dll_file_has_caused_an_exception](../Data_Needed/DN_0047_1032_dhcp_service_callout_dll_file_has_caused_an_exception.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1073: DLL Side-Loading](../Triggers/T1073.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html](https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html)</li><li>[https://technet.microsoft.com/en-us/library/cc726884(v=ws.10).aspx](https://technet.microsoft.com/en-us/library/cc726884(v=ws.10).aspx)</li><li>[https://msdn.microsoft.com/de-de/library/windows/desktop/aa363389(v=vs.85).aspx](https://msdn.microsoft.com/de-de/library/windows/desktop/aa363389(v=vs.85).aspx)</li></ul>  |
| Author               | Dimitrios Slamaris, @atc_project (fix) |


## Detection Rules

### Sigma rule

```
title: DHCP Server Error Failed Loading the CallOut DLL
id: 75edd3fd-7146-48e5-9848-3013d7f0282c
description: This rule detects a DHCP server error in which a specified Callout DLL (in registry) could not be loaded
status: experimental
references:
    - https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html
    - https://technet.microsoft.com/en-us/library/cc726884(v=ws.10).aspx
    - https://msdn.microsoft.com/de-de/library/windows/desktop/aa363389(v=vs.85).aspx
date: 2017/05/15
modified: 2019/07/17
tags:
    - attack.defense_evasion
    - attack.t1073
author: "Dimitrios Slamaris, @atc_project (fix)"
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 
            - 1031
            - 1032
            - 1034
        Source: Microsoft-Windows-DHCP-Server            
    condition: selection
falsepositives: 
    - Unknown
level: critical

```





### splunk
    
```
((EventID="1031" OR EventID="1032" OR EventID="1034") Source="Microsoft-Windows-DHCP-Server")
```






### Saved Search for Splunk

```
b'# Generated with Sigma2SplunkAlert\n[DHCP Server Error Failed Loading the CallOut DLL]\naction.email = 1\naction.email.subject.alert = Splunk Alert: $name$\naction.email.to = test@test.de\naction.email.message.alert = Splunk Alert $name$ triggered \\\nList of interesting fields:   \\\ntitle: DHCP Server Error Failed Loading the CallOut DLL status: experimental \\\ndescription: This rule detects a DHCP server error in which a specified Callout DLL (in registry) could not be loaded \\\nreferences: [\'https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html\', \'https://technet.microsoft.com/en-us/library/cc726884(v=ws.10).aspx\', \'https://msdn.microsoft.com/de-de/library/windows/desktop/aa363389(v=vs.85).aspx\'] \\\ntags: [\'attack.defense_evasion\', \'attack.t1073\'] \\\nauthor: Dimitrios Slamaris, @atc_project (fix) \\\ndate:  \\\nfalsepositives: [\'Unknown\'] \\\nlevel: critical\naction.email.useNSSubject = 1\nalert.severity = 1\nalert.suppress = 0\nalert.track = 1\nalert.expires = 24h\ncounttype = number of events\ncron_schedule = */10 * * * *\nallow_skew = 50%\nschedule_window = auto\ndescription = This rule detects a DHCP server error in which a specified Callout DLL (in registry) could not be loaded\ndispatch.earliest_time = -10m\ndispatch.latest_time = now\nenableSched = 1\nquantity = 0\nrelation = greater than\nrequest.ui_dispatch_app = sigma_hunting_app\nrequest.ui_dispatch_view = search\nsearch = ((EventID="1031" OR EventID="1032" OR EventID="1034") Source="Microsoft-Windows-DHCP-Server") | stats values(*) AS * by _time | search NOT [| inputlookup DHCP_Server_Error_Failed_Loading_the_CallOut_DLL_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.t1073,level=critical"\n\n\n'
```
