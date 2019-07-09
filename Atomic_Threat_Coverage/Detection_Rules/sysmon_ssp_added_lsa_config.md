| Title                | Security Support Provider (SSP) added to LSA configuration                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the addition of a SSP to the registry. Upon a reboot or API call, SSP DLLs gain access to encrypted and plaintext passwords stored in Windows.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1011: Exfiltration Over Other Network Medium](https://attack.mitre.org/techniques/T1011)</li></ul>  |
| Data Needed          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1011: Exfiltration Over Other Network Medium](../Triggers/T1011.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unlikely</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://attack.mitre.org/techniques/T1101/](https://attack.mitre.org/techniques/T1101/)</li><li>[https://powersploit.readthedocs.io/en/latest/Persistence/Install-SSP/](https://powersploit.readthedocs.io/en/latest/Persistence/Install-SSP/)</li></ul>  |
| Author               | iwillkeepwatch |


## Detection Rules

### Sigma rule

```
title: Security Support Provider (SSP) added to LSA configuration
status: experimental
description: Detects the addition of a SSP to the registry. Upon a reboot or API call, SSP DLLs gain access to encrypted and plaintext passwords stored in Windows. 
references:
    - https://attack.mitre.org/techniques/T1101/
    - https://powersploit.readthedocs.io/en/latest/Persistence/Install-SSP/
tags:
    - attack.persistence
    - attack.t1011
author: iwillkeepwatch
date: 2019/01/18
logsource:
    product: windows
    service: sysmon
detection:
    selection_registry:
        EventID: 13
        TargetObject: 
            - 'HKLM\System\CurrentControlSet\Control\Lsa\Security Packages'
            - 'HKLM\System\CurrentControlSet\Control\Lsa\OSConfig\Security Packages'
    exclusion_images:
        - Image: C:\Windows\system32\msiexec.exe
        - Image: C:\Windows\syswow64\MsiExec.exe
    condition: selection_registry and not exclusion_images
falsepositives:
    - Unlikely
level: critical


```





### es-qs
    
```
((EventID:"13" AND TargetObject:("HKLM\\\\System\\\\CurrentControlSet\\\\Control\\\\Lsa\\\\Security\\ Packages" "HKLM\\\\System\\\\CurrentControlSet\\\\Control\\\\Lsa\\\\OSConfig\\\\Security\\ Packages")) AND (NOT (Image:"C\\:\\\\Windows\\\\system32\\\\msiexec.exe" OR Image:"C\\:\\\\Windows\\\\syswow64\\\\MsiExec.exe")))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Security-Support-Provider-SSP-added-to-LSA-configuration <<EOF\n{\n  "metadata": {\n    "title": "Security Support Provider (SSP) added to LSA configuration",\n    "description": "Detects the addition of a SSP to the registry. Upon a reboot or API call, SSP DLLs gain access to encrypted and plaintext passwords stored in Windows.",\n    "tags": [\n      "attack.persistence",\n      "attack.t1011"\n    ],\n    "query": "((EventID:\\"13\\" AND TargetObject:(\\"HKLM\\\\\\\\System\\\\\\\\CurrentControlSet\\\\\\\\Control\\\\\\\\Lsa\\\\\\\\Security\\\\ Packages\\" \\"HKLM\\\\\\\\System\\\\\\\\CurrentControlSet\\\\\\\\Control\\\\\\\\Lsa\\\\\\\\OSConfig\\\\\\\\Security\\\\ Packages\\")) AND (NOT (Image:\\"C\\\\:\\\\\\\\Windows\\\\\\\\system32\\\\\\\\msiexec.exe\\" OR Image:\\"C\\\\:\\\\\\\\Windows\\\\\\\\syswow64\\\\\\\\MsiExec.exe\\")))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((EventID:\\"13\\" AND TargetObject:(\\"HKLM\\\\\\\\System\\\\\\\\CurrentControlSet\\\\\\\\Control\\\\\\\\Lsa\\\\\\\\Security\\\\ Packages\\" \\"HKLM\\\\\\\\System\\\\\\\\CurrentControlSet\\\\\\\\Control\\\\\\\\Lsa\\\\\\\\OSConfig\\\\\\\\Security\\\\ Packages\\")) AND (NOT (Image:\\"C\\\\:\\\\\\\\Windows\\\\\\\\system32\\\\\\\\msiexec.exe\\" OR Image:\\"C\\\\:\\\\\\\\Windows\\\\\\\\syswow64\\\\\\\\MsiExec.exe\\")))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Security Support Provider (SSP) added to LSA configuration\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:"13" AND TargetObject:("HKLM\\\\System\\\\CurrentControlSet\\\\Control\\\\Lsa\\\\Security Packages" "HKLM\\\\System\\\\CurrentControlSet\\\\Control\\\\Lsa\\\\OSConfig\\\\Security Packages")) AND NOT (Image:"C\\:\\\\Windows\\\\system32\\\\msiexec.exe" OR Image:"C\\:\\\\Windows\\\\syswow64\\\\MsiExec.exe"))
```


### splunk
    
```
((EventID="13" (TargetObject="HKLM\\\\System\\\\CurrentControlSet\\\\Control\\\\Lsa\\\\Security Packages" OR TargetObject="HKLM\\\\System\\\\CurrentControlSet\\\\Control\\\\Lsa\\\\OSConfig\\\\Security Packages")) NOT (Image="C:\\\\Windows\\\\system32\\\\msiexec.exe" OR Image="C:\\\\Windows\\\\syswow64\\\\MsiExec.exe"))
```


### logpoint
    
```
((EventID="13" TargetObject IN ["HKLM\\\\System\\\\CurrentControlSet\\\\Control\\\\Lsa\\\\Security Packages", "HKLM\\\\System\\\\CurrentControlSet\\\\Control\\\\Lsa\\\\OSConfig\\\\Security Packages"])  -(Image="C:\\\\Windows\\\\system32\\\\msiexec.exe" OR Image="C:\\\\Windows\\\\syswow64\\\\MsiExec.exe"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*13)(?=.*(?:.*HKLM\\System\\CurrentControlSet\\Control\\Lsa\\Security Packages|.*HKLM\\System\\CurrentControlSet\\Control\\Lsa\\OSConfig\\Security Packages))))(?=.*(?!.*(?:.*(?:.*(?=.*C:\\Windows\\system32\\msiexec\\.exe)|.*(?=.*C:\\Windows\\syswow64\\MsiExec\\.exe))))))'
```



