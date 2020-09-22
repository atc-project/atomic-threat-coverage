| Title                    | DHCP Server Error Failed Loading the CallOut DLL       |
|:-------------------------|:------------------|
| **Description**          | This rule detects a DHCP server error in which a specified Callout DLL (in registry) could not be loaded |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1073: DLL Side-Loading](https://attack.mitre.org/techniques/T1073)</li><li>[T1574.002: DLL Side-Loading](https://attack.mitre.org/techniques/T1574.002)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0046_1031_dhcp_service_callout_dll_file_has_caused_an_exception](../Data_Needed/DN_0046_1031_dhcp_service_callout_dll_file_has_caused_an_exception.md)</li><li>[DN_0047_1032_dhcp_service_callout_dll_file_has_caused_an_exception](../Data_Needed/DN_0047_1032_dhcp_service_callout_dll_file_has_caused_an_exception.md)</li><li>[DN_0049_1034_dhcp_service_failed_to_load_callout_dlls](../Data_Needed/DN_0049_1034_dhcp_service_failed_to_load_callout_dlls.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1574.002: DLL Side-Loading](../Triggers/T1574.002.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html](https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html)</li><li>[https://technet.microsoft.com/en-us/library/cc726884(v=ws.10).aspx](https://technet.microsoft.com/en-us/library/cc726884(v=ws.10).aspx)</li><li>[https://msdn.microsoft.com/de-de/library/windows/desktop/aa363389(v=vs.85).aspx](https://msdn.microsoft.com/de-de/library/windows/desktop/aa363389(v=vs.85).aspx)</li></ul>  |
| **Author**               | Dimitrios Slamaris, @atc_project (fix) |


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
    - attack.t1073           # an old one
    - attack.t1574.002
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





### powershell
    
```
Get-WinEvent -LogName System | where {(($_.ID -eq "1031" -or $_.ID -eq "1032" -or $_.ID -eq "1034") -and $_.message -match "Source.*Microsoft-Windows-DHCP-Server") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_id:("1031" OR "1032" OR "1034") AND winlog.event_data.Source:"Microsoft\\-Windows\\-DHCP\\-Server")
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/75edd3fd-7146-48e5-9848-3013d7f0282c <<EOF\n{\n  "metadata": {\n    "title": "DHCP Server Error Failed Loading the CallOut DLL",\n    "description": "This rule detects a DHCP server error in which a specified Callout DLL (in registry) could not be loaded",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1073",\n      "attack.t1574.002"\n    ],\n    "query": "(winlog.event_id:(\\"1031\\" OR \\"1032\\" OR \\"1034\\") AND winlog.event_data.Source:\\"Microsoft\\\\-Windows\\\\-DHCP\\\\-Server\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_id:(\\"1031\\" OR \\"1032\\" OR \\"1034\\") AND winlog.event_data.Source:\\"Microsoft\\\\-Windows\\\\-DHCP\\\\-Server\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'DHCP Server Error Failed Loading the CallOut DLL\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:("1031" "1032" "1034") AND Source:"Microsoft\\-Windows\\-DHCP\\-Server")
```


### splunk
    
```
(source="WinEventLog:System" (EventCode="1031" OR EventCode="1032" OR EventCode="1034") Source="Microsoft-Windows-DHCP-Server")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id IN ["1031", "1032", "1034"] Source="Microsoft-Windows-DHCP-Server")
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*1031|.*1032|.*1034))(?=.*Microsoft-Windows-DHCP-Server))'
```



