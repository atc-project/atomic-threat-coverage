| Title                | In-memory PowerShell                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects loading of essential DLL used by PowerShell, but not by the process powershell.exe. Detects meterpreter's "load powershell" extension.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0011_7_windows_sysmon_image_loaded](../Data_Needed/DN_0011_7_windows_sysmon_image_loaded.md)</li></ul>  |
| Enrichment |<ul><li>[EN_0001_cache_sysmon_event_id_1_info](../Enrichments/EN_0001_cache_sysmon_event_id_1_info.md)</li><li>[EN_0003_enrich_other_sysmon_events_with_event_id_1_data](../Enrichments/EN_0003_enrich_other_sysmon_events_with_event_id_1_data.md)</li></ul> |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Used by some .NET binaries, minimal on user workstation.</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://adsecurity.org/?p=2921](https://adsecurity.org/?p=2921)</li><li>[https://github.com/p3nt4/PowerShdll](https://github.com/p3nt4/PowerShdll)</li></ul>  |
| Author               | Tom Kern, oscd.community |


## Detection Rules

### Sigma rule

```
title: In-memory PowerShell
id: 092bc4b9-3d1d-43b4-a6b4-8c8acd83522f
status: experimental
description: Detects loading of essential DLL used by PowerShell, but not by the process powershell.exe. Detects meterpreter's "load powershell" extension.
author: Tom Kern, oscd.community
date: 2019/11/14
modified: 2019/11/30
references:
    - https://adsecurity.org/?p=2921
    - https://github.com/p3nt4/PowerShdll
tags:
    - attack.t1086
    - attack.execution
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 7
        ImageLoaded|endswith:
            - '\System.Management.Automation.Dll'
            - '\System.Management.Automation.ni.Dll'
    filter:
        Image|endswith:
            - '\powershell.exe'
            - '\WINDOWS\System32\sdiagnhost.exe'
        User: 'NT AUTHORITY\SYSTEM'
    condition: selection and not filter
falsepositives:
    - Used by some .NET binaries, minimal on user workstation.
level: high
enrichment:
    - EN_0001_cache_sysmon_event_id_1_info                      # http://bit.ly/314zc6x
    - EN_0003_enrich_other_sysmon_events_with_event_id_1_data   # http://bit.ly/2ojW7fw

```





### es-qs
    
```
((EventID:"7" AND ImageLoaded.keyword:(*\\\\System.Management.Automation.Dll OR *\\\\System.Management.Automation.ni.Dll)) AND (NOT (Image.keyword:(*\\\\powershell.exe OR *\\\\WINDOWS\\\\System32\\\\sdiagnhost.exe) AND User:"NT\\ AUTHORITY\\\\SYSTEM")))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/092bc4b9-3d1d-43b4-a6b4-8c8acd83522f <<EOF\n{\n  "metadata": {\n    "title": "In-memory PowerShell",\n    "description": "Detects loading of essential DLL used by PowerShell, but not by the process powershell.exe. Detects meterpreter\'s \\"load powershell\\" extension.",\n    "tags": [\n      "attack.t1086",\n      "attack.execution"\n    ],\n    "query": "((EventID:\\"7\\" AND ImageLoaded.keyword:(*\\\\\\\\System.Management.Automation.Dll OR *\\\\\\\\System.Management.Automation.ni.Dll)) AND (NOT (Image.keyword:(*\\\\\\\\powershell.exe OR *\\\\\\\\WINDOWS\\\\\\\\System32\\\\\\\\sdiagnhost.exe) AND User:\\"NT\\\\ AUTHORITY\\\\\\\\SYSTEM\\")))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((EventID:\\"7\\" AND ImageLoaded.keyword:(*\\\\\\\\System.Management.Automation.Dll OR *\\\\\\\\System.Management.Automation.ni.Dll)) AND (NOT (Image.keyword:(*\\\\\\\\powershell.exe OR *\\\\\\\\WINDOWS\\\\\\\\System32\\\\\\\\sdiagnhost.exe) AND User:\\"NT\\\\ AUTHORITY\\\\\\\\SYSTEM\\")))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'In-memory PowerShell\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:"7" AND ImageLoaded.keyword:(*\\\\System.Management.Automation.Dll *\\\\System.Management.Automation.ni.Dll)) AND (NOT (Image.keyword:(*\\\\powershell.exe *\\\\WINDOWS\\\\System32\\\\sdiagnhost.exe) AND User:"NT AUTHORITY\\\\SYSTEM")))
```


### splunk
    
```
((EventID="7" (ImageLoaded="*\\\\System.Management.Automation.Dll" OR ImageLoaded="*\\\\System.Management.Automation.ni.Dll")) NOT ((Image="*\\\\powershell.exe" OR Image="*\\\\WINDOWS\\\\System32\\\\sdiagnhost.exe") User="NT AUTHORITY\\\\SYSTEM"))
```


### logpoint
    
```
((event_id="7" ImageLoaded IN ["*\\\\System.Management.Automation.Dll", "*\\\\System.Management.Automation.ni.Dll"])  -(Image IN ["*\\\\powershell.exe", "*\\\\WINDOWS\\\\System32\\\\sdiagnhost.exe"] User="NT AUTHORITY\\\\SYSTEM"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*7)(?=.*(?:.*.*\\System\\.Management\\.Automation\\.Dll|.*.*\\System\\.Management\\.Automation\\.ni\\.Dll))))(?=.*(?!.*(?:.*(?=.*(?:.*.*\\powershell\\.exe|.*.*\\WINDOWS\\System32\\sdiagnhost\\.exe))(?=.*NT AUTHORITY\\SYSTEM)))))'
```



