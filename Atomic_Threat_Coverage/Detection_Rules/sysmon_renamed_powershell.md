| Title                    | Renamed PowerShell       |
|:-------------------------|:------------------|
| **Description**          | Detects the execution of a renamed PowerShell often used by attackers or malware |
| **ATT&amp;CK Tactic**    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0011_7_windows_sysmon_image_loaded](../Data_Needed/DN_0011_7_windows_sysmon_image_loaded.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/christophetd/status/1164506034720952320](https://twitter.com/christophetd/status/1164506034720952320)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>car.2013-05-009</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Renamed PowerShell
id: d178a2d7-129a-4ba4-8ee6-d6e1fecd5d20
status: experimental
description: Detects the execution of a renamed PowerShell often used by attackers or malware
references:
    - https://twitter.com/christophetd/status/1164506034720952320
author: Florian Roth
date: 2019/08/22
tags:
    - car.2013-05-009
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        Description: 'Windows PowerShell'
        Company: 'Microsoft Corporation'
    filter:
        Image: 
            - '*\powershell.exe'
            - '*\powershell_ise.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: critical

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.message -match "Description.*Windows PowerShell" -and $_.message -match "Company.*Microsoft Corporation") -and  -not (($_.message -match "Image.*.*\\\\powershell.exe" -or $_.message -match "Image.*.*\\\\powershell_ise.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\\-Windows\\-Sysmon\\/Operational" AND (winlog.event_data.Description:"Windows\\ PowerShell" AND Company:"Microsoft\\ Corporation") AND (NOT (winlog.event_data.Image.keyword:(*\\\\powershell.exe OR *\\\\powershell_ise.exe))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/d178a2d7-129a-4ba4-8ee6-d6e1fecd5d20 <<EOF\n{\n  "metadata": {\n    "title": "Renamed PowerShell",\n    "description": "Detects the execution of a renamed PowerShell often used by attackers or malware",\n    "tags": [\n      "car.2013-05-009"\n    ],\n    "query": "(winlog.channel:\\"Microsoft\\\\-Windows\\\\-Sysmon\\\\/Operational\\" AND (winlog.event_data.Description:\\"Windows\\\\ PowerShell\\" AND Company:\\"Microsoft\\\\ Corporation\\") AND (NOT (winlog.event_data.Image.keyword:(*\\\\\\\\powershell.exe OR *\\\\\\\\powershell_ise.exe))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Microsoft\\\\-Windows\\\\-Sysmon\\\\/Operational\\" AND (winlog.event_data.Description:\\"Windows\\\\ PowerShell\\" AND Company:\\"Microsoft\\\\ Corporation\\") AND (NOT (winlog.event_data.Image.keyword:(*\\\\\\\\powershell.exe OR *\\\\\\\\powershell_ise.exe))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Renamed PowerShell\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((Description:"Windows PowerShell" AND Company:"Microsoft Corporation") AND (NOT (Image.keyword:(*\\\\powershell.exe *\\\\powershell_ise.exe))))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (Description="Windows PowerShell" Company="Microsoft Corporation") NOT ((Image="*\\\\powershell.exe" OR Image="*\\\\powershell_ise.exe")))
```


### logpoint
    
```
((Description="Windows PowerShell" Company="Microsoft Corporation")  -(Image IN ["*\\\\powershell.exe", "*\\\\powershell_ise.exe"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*Windows PowerShell)(?=.*Microsoft Corporation)))(?=.*(?!.*(?:.*(?=.*(?:.*.*\\powershell\\.exe|.*.*\\powershell_ise\\.exe))))))'
```



