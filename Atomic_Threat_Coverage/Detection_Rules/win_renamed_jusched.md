| Title                    | Renamed jusched.exe       |
|:-------------------------|:------------------|
| **Description**          | Detects renamed jusched.exe used by cobalt group |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li><li>[T1036.003: Rename System Utilities](https://attack.mitre.org/techniques/T1036.003)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1036.003: Rename System Utilities](../Triggers/T1036.003.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>penetration tests, red teaming</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.bitdefender.com/files/News/CaseStudies/study/262/Bitdefender-WhitePaper-An-APT-Blueprint-Gaining-New-Visibility-into-Financial-Threats-interactive.pdf](https://www.bitdefender.com/files/News/CaseStudies/study/262/Bitdefender-WhitePaper-An-APT-Blueprint-Gaining-New-Visibility-into-Financial-Threats-interactive.pdf)</li></ul>  |
| **Author**               | Markus Neis, Swisscom |


## Detection Rules

### Sigma rule

```
title: Renamed jusched.exe 
status: experimental
id: edd8a48c-1b9f-4ba1-83aa-490338cd1ccb
description: Detects renamed jusched.exe used by cobalt group 
references:
    - https://www.bitdefender.com/files/News/CaseStudies/study/262/Bitdefender-WhitePaper-An-APT-Blueprint-Gaining-New-Visibility-into-Financial-Threats-interactive.pdf
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1036 # an old one
    - attack.t1036.003    
author: Markus Neis, Swisscom
date: 2019/06/04
modified: 2020/09/06
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Description: Java Update Scheduler
    selection2:
        Description: Java(TM) Update Scheduler
    filter:
        Image|endswith:
            - '\jusched.exe'
    condition: (selection1 or selection2) and not filter
falsepositives:
    - penetration tests, red teaming
level: high

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "Description.*Java Update Scheduler" -or $_.message -match "Description.*Java(TM) Update Scheduler") -and  -not (($_.message -match "Image.*.*\\\\jusched.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.Description:"Java\\ Update\\ Scheduler" OR winlog.event_data.Description:"Java\\(TM\\)\\ Update\\ Scheduler") AND (NOT (winlog.event_data.Image.keyword:(*\\\\jusched.exe))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/edd8a48c-1b9f-4ba1-83aa-490338cd1ccb <<EOF\n{\n  "metadata": {\n    "title": "Renamed jusched.exe",\n    "description": "Detects renamed jusched.exe used by cobalt group",\n    "tags": [\n      "attack.execution",\n      "attack.defense_evasion",\n      "attack.t1036",\n      "attack.t1036.003"\n    ],\n    "query": "((winlog.event_data.Description:\\"Java\\\\ Update\\\\ Scheduler\\" OR winlog.event_data.Description:\\"Java\\\\(TM\\\\)\\\\ Update\\\\ Scheduler\\") AND (NOT (winlog.event_data.Image.keyword:(*\\\\\\\\jusched.exe))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((winlog.event_data.Description:\\"Java\\\\ Update\\\\ Scheduler\\" OR winlog.event_data.Description:\\"Java\\\\(TM\\\\)\\\\ Update\\\\ Scheduler\\") AND (NOT (winlog.event_data.Image.keyword:(*\\\\\\\\jusched.exe))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Renamed jusched.exe\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((Description:"Java Update Scheduler" OR Description:"Java\\(TM\\) Update Scheduler") AND (NOT (Image.keyword:(*\\\\jusched.exe))))
```


### splunk
    
```
((Description="Java Update Scheduler" OR Description="Java(TM) Update Scheduler") NOT ((Image="*\\\\jusched.exe")))
```


### logpoint
    
```
((Description="Java Update Scheduler" OR Description="Java(TM) Update Scheduler")  -(Image IN ["*\\\\jusched.exe"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?:.*Java Update Scheduler|.*Java\\(TM\\) Update Scheduler)))(?=.*(?!.*(?:.*(?=.*(?:.*.*\\jusched\\.exe))))))'
```



