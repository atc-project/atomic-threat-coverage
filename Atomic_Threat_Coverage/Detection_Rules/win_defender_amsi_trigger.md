| Title                    | Windows Defender AMSI Trigger Detected       |
|:-------------------------|:------------------|
| **Description**          | Detects triggering of AMSI by Windows Defender. |
| **ATT&amp;CK Tactic**    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unlikely</li></ul>  |
| **Development Status**   | stable |
| **References**           | <ul><li>[https://docs.microsoft.com/en-us/windows/win32/amsi/how-amsi-helps](https://docs.microsoft.com/en-us/windows/win32/amsi/how-amsi-helps)</li></ul>  |
| **Author**               | Bhabesh Raj |


## Detection Rules

### Sigma rule

```
title: Windows Defender AMSI Trigger Detected
id: ea9bf0fa-edec-4fb8-8b78-b119f2528186
description: Detects triggering of AMSI by Windows Defender.
date: 2020/09/14
author: Bhabesh Raj
references:
    - https://docs.microsoft.com/en-us/windows/win32/amsi/how-amsi-helps
status: stable
logsource:
    product: windows
    service: windefend
detection:
    selection:
        EventID: 1116
        DetectionSource: 'AMSI'
    condition: selection
falsepositives:
    - unlikely
level: high
```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Windows Defender/Operational | where {($_.ID -eq "1116" -and $_.message -match "DetectionSource.*AMSI") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\\-Windows\\-Windows\\ Defender\\/Operational" AND winlog.event_id:"1116" AND DetectionSource:"AMSI")
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/ea9bf0fa-edec-4fb8-8b78-b119f2528186 <<EOF\n{\n  "metadata": {\n    "title": "Windows Defender AMSI Trigger Detected",\n    "description": "Detects triggering of AMSI by Windows Defender.",\n    "tags": "",\n    "query": "(winlog.channel:\\"Microsoft\\\\-Windows\\\\-Windows\\\\ Defender\\\\/Operational\\" AND winlog.event_id:\\"1116\\" AND DetectionSource:\\"AMSI\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Microsoft\\\\-Windows\\\\-Windows\\\\ Defender\\\\/Operational\\" AND winlog.event_id:\\"1116\\" AND DetectionSource:\\"AMSI\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Windows Defender AMSI Trigger Detected\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"1116" AND DetectionSource:"AMSI")
```


### splunk
    
```
(EventCode="1116" DetectionSource="AMSI")
```


### logpoint
    
```
(event_id="1116" DetectionSource="AMSI")
```


### grep
    
```
grep -P '^(?:.*(?=.*1116)(?=.*AMSI))'
```



