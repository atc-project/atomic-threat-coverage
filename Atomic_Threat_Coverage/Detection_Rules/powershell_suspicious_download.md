| Title                    | Suspicious PowerShell Download       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious PowerShell download command |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059.001)</li><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1059.001: PowerShell](../Triggers/T1059.001.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>PowerShell scripts that download content from the Internet</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious PowerShell Download
id: 65531a81-a694-4e31-ae04-f8ba5bc33759
status: experimental
description: Detects suspicious PowerShell download command
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1086  #an old one
author: Florian Roth
date: 2017/03/05
logsource:
    product: windows
    service: powershell
detection:
    downloadfile:
        Message|contains|all:
            - 'System.Net.WebClient'
            - '.DownloadFile('
    downloadstring:
        Message|contains|all:
            - 'System.Net.WebClient'
            - '.DownloadString('
    condition: downloadfile or downloadstring
falsepositives:
    - PowerShell scripts that download content from the Internet
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.message -match ".*System.Net.WebClient.*" -and ($_.message -match ".*.DownloadFile(.*" -or $_.message -match ".*.DownloadString(.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(Message.keyword:*System.Net.WebClient* AND (Message.keyword:*.DownloadFile\\(* OR Message.keyword:*.DownloadString\\(*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/65531a81-a694-4e31-ae04-f8ba5bc33759 <<EOF\n{\n  "metadata": {\n    "title": "Suspicious PowerShell Download",\n    "description": "Detects suspicious PowerShell download command",\n    "tags": [\n      "attack.execution",\n      "attack.t1059.001",\n      "attack.t1086"\n    ],\n    "query": "(Message.keyword:*System.Net.WebClient* AND (Message.keyword:*.DownloadFile\\\\(* OR Message.keyword:*.DownloadString\\\\(*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Message.keyword:*System.Net.WebClient* AND (Message.keyword:*.DownloadFile\\\\(* OR Message.keyword:*.DownloadString\\\\(*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious PowerShell Download\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Message.keyword:*System.Net.WebClient* AND (Message.keyword:*.DownloadFile\\(* OR Message.keyword:*.DownloadString\\(*))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-PowerShell/Operational" Message="*System.Net.WebClient*" (Message="*.DownloadFile(*" OR Message="*.DownloadString(*"))
```


### logpoint
    
```
(Message="*System.Net.WebClient*" (Message="*.DownloadFile(*" OR Message="*.DownloadString(*"))
```


### grep
    
```
grep -P '^(?:.*(?=.*.*System\\.Net\\.WebClient.*)(?=.*(?:.*(?:.*.*\\.DownloadFile\\(.*|.*.*\\.DownloadString\\(.*))))'
```



