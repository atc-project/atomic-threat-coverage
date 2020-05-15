| Title                    | Harvesting of Wifi Credentials Using netsh.exe       |
|:-------------------------|:------------------|
| **Description**          | Detect the harvesting of wifi credentials using netsh.exe |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1040: Network Sniffing](https://attack.mitre.org/techniques/T1040)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1040: Network Sniffing](../Triggers/T1040.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate administrator or user uses netsh.exe wlan functionality for legitimate reason</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://blog.malwarebytes.com/threat-analysis/2020/04/new-agenttesla-variant-steals-wifi-credentials/](https://blog.malwarebytes.com/threat-analysis/2020/04/new-agenttesla-variant-steals-wifi-credentials/)</li></ul>  |
| **Author**               | Andreas Hunkeler (@Karneades) |


## Detection Rules

### Sigma rule

```
title: Harvesting of Wifi Credentials Using netsh.exe
id: 42b1a5b8-353f-4f10-b256-39de4467faff
status: experimental
description: Detect the harvesting of wifi credentials using netsh.exe
references:
    - https://blog.malwarebytes.com/threat-analysis/2020/04/new-agenttesla-variant-steals-wifi-credentials/
author: Andreas Hunkeler (@Karneades)
date: 2020/04/20
tags:
    - attack.discovery
    - attack.t1040
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - 'netsh wlan s* p* k*=clear'
    condition: selection
falsepositives:
    - Legitimate administrator or user uses netsh.exe wlan functionality for legitimate reason
level: medium

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*netsh wlan s.* p.* k.*=clear") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(netsh\\ wlan\\ s*\\ p*\\ k*\\=clear)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/42b1a5b8-353f-4f10-b256-39de4467faff <<EOF\n{\n  "metadata": {\n    "title": "Harvesting of Wifi Credentials Using netsh.exe",\n    "description": "Detect the harvesting of wifi credentials using netsh.exe",\n    "tags": [\n      "attack.discovery",\n      "attack.t1040"\n    ],\n    "query": "winlog.event_data.CommandLine.keyword:(netsh\\\\ wlan\\\\ s*\\\\ p*\\\\ k*\\\\=clear)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "winlog.event_data.CommandLine.keyword:(netsh\\\\ wlan\\\\ s*\\\\ p*\\\\ k*\\\\=clear)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Harvesting of Wifi Credentials Using netsh.exe\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine.keyword:(netsh wlan s* p* k*=clear)
```


### splunk
    
```
(CommandLine="netsh wlan s* p* k*=clear")
```


### logpoint
    
```
CommandLine IN ["netsh wlan s* p* k*=clear"]
```


### grep
    
```
grep -P '^(?:.*netsh wlan s.* p.* k.*=clear)'
```



