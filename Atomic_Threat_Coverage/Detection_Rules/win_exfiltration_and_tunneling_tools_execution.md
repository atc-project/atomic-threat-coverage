| Title                    | Exfiltration and Tunneling Tools Execution       |
|:-------------------------|:------------------|
| **Description**          | Execution of well known tools for data exfiltration and tunneling |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0010: Exfiltration](https://attack.mitre.org/tactics/TA0010)</li><li>[TA0011: Command and Control](https://attack.mitre.org/tactics/TA0011)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1043: Commonly Used Port](https://attack.mitre.org/techniques/T1043)</li><li>[T1041: Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041)</li><li>[T1572: Protocol Tunneling](https://attack.mitre.org/techniques/T1572)</li><li>[T1071.001: Web Protocols](https://attack.mitre.org/techniques/T1071.001)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1071.001: Web Protocols](../Triggers/T1071.001.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate Administrator using tools</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Daniil Yugoslavskiy, oscd.community |


## Detection Rules

### Sigma rule

```
title: Exfiltration and Tunneling Tools Execution
id: c75309a3-59f8-4a8d-9c2c-4c927ad50555
description: Execution of well known tools for data exfiltration and tunneling
status: experimental
author: Daniil Yugoslavskiy, oscd.community
date: 2019/10/24
modified: 2020/08/29
tags:
    - attack.exfiltration
    - attack.command_and_control
    - attack.t1043   # an old one
    - attack.t1041
    - attack.t1572
    - attack.t1071.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\plink.exe'
            - '\socat.exe'
            - '\stunnel.exe'
            - '\httptunnel.exe'
    condition: selection
falsepositives:
    - Legitimate Administrator using tools
level: medium

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Image.*.*\\\\plink.exe" -or $_.message -match "Image.*.*\\\\socat.exe" -or $_.message -match "Image.*.*\\\\stunnel.exe" -or $_.message -match "Image.*.*\\\\httptunnel.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.Image.keyword:(*\\\\plink.exe OR *\\\\socat.exe OR *\\\\stunnel.exe OR *\\\\httptunnel.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/c75309a3-59f8-4a8d-9c2c-4c927ad50555 <<EOF\n{\n  "metadata": {\n    "title": "Exfiltration and Tunneling Tools Execution",\n    "description": "Execution of well known tools for data exfiltration and tunneling",\n    "tags": [\n      "attack.exfiltration",\n      "attack.command_and_control",\n      "attack.t1043",\n      "attack.t1041",\n      "attack.t1572",\n      "attack.t1071.001"\n    ],\n    "query": "winlog.event_data.Image.keyword:(*\\\\\\\\plink.exe OR *\\\\\\\\socat.exe OR *\\\\\\\\stunnel.exe OR *\\\\\\\\httptunnel.exe)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "winlog.event_data.Image.keyword:(*\\\\\\\\plink.exe OR *\\\\\\\\socat.exe OR *\\\\\\\\stunnel.exe OR *\\\\\\\\httptunnel.exe)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Exfiltration and Tunneling Tools Execution\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
Image.keyword:(*\\\\plink.exe *\\\\socat.exe *\\\\stunnel.exe *\\\\httptunnel.exe)
```


### splunk
    
```
(Image="*\\\\plink.exe" OR Image="*\\\\socat.exe" OR Image="*\\\\stunnel.exe" OR Image="*\\\\httptunnel.exe")
```


### logpoint
    
```
Image IN ["*\\\\plink.exe", "*\\\\socat.exe", "*\\\\stunnel.exe", "*\\\\httptunnel.exe"]
```


### grep
    
```
grep -P '^(?:.*.*\\plink\\.exe|.*.*\\socat\\.exe|.*.*\\stunnel\\.exe|.*.*\\httptunnel\\.exe)'
```



