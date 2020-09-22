| Title                    | Capture a Network Trace with netsh.exe       |
|:-------------------------|:------------------|
| **Description**          | Detects capture a network trace via netsh.exe trace functionality |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1040: Network Sniffing](https://attack.mitre.org/techniques/T1040)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1040: Network Sniffing](../Triggers/T1040.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate administrator or user uses netsh.exe trace functionality for legitimate reason</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://blogs.msdn.microsoft.com/canberrapfe/2012/03/30/capture-a-network-trace-without-installing-anything-capture-a-network-trace-of-a-reboot/](https://blogs.msdn.microsoft.com/canberrapfe/2012/03/30/capture-a-network-trace-without-installing-anything-capture-a-network-trace-of-a-reboot/)</li></ul>  |
| **Author**               | Kutepov Anton, oscd.community |


## Detection Rules

### Sigma rule

```
title: Capture a Network Trace with netsh.exe
id: d3c3861d-c504-4c77-ba55-224ba82d0118
status: experimental
description: Detects capture a network trace via netsh.exe trace functionality
references:
    - https://blogs.msdn.microsoft.com/canberrapfe/2012/03/30/capture-a-network-trace-without-installing-anything-capture-a-network-trace-of-a-reboot/
author: Kutepov Anton, oscd.community
date: 2019/10/24
modified: 2020/09/01
tags:
    - attack.discovery
    - attack.credential_access
    - attack.t1040
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all: 
            - netsh
            - trace
            - start
    condition: selection    
falsepositives: 
    - Legitimate administrator or user uses netsh.exe trace functionality for legitimate reason
level: medium

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.*netsh.*" -and $_.message -match "CommandLine.*.*trace.*" -and $_.message -match "CommandLine.*.*start.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:*netsh* AND winlog.event_data.CommandLine.keyword:*trace* AND winlog.event_data.CommandLine.keyword:*start*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/d3c3861d-c504-4c77-ba55-224ba82d0118 <<EOF\n{\n  "metadata": {\n    "title": "Capture a Network Trace with netsh.exe",\n    "description": "Detects capture a network trace via netsh.exe trace functionality",\n    "tags": [\n      "attack.discovery",\n      "attack.credential_access",\n      "attack.t1040"\n    ],\n    "query": "(winlog.event_data.CommandLine.keyword:*netsh* AND winlog.event_data.CommandLine.keyword:*trace* AND winlog.event_data.CommandLine.keyword:*start*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.CommandLine.keyword:*netsh* AND winlog.event_data.CommandLine.keyword:*trace* AND winlog.event_data.CommandLine.keyword:*start*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Capture a Network Trace with netsh.exe\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(CommandLine.keyword:*netsh* AND CommandLine.keyword:*trace* AND CommandLine.keyword:*start*)
```


### splunk
    
```
(CommandLine="*netsh*" CommandLine="*trace*" CommandLine="*start*")
```


### logpoint
    
```
(CommandLine="*netsh*" CommandLine="*trace*" CommandLine="*start*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*netsh.*)(?=.*.*trace.*)(?=.*.*start.*))'
```



