| Title                    | Curl Start Combination       |
|:-------------------------|:------------------|
| **Description**          | Adversaries can use curl to download payloads remotely and execute them. Curl is included by default in Windows 10 build 17063 and later. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1218: Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1218: Signed Binary Proxy Execution](../Triggers/T1218.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Administrative scripts (installers)</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://medium.com/@reegun/curl-exe-is-the-new-rundll32-exe-lolbin-3f79c5f35983](https://medium.com/@reegun/curl-exe-is-the-new-rundll32-exe-lolbin-3f79c5f35983)</li></ul>  |
| **Author**               | Sreeman |


## Detection Rules

### Sigma rule

```
title: Curl Start Combination
id: 21dd6d38-2b18-4453-9404-a0fe4a0cc288
status: experimental
description: Adversaries can use curl to download payloads remotely and execute them. Curl is included by default in Windows 10 build 17063 and later.
references: 
    - https://medium.com/@reegun/curl-exe-is-the-new-rundll32-exe-lolbin-3f79c5f35983
author: Sreeman
date: 2020/01/13
tags:
    - attack.execution
    - attack.t1218
logsource:
   category: process_creation
   product: windows
detection:
  condition: selection
  selection:
      CommandLine|contains: 'curl* start '
falsepositives:
    - Administrative scripts (installers)
fields:
    - ParentImage
    - CommandLine
level: medium

```





### powershell
    
```
Get-WinEvent | where {$_.message -match "CommandLine.*.*curl.* start .*" } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:*curl*\\ start\\ *
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/21dd6d38-2b18-4453-9404-a0fe4a0cc288 <<EOF\n{\n  "metadata": {\n    "title": "Curl Start Combination",\n    "description": "Adversaries can use curl to download payloads remotely and execute them. Curl is included by default in Windows 10 build 17063 and later.",\n    "tags": [\n      "attack.execution",\n      "attack.t1218"\n    ],\n    "query": "winlog.event_data.CommandLine.keyword:*curl*\\\\ start\\\\ *"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "winlog.event_data.CommandLine.keyword:*curl*\\\\ start\\\\ *",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Curl Start Combination\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\nParentImage = {{_source.ParentImage}}\\nCommandLine = {{_source.CommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine.keyword:*curl* start *
```


### splunk
    
```
CommandLine="*curl* start *" | table ParentImage,CommandLine
```


### logpoint
    
```
CommandLine="*curl* start *"
```


### grep
    
```
grep -P '^.*curl.* start .*'
```



