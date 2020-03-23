| Title                | Wsreset UAC Bypass                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a method that uses Wsreset.exe tool that can be used to reset the Windows Store to bypass UAC                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1088: Bypass User Account Control](https://attack.mitre.org/techniques/T1088)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Trigger              | <ul><li>[T1088: Bypass User Account Control](../Triggers/T1088.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown sub processes of Wsreset.exe</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://lolbas-project.github.io/lolbas/Binaries/Wsreset/](https://lolbas-project.github.io/lolbas/Binaries/Wsreset/)</li><li>[https://www.activecyber.us/activelabs/windows-uac-bypass](https://www.activecyber.us/activelabs/windows-uac-bypass)</li><li>[https://twitter.com/ReaQta/status/1222548288731217921](https://twitter.com/ReaQta/status/1222548288731217921)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Wsreset UAC Bypass
id: bdc8918e-a1d5-49d1-9db7-ea0fd91aa2ae
status: experimental
description: Detects a method that uses Wsreset.exe tool that can be used to reset the Windows Store to bypass UAC 
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Wsreset/
    - https://www.activecyber.us/activelabs/windows-uac-bypass
    - https://twitter.com/ReaQta/status/1222548288731217921
author: Florian Roth
date: 2020/01/30
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1088
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\WSreset.exe'
    condition: selection
fields:
    - CommandLine
falsepositives:
    - Unknown sub processes of Wsreset.exe
level: high

```





### es-qs
    
```
ParentImage.keyword:(*\\\\WSreset.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/bdc8918e-a1d5-49d1-9db7-ea0fd91aa2ae <<EOF\n{\n  "metadata": {\n    "title": "Wsreset UAC Bypass",\n    "description": "Detects a method that uses Wsreset.exe tool that can be used to reset the Windows Store to bypass UAC",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.execution",\n      "attack.t1088"\n    ],\n    "query": "ParentImage.keyword:(*\\\\\\\\WSreset.exe)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "ParentImage.keyword:(*\\\\\\\\WSreset.exe)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Wsreset UAC Bypass\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\nCommandLine = {{_source.CommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
ParentImage.keyword:(*\\\\WSreset.exe)
```


### splunk
    
```
(ParentImage="*\\\\WSreset.exe") | table CommandLine
```


### logpoint
    
```
(event_id="1" ParentImage IN ["*\\\\WSreset.exe"])
```


### grep
    
```
grep -P '^(?:.*.*\\WSreset\\.exe)'
```



