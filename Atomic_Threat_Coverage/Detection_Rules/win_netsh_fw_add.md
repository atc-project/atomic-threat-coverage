| Title                | Netsh                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Allow Incoming Connections by Port or Application on Windows Firewall                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li><li>[TA0011: Command and Control](https://attack.mitre.org/tactics/TA0011)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1090: Connection Proxy](https://attack.mitre.org/techniques/T1090)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1090: Connection Proxy](../Triggers/T1090.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Legitimate administration</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://attack.mitre.org/software/S0246/ (Lazarus HARDRAIN)](https://attack.mitre.org/software/S0246/ (Lazarus HARDRAIN))</li><li>[https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-RAT-and-Staging-Report.pdf](https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-RAT-and-Staging-Report.pdf)</li></ul>  |
| Author               | Markus Neis |


## Detection Rules

### Sigma rule

```
title: Netsh 
description: Allow Incoming Connections by Port or Application on Windows Firewall
references:
    - https://attack.mitre.org/software/S0246/ (Lazarus HARDRAIN)
    - https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-RAT-and-Staging-Report.pdf
date: 2019/01/29
tags:
    - attack.lateral_movement
    - attack.command_and_control
    - attack.t1090 
status: experimental
author: Markus Neis
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '*netsh firewall add*'
    condition: selection
falsepositives:
    - Legitimate administration
level: medium

```





### es-qs
    
```
CommandLine.keyword:(*netsh\\ firewall\\ add*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Netsh <<EOF\n{\n  "metadata": {\n    "title": "Netsh",\n    "description": "Allow Incoming Connections by Port or Application on Windows Firewall",\n    "tags": [\n      "attack.lateral_movement",\n      "attack.command_and_control",\n      "attack.t1090"\n    ],\n    "query": "CommandLine.keyword:(*netsh\\\\ firewall\\\\ add*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "CommandLine.keyword:(*netsh\\\\ firewall\\\\ add*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Netsh\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine:("*netsh firewall add*")
```


### splunk
    
```
(CommandLine="*netsh firewall add*")
```


### logpoint
    
```
CommandLine IN ["*netsh firewall add*"]
```


### grep
    
```
grep -P '^(?:.*.*netsh firewall add.*)'
```



