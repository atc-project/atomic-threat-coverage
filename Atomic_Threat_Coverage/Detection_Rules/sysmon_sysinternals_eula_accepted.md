| Title                | Usage of Sysinternals Tools                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the usage of Sysinternals Tools due to accepteula key being added to Registry                                                                                                                                           |
| ATT&amp;CK Tactic    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | low |
| False Positives      | <ul><li>Legitimate use of SysInternals tools</li><li>Programs that use the same Registry Key</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/Moti_B/status/1008587936735035392](https://twitter.com/Moti_B/status/1008587936735035392)</li></ul>  |
| Author               | Markus Neis |


## Detection Rules

### Sigma rule

```
---
action: global
title: Usage of Sysinternals Tools 
status: experimental
description: Detects the usage of Sysinternals Tools due to accepteula key being added to Registry 
references:
    - https://twitter.com/Moti_B/status/1008587936735035392
date: 2017/08/28
author: Markus Neis
detection:
    condition: 1 of them
falsepositives:
    - Legitimate use of SysInternals tools
    - Programs that use the same Registry Key
level: low
---
logsource:
    product: windows
    service: sysmon
detection:
    selection1:
        EventID: 13
        TargetObject: '*\EulaAccepted'
---
logsource:
    category: process_creation
    product: windows
detection:
    selection2:
        CommandLine: '* -accepteula*'
```





### es-qs
    
```
(EventID:"13" AND TargetObject.keyword:*\\\\EulaAccepted)\nCommandLine.keyword:*\\ \\-accepteula*
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Usage-of-Sysinternals-Tools <<EOF\n{\n  "metadata": {\n    "title": "Usage of Sysinternals Tools",\n    "description": "Detects the usage of Sysinternals Tools due to accepteula key being added to Registry",\n    "tags": "",\n    "query": "(EventID:\\"13\\" AND TargetObject.keyword:*\\\\\\\\EulaAccepted)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"13\\" AND TargetObject.keyword:*\\\\\\\\EulaAccepted)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Usage of Sysinternals Tools\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Usage-of-Sysinternals-Tools-2 <<EOF\n{\n  "metadata": {\n    "title": "Usage of Sysinternals Tools",\n    "description": "Detects the usage of Sysinternals Tools due to accepteula key being added to Registry",\n    "tags": "",\n    "query": "CommandLine.keyword:*\\\\ \\\\-accepteula*"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "CommandLine.keyword:*\\\\ \\\\-accepteula*",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Usage of Sysinternals Tools\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"13" AND TargetObject:"*\\\\EulaAccepted")\nCommandLine:"* \\-accepteula*"
```


### splunk
    
```
(EventID="13" TargetObject="*\\\\EulaAccepted")\nCommandLine="* -accepteula*"
```


### logpoint
    
```
(EventID="13" TargetObject="*\\\\EulaAccepted")\nCommandLine="* -accepteula*"
```


### grep
    
```
grep -P '^(?:.*(?=.*13)(?=.*.*\\EulaAccepted))'\ngrep -P '^.* -accepteula.*'
```



