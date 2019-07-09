| Title                | Suspicious RASdial Activity                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious process related to rasdial.exe                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1064: Scripting](https://attack.mitre.org/techniques/T1064)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1064: Scripting](../Triggers/T1064.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/subTee/status/891298217907830785](https://twitter.com/subTee/status/891298217907830785)</li></ul>  |
| Author               | juju4 |


## Detection Rules

### Sigma rule

```
title: Suspicious RASdial Activity
description: Detects suspicious process related to rasdial.exe
status: experimental
references:
    - https://twitter.com/subTee/status/891298217907830785
author: juju4
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1064
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - rasdial
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium

```





### es-qs
    
```
CommandLine:("rasdial")
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Suspicious-RASdial-Activity <<EOF\n{\n  "metadata": {\n    "title": "Suspicious RASdial Activity",\n    "description": "Detects suspicious process related to rasdial.exe",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.execution",\n      "attack.t1064"\n    ],\n    "query": "CommandLine:(\\"rasdial\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "CommandLine:(\\"rasdial\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious RASdial Activity\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine:("rasdial")
```


### splunk
    
```
(CommandLine="rasdial")
```


### logpoint
    
```
CommandLine IN ["rasdial"]
```


### grep
    
```
grep -P '^(?:.*rasdial)'
```



