| Title                | Control Panel Items                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the use of a control panel item (.cpl) outside of the System32 folder                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1196: Control Panel Items](https://attack.mitre.org/techniques/T1196)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1196: Control Panel Items](../Triggers/T1196.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Kyaw Min Thein |


## Detection Rules

### Sigma rule

```
title: Control Panel Items
status: experimental
description: Detects the use of a control panel item (.cpl) outside of the System32 folder
reference: 
  - https://attack.mitre.org/techniques/T1196/
tags: 
  - attack.execution
  - attack.t1196
  - attack.defense_evasion
author: Kyaw Min Thein
date: 2019/08/27
level: critical
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    CommandLine: '*.cpl'
  filter:
    CommandLine:
      - '*\System32\\*'
      - '*%System%*'
  condition: selection and not filter
falsepositives:
  - Unknown

```





### es-qs
    
```
(CommandLine.keyword:*.cpl AND (NOT (CommandLine.keyword:(*\\\\System32\\\\* OR *%System%*))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Control-Panel-Items <<EOF\n{\n  "metadata": {\n    "title": "Control Panel Items",\n    "description": "Detects the use of a control panel item (.cpl) outside of the System32 folder",\n    "tags": [\n      "attack.execution",\n      "attack.t1196",\n      "attack.defense_evasion"\n    ],\n    "query": "(CommandLine.keyword:*.cpl AND (NOT (CommandLine.keyword:(*\\\\\\\\System32\\\\\\\\* OR *%System%*))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(CommandLine.keyword:*.cpl AND (NOT (CommandLine.keyword:(*\\\\\\\\System32\\\\\\\\* OR *%System%*))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Control Panel Items\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(CommandLine:"*.cpl" AND NOT (CommandLine:("*\\\\System32\\\\*" "*%System%*")))
```


### splunk
    
```
(CommandLine="*.cpl" NOT ((CommandLine="*\\\\System32\\\\*" OR CommandLine="*%System%*")))
```


### logpoint
    
```
(CommandLine="*.cpl"  -(CommandLine IN ["*\\\\System32\\\\*", "*%System%*"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\.cpl)(?=.*(?!.*(?:.*(?=.*(?:.*.*\\System32\\\\.*|.*.*%System%.*))))))'
```



