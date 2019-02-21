| Title                | Backup Catalog Deleted                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects backup catalog deletions                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1107: File Deletion](https://attack.mitre.org/techniques/T1107)</li></ul>                             |
| Data Needed          | <ul></ul>                                                         |
| Trigger              | <ul><li>[T1107: File Deletion](../Triggers/T1107.md)</li></ul>  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul><li>Unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://technet.microsoft.com/en-us/library/cc742154(v=ws.11).aspx](https://technet.microsoft.com/en-us/library/cc742154(v=ws.11).aspx)</li><li>[https://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa?environmentId=100](https://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa?environmentId=100)</li></ul>                                                          |
| Author               | Florian Roth (rule), Tom U. @c_APT_ure (collection)                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Backup Catalog Deleted
status: experimental
description: Detects backup catalog deletions
references:
    - https://technet.microsoft.com/en-us/library/cc742154(v=ws.11).aspx
    - https://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa?environmentId=100
author: Florian Roth (rule), Tom U. @c_APT_ure (collection) 
tags:
    - attack.defense_evasion
    - attack.t1107
logsource:
    product: windows
    service: application
detection:
    selection:
        EventID: 524
        Source: Backup
    condition: selection
falsepositives:
    - Unknown
level: medium


```





### Kibana query

```
(EventID:"524" AND Source:"Backup")
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Backup-Catalog-Deleted <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"524\\" AND Source:\\"Backup\\")",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Backup Catalog Deleted\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"524" AND Source:"Backup")
```





### Splunk

```
(EventID="524" Source="Backup")
```





### Logpoint

```
(EventID="524" Source="Backup")
```





### Grep

```
grep -P '^(?:.*(?=.*524)(?=.*Backup))'
```





### Fieldlist

```
EventID\nSource
```

