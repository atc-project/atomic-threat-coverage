| Title                | OpenWith.exe executes specified binary                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | The OpenWith.exe executes other binary                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1218: Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1218: Signed Binary Proxy Execution](../Triggers/T1218.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Legitimate use of OpenWith.exe by legitimate user</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/LOLUtilz/OSBinaries/Openwith.yml](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/LOLUtilz/OSBinaries/Openwith.yml)</li><li>[https://twitter.com/harr0ey/status/991670870384021504](https://twitter.com/harr0ey/status/991670870384021504)</li></ul>  |
| Author               | Beyu Denis, oscd.community (rule), @harr0ey (idea) |


## Detection Rules

### Sigma rule

```
title: OpenWith.exe executes specified binary
id: cec8e918-30f7-4e2d-9bfa-a59cc97ae60f
status: experimental
description: The OpenWith.exe executes other binary
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/LOLUtilz/OSBinaries/Openwith.yml
    - https://twitter.com/harr0ey/status/991670870384021504
author: Beyu Denis, oscd.community (rule), @harr0ey (idea)
date: 2019/10/12
modified: 2019/11/04
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1218
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\OpenWith.exe'
        CommandLine|contains: '/c'
    condition: selection
falsepositives:
    - Legitimate use of OpenWith.exe by legitimate user

```





### es-qs
    
```
(Image.keyword:*\\\\OpenWith.exe AND CommandLine.keyword:*\\/c*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/OpenWith.exe-executes-specified-binary <<EOF\n{\n  "metadata": {\n    "title": "OpenWith.exe executes specified binary",\n    "description": "The OpenWith.exe executes other binary",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.execution",\n      "attack.t1218"\n    ],\n    "query": "(Image.keyword:*\\\\\\\\OpenWith.exe AND CommandLine.keyword:*\\\\/c*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Image.keyword:*\\\\\\\\OpenWith.exe AND CommandLine.keyword:*\\\\/c*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'OpenWith.exe executes specified binary\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:*\\\\OpenWith.exe AND CommandLine.keyword:*\\/c*)
```


### splunk
    
```
(Image="*\\\\OpenWith.exe" CommandLine="*/c*")
```


### logpoint
    
```
(event_id="1" Image="*\\\\OpenWith.exe" CommandLine="*/c*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\OpenWith\\.exe)(?=.*.*/c.*))'
```



