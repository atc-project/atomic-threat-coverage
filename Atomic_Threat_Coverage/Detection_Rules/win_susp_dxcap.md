| Title                | Application Whitelisting bypass via dxcap.exe                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects execution of of Dxcap.exe                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1218: Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1218: Signed Binary Proxy Execution](../Triggers/T1218.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Legitimate execution of dxcap.exe by legitimate user</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Dxcap.yml](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Dxcap.yml)</li><li>[https://twitter.com/harr0ey/status/992008180904419328](https://twitter.com/harr0ey/status/992008180904419328)</li></ul>  |
| Author               | Beyu Denis, oscd.community |


## Detection Rules

### Sigma rule

```
title: Application Whitelisting bypass via dxcap.exe
id: 60f16a96-db70-42eb-8f76-16763e333590
status: experimental
description: Detects execution of of Dxcap.exe
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Dxcap.yml
    - https://twitter.com/harr0ey/status/992008180904419328
author: Beyu Denis, oscd.community
date: 2019/10/26
modified: 2019/11/04
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1218
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\dxcap.exe'
        CommandLine|contains|all:
            - '-c'
            - '.exe'
    condition: selection
falsepositives:
    - Legitimate execution of dxcap.exe by legitimate user

```





### es-qs
    
```
(Image.keyword:*\\\\dxcap.exe AND CommandLine.keyword:*\\-c* AND CommandLine.keyword:*.exe*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Application-Whitelisting-bypass-via-dxcap.exe <<EOF\n{\n  "metadata": {\n    "title": "Application Whitelisting bypass via dxcap.exe",\n    "description": "Detects execution of of Dxcap.exe",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.execution",\n      "attack.t1218"\n    ],\n    "query": "(Image.keyword:*\\\\\\\\dxcap.exe AND CommandLine.keyword:*\\\\-c* AND CommandLine.keyword:*.exe*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Image.keyword:*\\\\\\\\dxcap.exe AND CommandLine.keyword:*\\\\-c* AND CommandLine.keyword:*.exe*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Application Whitelisting bypass via dxcap.exe\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:*\\\\dxcap.exe AND CommandLine.keyword:*\\-c* AND CommandLine.keyword:*.exe*)
```


### splunk
    
```
(Image="*\\\\dxcap.exe" CommandLine="*-c*" CommandLine="*.exe*")
```


### logpoint
    
```
(event_id="1" Image="*\\\\dxcap.exe" CommandLine="*-c*" CommandLine="*.exe*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\dxcap\\.exe)(?=.*.*-c.*)(?=.*.*\\.exe.*))'
```



