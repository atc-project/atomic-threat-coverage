| Title                | Mimikatz DC Sync                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects Mimikatz DC sync security events                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          | <ul><li>[DN_0030_4662_operation_was_performed_on_an_object](../Data_Needed/DN_0030_4662_operation_was_performed_on_an_object.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unkown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/gentilkiwi/status/1003236624925413376](https://twitter.com/gentilkiwi/status/1003236624925413376)</li><li>[https://gist.github.com/gentilkiwi/dcc132457408cf11ad2061340dcb53c2](https://gist.github.com/gentilkiwi/dcc132457408cf11ad2061340dcb53c2)</li></ul>  |
| Author               | Benjamin Delpy, Florian Roth |
| Other Tags           | <ul><li>attack.s0002</li><li>attack.s0002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Mimikatz DC Sync
description: Detects Mimikatz DC sync security events
status: experimental
date: 2018/06/03
author: Benjamin Delpy, Florian Roth
references:
    - https://twitter.com/gentilkiwi/status/1003236624925413376
    - https://gist.github.com/gentilkiwi/dcc132457408cf11ad2061340dcb53c2
tags:
    - attack.credential_access
    - attack.s0002
    - attack.t1003
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662
        Properties: 
            - '*Replicating Directory Changes All*'
            - '*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*'
    condition: selection
falsepositives:
    - Unkown
level: critical


```





### es-qs
    
```
(EventID:"4662" AND Properties.keyword:(*Replicating\\ Directory\\ Changes\\ All* *1131f6ad\\-9c07\\-11d1\\-f79f\\-00c04fc2dcd2*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Mimikatz-DC-Sync <<EOF\n{\n  "metadata": {\n    "title": "Mimikatz DC Sync",\n    "description": "Detects Mimikatz DC sync security events",\n    "tags": [\n      "attack.credential_access",\n      "attack.s0002",\n      "attack.t1003"\n    ],\n    "query": "(EventID:\\"4662\\" AND Properties.keyword:(*Replicating\\\\ Directory\\\\ Changes\\\\ All* *1131f6ad\\\\-9c07\\\\-11d1\\\\-f79f\\\\-00c04fc2dcd2*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"4662\\" AND Properties.keyword:(*Replicating\\\\ Directory\\\\ Changes\\\\ All* *1131f6ad\\\\-9c07\\\\-11d1\\\\-f79f\\\\-00c04fc2dcd2*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Mimikatz DC Sync\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"4662" AND Properties:("*Replicating Directory Changes All*" "*1131f6ad\\-9c07\\-11d1\\-f79f\\-00c04fc2dcd2*"))
```


### splunk
    
```
(EventID="4662" (Properties="*Replicating Directory Changes All*" OR Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*"))
```


### logpoint
    
```
(EventID="4662" Properties IN ["*Replicating Directory Changes All*", "*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*4662)(?=.*(?:.*.*Replicating Directory Changes All.*|.*.*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2.*)))'
```



