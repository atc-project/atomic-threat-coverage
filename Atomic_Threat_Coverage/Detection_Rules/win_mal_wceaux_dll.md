| Title                | WCE wceaux.dll Access                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects wceaux.dll access while WCE pass-the-hash remote command execution on source host                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          | <ul><li>[DN_0060_4658_handle_to_an_object_was_closed](../Data_Needed/DN_0060_4658_handle_to_an_object_was_closed.md)</li><li>[DN_0058_4656_handle_to_an_object_was_requested](../Data_Needed/DN_0058_4656_handle_to_an_object_was_requested.md)</li><li>[DN_0061_4660_object_was_deleted](../Data_Needed/DN_0061_4660_object_was_deleted.md)</li><li>[DN_0062_4663_attempt_was_made_to_access_an_object](../Data_Needed/DN_0062_4663_attempt_was_made_to_access_an_object.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Penetration testing</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.jpcert.or.jp/english/pub/sr/ir_research.html](https://www.jpcert.or.jp/english/pub/sr/ir_research.html)</li><li>[https://jpcertcc.github.io/ToolAnalysisResultSheet](https://jpcertcc.github.io/ToolAnalysisResultSheet)</li></ul>  |
| Author               | Thomas Patzke |
| Other Tags           | <ul><li>attack.s0005</li><li>attack.s0005</li></ul> | 

## Detection Rules

### Sigma rule

```
title: WCE wceaux.dll Access
status: experimental
description: Detects wceaux.dll access while WCE pass-the-hash remote command execution on source host
author: Thomas Patzke
references:
    - https://www.jpcert.or.jp/english/pub/sr/ir_research.html
    - https://jpcertcc.github.io/ToolAnalysisResultSheet
tags:
    - attack.credential_access
    - attack.t1003
    - attack.s0005
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4656
            - 4658
            - 4660
            - 4663
        ObjectName: '*\wceaux.dll'
    condition: selection
falsepositives: 
    - Penetration testing
level: critical

```





### es-qs
    
```
(EventID:("4656" "4658" "4660" "4663") AND ObjectName.keyword:*\\\\wceaux.dll)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/WCE-wceaux.dll-Access <<EOF\n{\n  "metadata": {\n    "title": "WCE wceaux.dll Access",\n    "description": "Detects wceaux.dll access while WCE pass-the-hash remote command execution on source host",\n    "tags": [\n      "attack.credential_access",\n      "attack.t1003",\n      "attack.s0005"\n    ],\n    "query": "(EventID:(\\"4656\\" \\"4658\\" \\"4660\\" \\"4663\\") AND ObjectName.keyword:*\\\\\\\\wceaux.dll)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:(\\"4656\\" \\"4658\\" \\"4660\\" \\"4663\\") AND ObjectName.keyword:*\\\\\\\\wceaux.dll)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'WCE wceaux.dll Access\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:("4656" "4658" "4660" "4663") AND ObjectName:"*\\\\wceaux.dll")
```


### splunk
    
```
((EventID="4656" OR EventID="4658" OR EventID="4660" OR EventID="4663") ObjectName="*\\\\wceaux.dll")
```


### logpoint
    
```
(EventID IN ["4656", "4658", "4660", "4663"] ObjectName="*\\\\wceaux.dll")
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*4656|.*4658|.*4660|.*4663))(?=.*.*\\wceaux\\.dll))'
```



