| Title                    | Possible DC Shadow       |
|:-------------------------|:------------------|
| **Description**          | Detects DC sync via create new SPN |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1207: DCShadow](https://attack.mitre.org/techniques/T1207)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0026_5136_windows_directory_service_object_was_modified](../Data_Needed/DN_0026_5136_windows_directory_service_object_was_modified.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1207: DCShadow](../Triggers/T1207.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Exclude known DCs</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/Neo23x0/sigma/blob/ec5bb710499caae6667c7f7311ca9e92c03b9039/rules/windows/builtin/win_dcsync.yml](https://github.com/Neo23x0/sigma/blob/ec5bb710499caae6667c7f7311ca9e92c03b9039/rules/windows/builtin/win_dcsync.yml)</li><li>[https://twitter.com/gentilkiwi/status/1003236624925413376](https://twitter.com/gentilkiwi/status/1003236624925413376)</li><li>[https://gist.github.com/gentilkiwi/dcc132457408cf11ad2061340dcb53c2](https://gist.github.com/gentilkiwi/dcc132457408cf11ad2061340dcb53c2)</li><li>[https://blog.alsid.eu/dcshadow-explained-4510f52fc19d](https://blog.alsid.eu/dcshadow-explained-4510f52fc19d)</li></ul>  |
| **Author**               | Ilyas Ochkov, oscd.community, Chakib Gzenayi (@Chak092), Hosni Mribah |


## Detection Rules

### Sigma rule

```
title: Possible DC Shadow
id: 32e19d25-4aed-4860-a55a-be99cb0bf7ed
description: Detects DC sync via create new SPN
status: experimental
author: Ilyas Ochkov, oscd.community, Chakib Gzenayi (@Chak092), Hosni Mribah
date: 2019/10/25
references:
    - https://github.com/Neo23x0/sigma/blob/ec5bb710499caae6667c7f7311ca9e92c03b9039/rules/windows/builtin/win_dcsync.yml
    - https://twitter.com/gentilkiwi/status/1003236624925413376
    - https://gist.github.com/gentilkiwi/dcc132457408cf11ad2061340dcb53c2
    - https://blog.alsid.eu/dcshadow-explained-4510f52fc19d
tags:
    - attack.credential_access
    - attack.t1207
logsource:
    product: windows
    service: security
detection:
    selection1:
        EventID: 4742
        ServicePrincipalNames: '*GC/*'
    selection2:
        EventID: 5136
        LDAPDisplayName: servicePrincipalName
        Value: 'GC/*'
    condition: selection1 OR selection2
falsepositives:
    - Exclude known DCs
level: high

```





### es-qs
    
```
((EventID:"4742" AND ServicePrincipalNames.keyword:*GC\\/*) OR (EventID:"5136" AND LDAPDisplayName:"servicePrincipalName" AND Value.keyword:GC\\/*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/32e19d25-4aed-4860-a55a-be99cb0bf7ed <<EOF\n{\n  "metadata": {\n    "title": "Possible DC Shadow",\n    "description": "Detects DC sync via create new SPN",\n    "tags": [\n      "attack.credential_access",\n      "attack.t1207"\n    ],\n    "query": "((EventID:\\"4742\\" AND ServicePrincipalNames.keyword:*GC\\\\/*) OR (EventID:\\"5136\\" AND LDAPDisplayName:\\"servicePrincipalName\\" AND Value.keyword:GC\\\\/*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((EventID:\\"4742\\" AND ServicePrincipalNames.keyword:*GC\\\\/*) OR (EventID:\\"5136\\" AND LDAPDisplayName:\\"servicePrincipalName\\" AND Value.keyword:GC\\\\/*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Possible DC Shadow\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:"4742" AND ServicePrincipalNames.keyword:*GC\\/*) OR (EventID:"5136" AND LDAPDisplayName:"servicePrincipalName" AND Value.keyword:GC\\/*))
```


### splunk
    
```
((EventID="4742" ServicePrincipalNames="*GC/*") OR (EventID="5136" LDAPDisplayName="servicePrincipalName" Value="GC/*"))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" ((event_id="4742" ServicePrincipalNames="*GC/*") OR (event_id="5136" LDAPDisplayName="servicePrincipalName" Value="GC/*")))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*4742)(?=.*.*GC/.*))|.*(?:.*(?=.*5136)(?=.*servicePrincipalName)(?=.*GC/.*))))'
```



