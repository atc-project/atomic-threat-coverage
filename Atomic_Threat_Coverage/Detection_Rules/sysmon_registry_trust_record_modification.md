| Title                    | Windows Registry Trust Record Modification       |
|:-------------------------|:------------------|
| **Description**          | Alerts on trust record modification within the registry, indicating usage of macros |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0001: Initial Access](https://attack.mitre.org/tactics/TA0001)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1193: Spearphishing Attachment](https://attack.mitre.org/techniques/T1193)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0016_12_windows_sysmon_RegistryEvent](../Data_Needed/DN_0016_12_windows_sysmon_RegistryEvent.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1193: Spearphishing Attachment](../Triggers/T1193.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Alerts on legitimate macro usage as well, will need to filter as appropriate</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://outflank.nl/blog/2018/01/16/hunting-for-evil-detect-macros-being-executed/](https://outflank.nl/blog/2018/01/16/hunting-for-evil-detect-macros-being-executed/)</li><li>[http://az4n6.blogspot.com/2016/02/more-on-trust-records-macros-and.html](http://az4n6.blogspot.com/2016/02/more-on-trust-records-macros-and.html)</li></ul>  |
| **Author**               | Antonlovesdnb |


## Detection Rules

### Sigma rule

```
title: Windows Registry Trust Record Modification
id: 295a59c1-7b79-4b47-a930-df12c15fc9c2
status: experimental
description: Alerts on trust record modification within the registry, indicating usage of macros
references:
    - https://outflank.nl/blog/2018/01/16/hunting-for-evil-detect-macros-being-executed/
    - http://az4n6.blogspot.com/2016/02/more-on-trust-records-macros-and.html
author: Antonlovesdnb
date: 2020/02/19
modified: 2020/02/19
tags:
    - attack.initial_access
    - attack.t1193
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 12
        TargetObject|contains: 'TrustRecords'
    condition: selection
falsepositives:
    - Alerts on legitimate macro usage as well, will need to filter as appropriate
level: medium

```





### es-qs
    
```
(EventID:"12" AND TargetObject.keyword:*TrustRecords*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/295a59c1-7b79-4b47-a930-df12c15fc9c2 <<EOF\n{\n  "metadata": {\n    "title": "Windows Registry Trust Record Modification",\n    "description": "Alerts on trust record modification within the registry, indicating usage of macros",\n    "tags": [\n      "attack.initial_access",\n      "attack.t1193"\n    ],\n    "query": "(EventID:\\"12\\" AND TargetObject.keyword:*TrustRecords*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"12\\" AND TargetObject.keyword:*TrustRecords*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Windows Registry Trust Record Modification\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"12" AND TargetObject.keyword:*TrustRecords*)
```


### splunk
    
```
(EventID="12" TargetObject="*TrustRecords*")
```


### logpoint
    
```
(event_id="12" TargetObject="*TrustRecords*")
```


### grep
    
```
grep -P '^(?:.*(?=.*12)(?=.*.*TrustRecords.*))'
```



