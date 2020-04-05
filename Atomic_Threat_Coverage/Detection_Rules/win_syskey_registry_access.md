| Title                    | SysKey Registry Keys Access       |
|:-------------------------|:------------------|
| **Description**          | Detects handle requests and access operations to specific registry keys to calculate the SysKey |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1012: Query Registry](https://attack.mitre.org/techniques/T1012)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0058_4656_handle_to_an_object_was_requested](../Data_Needed/DN_0058_4656_handle_to_an_object_was_requested.md)</li><li>[DN_0062_4663_attempt_was_made_to_access_an_object](../Data_Needed/DN_0062_4663_attempt_was_made_to_access_an_object.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1012: Query Registry](../Triggers/T1012.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/hunters-forge/ThreatHunter-Playbook/blob/master/playbooks/windows/07_discovery/T1012_query_registry/syskey_registry_keys_access.md](https://github.com/hunters-forge/ThreatHunter-Playbook/blob/master/playbooks/windows/07_discovery/T1012_query_registry/syskey_registry_keys_access.md)</li></ul>  |
| **Author**               | Roberto Rodriguez @Cyb3rWard0g |


## Detection Rules

### Sigma rule

```
title: SysKey Registry Keys Access
id: 9a4ff3b8-6187-4fd2-8e8b-e0eae1129495
description: Detects handle requests and access operations to specific registry keys to calculate the SysKey
status: experimental
date: 2019/08/12
modified: 2019/11/10
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/hunters-forge/ThreatHunter-Playbook/blob/master/playbooks/windows/07_discovery/T1012_query_registry/syskey_registry_keys_access.md
tags:
    - attack.discovery
    - attack.t1012
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4656
            - 4663
        ObjectType: 'key'
        ObjectName|endswith:
            - 'lsa\JD'
            - 'lsa\GBG'
            - 'lsa\Skew1'
            - 'lsa\Data'
    condition: selection
falsepositives:
    - Unknown
level: critical
```





### es-qs
    
```
(EventID:("4656" OR "4663") AND ObjectType:"key" AND ObjectName.keyword:(*lsa\\\\JD OR *lsa\\\\GBG OR *lsa\\\\Skew1 OR *lsa\\\\Data))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/9a4ff3b8-6187-4fd2-8e8b-e0eae1129495 <<EOF\n{\n  "metadata": {\n    "title": "SysKey Registry Keys Access",\n    "description": "Detects handle requests and access operations to specific registry keys to calculate the SysKey",\n    "tags": [\n      "attack.discovery",\n      "attack.t1012"\n    ],\n    "query": "(EventID:(\\"4656\\" OR \\"4663\\") AND ObjectType:\\"key\\" AND ObjectName.keyword:(*lsa\\\\\\\\JD OR *lsa\\\\\\\\GBG OR *lsa\\\\\\\\Skew1 OR *lsa\\\\\\\\Data))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:(\\"4656\\" OR \\"4663\\") AND ObjectType:\\"key\\" AND ObjectName.keyword:(*lsa\\\\\\\\JD OR *lsa\\\\\\\\GBG OR *lsa\\\\\\\\Skew1 OR *lsa\\\\\\\\Data))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'SysKey Registry Keys Access\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:("4656" "4663") AND ObjectType:"key" AND ObjectName.keyword:(*lsa\\\\JD *lsa\\\\GBG *lsa\\\\Skew1 *lsa\\\\Data))
```


### splunk
    
```
((EventID="4656" OR EventID="4663") ObjectType="key" (ObjectName="*lsa\\\\JD" OR ObjectName="*lsa\\\\GBG" OR ObjectName="*lsa\\\\Skew1" OR ObjectName="*lsa\\\\Data"))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id IN ["4656", "4663"] ObjectType="key" ObjectName IN ["*lsa\\\\JD", "*lsa\\\\GBG", "*lsa\\\\Skew1", "*lsa\\\\Data"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*4656|.*4663))(?=.*key)(?=.*(?:.*.*lsa\\JD|.*.*lsa\\GBG|.*.*lsa\\Skew1|.*.*lsa\\Data)))'
```



