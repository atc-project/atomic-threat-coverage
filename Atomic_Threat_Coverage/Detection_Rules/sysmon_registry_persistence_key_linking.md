| Title                | Windows Registry Persistence COM Key Linking                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects COM object hijacking via TreatAs subkey                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1122: Component Object Model Hijacking](https://attack.mitre.org/techniques/T1122)</li></ul>  |
| Data Needed          | <ul><li>[DN_0016_12_windows_sysmon_RegistryEvent](../Data_Needed/DN_0016_12_windows_sysmon_RegistryEvent.md)</li></ul>  |
| Trigger              | <ul><li>[T1122: Component Object Model Hijacking](../Triggers/T1122.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Maybe some system utilities in rare cases use linking keys for backward compability</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/](https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/)</li></ul>  |
| Author               | Kutepov Anton, oscd.community |


## Detection Rules

### Sigma rule

```
title: Windows Registry Persistence COM Key Linking
id: 9b0f8a61-91b2-464f-aceb-0527e0a45020
status: experimental
description: Detects COM object hijacking via TreatAs subkey
references:
    - https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/
author: Kutepov Anton, oscd.community
date: 2019/10/23
modified: 2019/11/07
tags:
    - attack.persistence
    - attack.t1122
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 12
        TargetObject: 'HKU\\*_Classes\CLSID\\*\TreatAs'
    condition: selection
falsepositives:
    - Maybe some system utilities in rare cases use linking keys for backward compability
level: medium

```





### es-qs
    
```
(EventID:"12" AND TargetObject.keyword:HKU\\\\*_Classes\\\\CLSID\\\\*\\\\TreatAs)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/9b0f8a61-91b2-464f-aceb-0527e0a45020 <<EOF\n{\n  "metadata": {\n    "title": "Windows Registry Persistence COM Key Linking",\n    "description": "Detects COM object hijacking via TreatAs subkey",\n    "tags": [\n      "attack.persistence",\n      "attack.t1122"\n    ],\n    "query": "(EventID:\\"12\\" AND TargetObject.keyword:HKU\\\\\\\\*_Classes\\\\\\\\CLSID\\\\\\\\*\\\\\\\\TreatAs)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"12\\" AND TargetObject.keyword:HKU\\\\\\\\*_Classes\\\\\\\\CLSID\\\\\\\\*\\\\\\\\TreatAs)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Windows Registry Persistence COM Key Linking\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"12" AND TargetObject.keyword:HKU\\\\*_Classes\\\\CLSID\\\\*\\\\TreatAs)
```


### splunk
    
```
(EventID="12" TargetObject="HKU\\\\*_Classes\\\\CLSID\\\\*\\\\TreatAs")
```


### logpoint
    
```
(event_id="12" TargetObject="HKU\\\\*_Classes\\\\CLSID\\\\*\\\\TreatAs")
```


### grep
    
```
grep -P '^(?:.*(?=.*12)(?=.*HKU\\\\.*_Classes\\CLSID\\\\.*\\TreatAs))'
```



