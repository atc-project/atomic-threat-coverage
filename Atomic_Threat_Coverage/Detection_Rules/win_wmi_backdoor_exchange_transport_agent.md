| Title                | WMI Backdoor Exchange Transport Agent                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a WMi backdoor in Exchange Transport Agents via WMi event filters                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1084: Windows Management Instrumentation Event Subscription](https://attack.mitre.org/techniques/T1084)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Trigger              | <ul><li>[T1084: Windows Management Instrumentation Event Subscription](../Triggers/T1084.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/cglyer/status/1182389676876980224](https://twitter.com/cglyer/status/1182389676876980224)</li><li>[https://twitter.com/cglyer/status/1182391019633029120](https://twitter.com/cglyer/status/1182391019633029120)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: WMI Backdoor Exchange Transport Agent
id: 797011dc-44f4-4e6f-9f10-a8ceefbe566b
status: experimental
description: Detects a WMi backdoor in Exchange Transport Agents via WMi event filters
author: Florian Roth
date: 2019/10/11
references:
    - https://twitter.com/cglyer/status/1182389676876980224
    - https://twitter.com/cglyer/status/1182391019633029120
logsource:
    category: process_creation
    product: windows
tags:
    - attack.persistence
    - attack.t1084
detection:
    selection: 
        ParentImage: '*\EdgeTransport.exe'
    condition: selection
falsepositives:
    - Unknown
level: critical


```





### es-qs
    
```
ParentImage.keyword:*\\\\EdgeTransport.exe
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/WMI-Backdoor-Exchange-Transport-Agent <<EOF\n{\n  "metadata": {\n    "title": "WMI Backdoor Exchange Transport Agent",\n    "description": "Detects a WMi backdoor in Exchange Transport Agents via WMi event filters",\n    "tags": [\n      "attack.persistence",\n      "attack.t1084"\n    ],\n    "query": "ParentImage.keyword:*\\\\\\\\EdgeTransport.exe"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "ParentImage.keyword:*\\\\\\\\EdgeTransport.exe",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'WMI Backdoor Exchange Transport Agent\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
ParentImage.keyword:*\\\\EdgeTransport.exe
```


### splunk
    
```
ParentImage="*\\\\EdgeTransport.exe"
```


### logpoint
    
```
(event_id="1" ParentImage="*\\\\EdgeTransport.exe")
```


### grep
    
```
grep -P '^.*\\EdgeTransport\\.exe'
```



