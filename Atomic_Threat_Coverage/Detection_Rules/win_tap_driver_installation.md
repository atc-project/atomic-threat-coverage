| Title                | Tap driver installation                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Well-known TAP software installation. Possible preparation for data exfiltration using tunnelling techniques                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0010: Exfiltration](https://attack.mitre.org/tactics/TA0010)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1048: Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)</li></ul>  |
| Data Needed          | <ul><li>[DN_0005_7045_windows_service_insatalled](../Data_Needed/DN_0005_7045_windows_service_insatalled.md)</li><li>[DN_0010_6_windows_sysmon_driver_loaded](../Data_Needed/DN_0010_6_windows_sysmon_driver_loaded.md)</li><li>[DN_0063_4697_service_was_installed_in_the_system](../Data_Needed/DN_0063_4697_service_was_installed_in_the_system.md)</li></ul>  |
| Trigger              | <ul><li>[T1048: Exfiltration Over Alternative Protocol](../Triggers/T1048.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Legitimate OpenVPN TAP insntallation</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Daniil Yugoslavskiy, Ian Davis, oscd.community |


## Detection Rules

### Sigma rule

```
action: global
title: Tap driver installation
id: 8e4cf0e5-aa5d-4dc3-beff-dc26917744a9
description: Well-known TAP software installation. Possible preparation for data exfiltration using tunnelling techniques
status: experimental
author: Daniil Yugoslavskiy, Ian Davis, oscd.community
date: 2019/10/24
tags:
    - attack.exfiltration
    - attack.t1048
falsepositives:
    - Legitimate OpenVPN TAP insntallation
level: medium
detection:
    selection:
        ImagePath|contains: 'tap0901'
    condition: selection
---
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
---
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 6
---
 logsource:
     product: windows
     service: security
 detection:
     selection:
         EventID: 4697
```





### es-qs
    
```
(EventID:"7045" AND ImagePath.keyword:*tap0901*)\n(EventID:"6" AND ImagePath.keyword:*tap0901*)\n(EventID:"4697" AND ImagePath.keyword:*tap0901*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Tap-driver-installation <<EOF\n{\n  "metadata": {\n    "title": "Tap driver installation",\n    "description": "Well-known TAP software installation. Possible preparation for data exfiltration using tunnelling techniques",\n    "tags": [\n      "attack.exfiltration",\n      "attack.t1048"\n    ],\n    "query": "(EventID:\\"7045\\" AND ImagePath.keyword:*tap0901*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"7045\\" AND ImagePath.keyword:*tap0901*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Tap driver installation\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Tap-driver-installation-2 <<EOF\n{\n  "metadata": {\n    "title": "Tap driver installation",\n    "description": "Well-known TAP software installation. Possible preparation for data exfiltration using tunnelling techniques",\n    "tags": [\n      "attack.exfiltration",\n      "attack.t1048"\n    ],\n    "query": "(EventID:\\"6\\" AND ImagePath.keyword:*tap0901*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"6\\" AND ImagePath.keyword:*tap0901*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Tap driver installation\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Tap-driver-installation-3 <<EOF\n{\n  "metadata": {\n    "title": "Tap driver installation",\n    "description": "Well-known TAP software installation. Possible preparation for data exfiltration using tunnelling techniques",\n    "tags": [\n      "attack.exfiltration",\n      "attack.t1048"\n    ],\n    "query": "(EventID:\\"4697\\" AND ImagePath.keyword:*tap0901*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"4697\\" AND ImagePath.keyword:*tap0901*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Tap driver installation\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"7045" AND ImagePath.keyword:*tap0901*)\n(EventID:"6" AND ImagePath.keyword:*tap0901*)\n(EventID:"4697" AND ImagePath.keyword:*tap0901*)
```


### splunk
    
```
(EventID="7045" ImagePath="*tap0901*")\n(EventID="6" ImagePath="*tap0901*")\n(EventID="4697" ImagePath="*tap0901*")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="7045" ImagePath="*tap0901*")\n(event_id="6" ImagePath="*tap0901*")\n(event_source="Microsoft-Windows-Security-Auditing" event_id="4697" ImagePath="*tap0901*")
```


### grep
    
```
grep -P '^(?:.*(?=.*7045)(?=.*.*tap0901.*))'\ngrep -P '^(?:.*(?=.*6)(?=.*.*tap0901.*))'\ngrep -P '^(?:.*(?=.*4697)(?=.*.*tap0901.*))'
```



