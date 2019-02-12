| Title                | WMI Persistence - Script Event Consumer File Write                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects file writes of WMI script event consumer                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1084: Windows Management Instrumentation Event Subscription](https://attack.mitre.org/tactics/T1084)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0015_11_windows_sysmon_FileCreate](../Data_Needed/DN_0015_11_windows_sysmon_FileCreate.md)</li></ul>                                                         |
| Trigger              | <ul><li>[('Windows Management Instrumentation Event Subscription', 'T1084')](../Triggers/('Windows Management Instrumentation Event Subscription', 'T1084').md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Unknown (data set is too small; further testing needed)</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/](https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/)</li></ul>                                                          |
| Author               | Thomas Patzke                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: WMI Persistence - Script Event Consumer File Write
status: experimental
description: Detects file writes of WMI script event consumer
references:
    - https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/
author: Thomas Patzke
date: 2018/03/07
tags:
    - attack.t1084
    - attack.persistence
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 11
        Image: 'C:\WINDOWS\system32\wbem\scrcons.exe'
    condition: selection
falsepositives: 
    - Unknown (data set is too small; further testing needed)
level: high

```





### Kibana query

```
(EventID:"11" AND Image:"C\\:\\\\WINDOWS\\\\system32\\\\wbem\\\\scrcons.exe")
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/WMI-Persistence---Script-Event-Consumer-File-Write <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"11\\" AND Image:\\"C\\\\:\\\\\\\\WINDOWS\\\\\\\\system32\\\\\\\\wbem\\\\\\\\scrcons.exe\\")",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'WMI Persistence - Script Event Consumer File Write\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"11" AND Image:"C\\:\\\\WINDOWS\\\\system32\\\\wbem\\\\scrcons.exe")
```

