| Title                | WMI Persistence - Script Event Consumer                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects WMI script event consumers                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1047: Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1047: Windows Management Instrumentation](../Triggers/T1047.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Legitimate event consumers</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/](https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/)</li></ul>  |
| Author               | Thomas Patzke |


## Detection Rules

### Sigma rule

```
title: WMI Persistence - Script Event Consumer
status: experimental
description: Detects WMI script event consumers
references:
    - https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/
author: Thomas Patzke
date: 2018/03/07
tags:
    - attack.execution
    - attack.persistence
    - attack.t1047
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: C:\WINDOWS\system32\wbem\scrcons.exe
        ParentImage: C:\Windows\System32\svchost.exe
    condition: selection
falsepositives:
    - Legitimate event consumers
level: high

```





### es-qs
    
```
(Image:"C\\:\\\\WINDOWS\\\\system32\\\\wbem\\\\scrcons.exe" AND ParentImage:"C\\:\\\\Windows\\\\System32\\\\svchost.exe")
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/WMI-Persistence---Script-Event-Consumer <<EOF\n{\n  "metadata": {\n    "title": "WMI Persistence - Script Event Consumer",\n    "description": "Detects WMI script event consumers",\n    "tags": [\n      "attack.execution",\n      "attack.persistence",\n      "attack.t1047"\n    ],\n    "query": "(Image:\\"C\\\\:\\\\\\\\WINDOWS\\\\\\\\system32\\\\\\\\wbem\\\\\\\\scrcons.exe\\" AND ParentImage:\\"C\\\\:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\svchost.exe\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Image:\\"C\\\\:\\\\\\\\WINDOWS\\\\\\\\system32\\\\\\\\wbem\\\\\\\\scrcons.exe\\" AND ParentImage:\\"C\\\\:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\svchost.exe\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'WMI Persistence - Script Event Consumer\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image:"C\\:\\\\WINDOWS\\\\system32\\\\wbem\\\\scrcons.exe" AND ParentImage:"C\\:\\\\Windows\\\\System32\\\\svchost.exe")
```


### splunk
    
```
(Image="C:\\\\WINDOWS\\\\system32\\\\wbem\\\\scrcons.exe" ParentImage="C:\\\\Windows\\\\System32\\\\svchost.exe")
```


### logpoint
    
```
(Image="C:\\\\WINDOWS\\\\system32\\\\wbem\\\\scrcons.exe" ParentImage="C:\\\\Windows\\\\System32\\\\svchost.exe")
```


### grep
    
```
grep -P '^(?:.*(?=.*C:\\WINDOWS\\system32\\wbem\\scrcons\\.exe)(?=.*C:\\Windows\\System32\\svchost\\.exe))'
```



