| Title        | WMI Persistence - Script Event Consumer |
|:-------------------|:------------------|
| Description        | Detects WMI script event consumers |
| Tags               |   |
| ATT&amp;CK Tactic | ('Execution', 'TA0002'), ('Persistence', 'TA0003')  |
| ATT&amp;CK Technique | T1047  |
| Dataneeded         | , , DN_0002_windows_process_creation_with_commandline_4688DN_0001_windows_process_creation_4688, DN_0002_windows_process_creation_with_commandline_4688DN_0001_windows_process_creation_4688 |
| Triggering         | T1047 |
| Severity Level     | high       |
| False Positives    | Legitimate event consumers |
| Development Status | experimental      |
| References         | https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/ |
| Author             | Thomas Patzke      |


## Detection Rules

### Sigma rule

```
---
action: global
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
detection:
    selection:
        Image: 'C:\WINDOWS\system32\wbem\scrcons.exe'
        ParentImage: 'C:\Windows\System32\svchost.exe'
    condition: selection
falsepositives: 
    - Legitimate event consumers
level: high
---
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
---
logsource:
    product: windows
    service: security
    description: 'Requirements: Audit Policy : Detailed Tracking > Audit Process creation, Group Policy : Administrative Templates\System\Audit Process Creation'
detection:
    selection:
        EventID: 4688

```





### Kibana query

```
(EventID:"1" AND Image:"C\\:\\\\WINDOWS\\\\system32\\\\wbem\\\\scrcons.exe" AND ParentImage:"C\\:\\\\Windows\\\\System32\\\\svchost.exe")\n(EventID:"4688" AND Image:"C\\:\\\\WINDOWS\\\\system32\\\\wbem\\\\scrcons.exe" AND ParentImage:"C\\:\\\\Windows\\\\System32\\\\svchost.exe")
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/WMI-Persistence---Script-Event-Consumer <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"1\\" AND Image:\\"C\\\\:\\\\\\\\WINDOWS\\\\\\\\system32\\\\\\\\wbem\\\\\\\\scrcons.exe\\" AND ParentImage:\\"C\\\\:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\svchost.exe\\")",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'WMI Persistence - Script Event Consumer\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/WMI-Persistence---Script-Event-Consumer-2 <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"4688\\" AND Image:\\"C\\\\:\\\\\\\\WINDOWS\\\\\\\\system32\\\\\\\\wbem\\\\\\\\scrcons.exe\\" AND ParentImage:\\"C\\\\:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\svchost.exe\\")",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'WMI Persistence - Script Event Consumer\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"1" AND Image:"C\\:\\\\WINDOWS\\\\system32\\\\wbem\\\\scrcons.exe" AND ParentImage:"C\\:\\\\Windows\\\\System32\\\\svchost.exe")\n(EventID:"4688" AND Image:"C\\:\\\\WINDOWS\\\\system32\\\\wbem\\\\scrcons.exe" AND ParentImage:"C\\:\\\\Windows\\\\System32\\\\svchost.exe")
```

