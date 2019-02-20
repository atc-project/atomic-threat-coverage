| Title                | Possible Ransomware or unauthorized MBR modifications                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects, possibly, malicious unauthorized usage of bcdedit.exe                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set](https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set)</li></ul>                                                          |
| Author               | @neu5ron                                                                                                                                                |


## Detection Rules

### Sigma rule

```
---
action: global
title: Possible Ransomware or unauthorized MBR modifications
status: experimental
description: Detects, possibly, malicious unauthorized usage of bcdedit.exe
references:
    - https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set
author: "@neu5ron"
date: 2019/02/07
detection:
    condition: selection
level: medium
---
# Windows Security Eventlog: Process Creation with Full Command Line
logsource:
    product: windows
    service: security
    definition: 'Requirements: Audit Policy : Detailed Tracking > Audit Process creation, Group Policy : Administrative Templates\System\Audit Process Creation'
detection:
    selection:
        EventID: 4688
        NewProcessName: '*\fsutil.exe'
        ProcessCommandLine: 
            - '*delete*'
            - '*deletevalue*'
            - '*import*'
---
# Sysmon: Process Creation (ID 1)
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        Image: '*\fsutil.exe'
        ProcessCommandLine: 
            - '*delete*'
            - '*deletevalue*'
            - '*import*'

```





### Kibana query

```
(EventID:"4688" AND NewProcessName.keyword:*\\\\fsutil.exe AND ProcessCommandLine.keyword:(*delete* *deletevalue* *import*))\n(EventID:"1" AND Image.keyword:*\\\\fsutil.exe AND ProcessCommandLine.keyword:(*delete* *deletevalue* *import*))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Possible-Ransomware-or-unauthorized-MBR-modifications <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"4688\\" AND NewProcessName.keyword:*\\\\\\\\fsutil.exe AND ProcessCommandLine.keyword:(*delete* *deletevalue* *import*))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Possible Ransomware or unauthorized MBR modifications\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Possible-Ransomware-or-unauthorized-MBR-modifications-2 <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"1\\" AND Image.keyword:*\\\\\\\\fsutil.exe AND ProcessCommandLine.keyword:(*delete* *deletevalue* *import*))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Possible Ransomware or unauthorized MBR modifications\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"4688" AND NewProcessName:"*\\\\fsutil.exe" AND ProcessCommandLine:("*delete*" "*deletevalue*" "*import*"))\n(EventID:"1" AND Image:"*\\\\fsutil.exe" AND ProcessCommandLine:("*delete*" "*deletevalue*" "*import*"))
```

