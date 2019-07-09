| Title                | Windows 10 scheduled task SandboxEscaper 0-day                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects Task Scheduler .job import arbitrary DACL write\par                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1053: Scheduled Task](https://attack.mitre.org/techniques/T1053)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1053: Scheduled Task](../Triggers/T1053.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/SandboxEscaper/polarbearrepo/tree/master/bearlpe](https://github.com/SandboxEscaper/polarbearrepo/tree/master/bearlpe)</li></ul>  |
| Author               | Olaf Hartong |
| Other Tags           | <ul><li>car.2013-08-001</li><li>car.2013-08-001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Windows 10 scheduled task SandboxEscaper 0-day 
status: experimental
description: Detects Task Scheduler .job import arbitrary DACL write\par
references:
   - https://github.com/SandboxEscaper/polarbearrepo/tree/master/bearlpe
author: Olaf Hartong
date: 2019/05/22
logsource:
    category: process_creation
    product: windows
detection:
   selection:
       Image: 'schtasks.exe'
       CommandLine: '*/change*/TN*/RU*/RP*'
   condition: selection
falsepositives:
   - Unknown
tags:
    - attack.privilege_escalation
    - attack.execution
    - attack.t1053
    - car.2013-08-001
level: high

```





### es-qs
    
```
(Image:"schtasks.exe" AND CommandLine.keyword:*\\/change*\\/TN*\\/RU*\\/RP*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Windows-10-scheduled-task-SandboxEscaper-0-day <<EOF\n{\n  "metadata": {\n    "title": "Windows 10 scheduled task SandboxEscaper 0-day",\n    "description": "Detects Task Scheduler .job import arbitrary DACL write\\\\par",\n    "tags": [\n      "attack.privilege_escalation",\n      "attack.execution",\n      "attack.t1053",\n      "car.2013-08-001"\n    ],\n    "query": "(Image:\\"schtasks.exe\\" AND CommandLine.keyword:*\\\\/change*\\\\/TN*\\\\/RU*\\\\/RP*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Image:\\"schtasks.exe\\" AND CommandLine.keyword:*\\\\/change*\\\\/TN*\\\\/RU*\\\\/RP*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Windows 10 scheduled task SandboxEscaper 0-day\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image:"schtasks.exe" AND CommandLine:"*\\/change*\\/TN*\\/RU*\\/RP*")
```


### splunk
    
```
(Image="schtasks.exe" CommandLine="*/change*/TN*/RU*/RP*")
```


### logpoint
    
```
(Image="schtasks.exe" CommandLine="*/change*/TN*/RU*/RP*")
```


### grep
    
```
grep -P '^(?:.*(?=.*schtasks\\.exe)(?=.*.*/change.*/TN.*/RU.*/RP.*))'
```



