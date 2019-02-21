| Title                | Bitsadmin Download                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects usage of bitsadmin downloading a file                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1197: BITS Jobs](https://attack.mitre.org/techniques/T1197)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1197: BITS Jobs](../Triggers/T1197.md)</li></ul>  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul><li>Some legitimate apps use this, but limited.</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://blog.netspi.com/15-ways-to-download-a-file/#bitsadmin](https://blog.netspi.com/15-ways-to-download-a-file/#bitsadmin)</li><li>[https://isc.sans.edu/diary/22264](https://isc.sans.edu/diary/22264)</li></ul>                                                          |
| Author               | Michael Haag                                                                                                                                                |
| Other Tags           | <ul><li>attack.s0190</li><li>attack.s0190</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Bitsadmin Download
status: experimental
description: Detects usage of bitsadmin downloading a file
references:
    - https://blog.netspi.com/15-ways-to-download-a-file/#bitsadmin
    - https://isc.sans.edu/diary/22264
tags:
    - attack.defense_evasion
    - attack.persistence
    - attack.t1197
    - attack.s0190
author: Michael Haag
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        Image:
            - '*\bitsadmin.exe'
        CommandLine:
            - '/transfer'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Some legitimate apps use this, but limited.
level: medium

```




### esqs
    
```
(EventID:"1" AND Image.keyword:(*\\\\bitsadmin.exe) AND CommandLine:("\\/transfer"))
```


### xpackwatcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Bitsadmin-Download <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"1\\" AND Image.keyword:(*\\\\\\\\bitsadmin.exe) AND CommandLine:(\\"\\\\/transfer\\"))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Bitsadmin Download\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"1" AND Image:("*\\\\bitsadmin.exe") AND CommandLine:("\\/transfer"))
```


### splunk
    
```
(EventID="1" (Image="*\\\\bitsadmin.exe") (CommandLine="/transfer")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(EventID="1" Image IN ["*\\\\bitsadmin.exe"] CommandLine IN ["/transfer"])
```


### grep
    
```
grep -P '^(?:.*(?=.*1)(?=.*(?:.*.*\\bitsadmin\\.exe))(?=.*(?:.*/transfer)))'
```


