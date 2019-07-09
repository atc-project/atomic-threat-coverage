| Title                | LSASS Memory Dump                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects process LSASS memory dump using procdump or taskmgr based on the CallTrace pointing to dbghelp.dll or dbgcore.dll for win10                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          | <ul><li>[DN_0014_10_windows_sysmon_ProcessAccess](../Data_Needed/DN_0014_10_windows_sysmon_ProcessAccess.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://blog.menasec.net/2019/02/threat-hunting-21-procdump-or-taskmgr.html](https://blog.menasec.net/2019/02/threat-hunting-21-procdump-or-taskmgr.html)</li></ul>  |
| Author               | Samir Bousseaden |
| Other Tags           | <ul><li>attack.s0002</li><li>attack.s0002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: LSASS Memory Dump
status: experimental
description: Detects process LSASS memory dump using procdump or taskmgr based on the CallTrace pointing to dbghelp.dll or dbgcore.dll for win10
author: Samir Bousseaden
references:
    - https://blog.menasec.net/2019/02/threat-hunting-21-procdump-or-taskmgr.html
tags:
    - attack.t1003
    - attack.s0002
    - attack.credential_access
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 10
        TargetImage: 'C:\windows\system32\lsass.exe'
        GrantedAccess: '0x1fffff'
        CallTrace:
         - '*dbghelp.dll*'
         - '*dbgcore.dll*'
    condition: selection
falsepositives:
    - unknown
level: high

```





### es-qs
    
```
(EventID:"10" AND TargetImage:"C\\:\\\\windows\\\\system32\\\\lsass.exe" AND GrantedAccess:"0x1fffff" AND CallTrace.keyword:(*dbghelp.dll* *dbgcore.dll*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/LSASS-Memory-Dump <<EOF\n{\n  "metadata": {\n    "title": "LSASS Memory Dump",\n    "description": "Detects process LSASS memory dump using procdump or taskmgr based on the CallTrace pointing to dbghelp.dll or dbgcore.dll for win10",\n    "tags": [\n      "attack.t1003",\n      "attack.s0002",\n      "attack.credential_access"\n    ],\n    "query": "(EventID:\\"10\\" AND TargetImage:\\"C\\\\:\\\\\\\\windows\\\\\\\\system32\\\\\\\\lsass.exe\\" AND GrantedAccess:\\"0x1fffff\\" AND CallTrace.keyword:(*dbghelp.dll* *dbgcore.dll*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"10\\" AND TargetImage:\\"C\\\\:\\\\\\\\windows\\\\\\\\system32\\\\\\\\lsass.exe\\" AND GrantedAccess:\\"0x1fffff\\" AND CallTrace.keyword:(*dbghelp.dll* *dbgcore.dll*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'LSASS Memory Dump\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"10" AND TargetImage:"C\\:\\\\windows\\\\system32\\\\lsass.exe" AND GrantedAccess:"0x1fffff" AND CallTrace:("*dbghelp.dll*" "*dbgcore.dll*"))
```


### splunk
    
```
(EventID="10" TargetImage="C:\\\\windows\\\\system32\\\\lsass.exe" GrantedAccess="0x1fffff" (CallTrace="*dbghelp.dll*" OR CallTrace="*dbgcore.dll*"))
```


### logpoint
    
```
(EventID="10" TargetImage="C:\\\\windows\\\\system32\\\\lsass.exe" GrantedAccess="0x1fffff" CallTrace IN ["*dbghelp.dll*", "*dbgcore.dll*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*10)(?=.*C:\\windows\\system32\\lsass\\.exe)(?=.*0x1fffff)(?=.*(?:.*.*dbghelp\\.dll.*|.*.*dbgcore\\.dll.*)))'
```



