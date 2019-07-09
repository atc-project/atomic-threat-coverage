| Title                | CACTUSTORCH Remote Thread Creation                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects remote thread creation from CACTUSTORCH as described in references.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1055: Process Injection](https://attack.mitre.org/techniques/T1055)</li><li>[T1064: Scripting](https://attack.mitre.org/techniques/T1064)</li></ul>  |
| Data Needed          | <ul><li>[DN_0012_8_windows_sysmon_CreateRemoteThread](../Data_Needed/DN_0012_8_windows_sysmon_CreateRemoteThread.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1055: Process Injection](../Triggers/T1055.md)</li><li>[T1064: Scripting](../Triggers/T1064.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/SBousseaden/status/1090588499517079552](https://twitter.com/SBousseaden/status/1090588499517079552)</li><li>[https://github.com/mdsecactivebreach/CACTUSTORCH](https://github.com/mdsecactivebreach/CACTUSTORCH)</li></ul>  |
| Author               | @SBousseaden (detection), Thomas Patzke (rule) |


## Detection Rules

### Sigma rule

```
title: CACTUSTORCH Remote Thread Creation
description: Detects remote thread creation from CACTUSTORCH as described in references.
references:
    - https://twitter.com/SBousseaden/status/1090588499517079552
    - https://github.com/mdsecactivebreach/CACTUSTORCH
status: experimental
author: "@SBousseaden (detection), Thomas Patzke (rule)"
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 8
        SourceImage:
            - '*\System32\cscript.exe'
            - '*\System32\wscript.exe'
            - '*\System32\mshta.exe'
            - '*\winword.exe'
            - '*\excel.exe'
        TargetImage: '*\SysWOW64\\*'
        StartModule: null
    condition: selection
tags:
    - attack.execution
    - attack.t1055
    - attack.t1064
falsepositives:
    - unknown
level: high

```





### es-qs
    
```
(EventID:"8" AND SourceImage.keyword:(*\\\\System32\\\\cscript.exe *\\\\System32\\\\wscript.exe *\\\\System32\\\\mshta.exe *\\\\winword.exe *\\\\excel.exe) AND TargetImage.keyword:*\\\\SysWOW64\\\\* AND NOT _exists_:StartModule)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/CACTUSTORCH-Remote-Thread-Creation <<EOF\n{\n  "metadata": {\n    "title": "CACTUSTORCH Remote Thread Creation",\n    "description": "Detects remote thread creation from CACTUSTORCH as described in references.",\n    "tags": [\n      "attack.execution",\n      "attack.t1055",\n      "attack.t1064"\n    ],\n    "query": "(EventID:\\"8\\" AND SourceImage.keyword:(*\\\\\\\\System32\\\\\\\\cscript.exe *\\\\\\\\System32\\\\\\\\wscript.exe *\\\\\\\\System32\\\\\\\\mshta.exe *\\\\\\\\winword.exe *\\\\\\\\excel.exe) AND TargetImage.keyword:*\\\\\\\\SysWOW64\\\\\\\\* AND NOT _exists_:StartModule)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"8\\" AND SourceImage.keyword:(*\\\\\\\\System32\\\\\\\\cscript.exe *\\\\\\\\System32\\\\\\\\wscript.exe *\\\\\\\\System32\\\\\\\\mshta.exe *\\\\\\\\winword.exe *\\\\\\\\excel.exe) AND TargetImage.keyword:*\\\\\\\\SysWOW64\\\\\\\\* AND NOT _exists_:StartModule)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'CACTUSTORCH Remote Thread Creation\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"8" AND SourceImage:("*\\\\System32\\\\cscript.exe" "*\\\\System32\\\\wscript.exe" "*\\\\System32\\\\mshta.exe" "*\\\\winword.exe" "*\\\\excel.exe") AND TargetImage:"*\\\\SysWOW64\\\\*" AND NOT _exists_:StartModule)
```


### splunk
    
```
(EventID="8" (SourceImage="*\\\\System32\\\\cscript.exe" OR SourceImage="*\\\\System32\\\\wscript.exe" OR SourceImage="*\\\\System32\\\\mshta.exe" OR SourceImage="*\\\\winword.exe" OR SourceImage="*\\\\excel.exe") TargetImage="*\\\\SysWOW64\\\\*" NOT StartModule="*")
```


### logpoint
    
```
(EventID="8" SourceImage IN ["*\\\\System32\\\\cscript.exe", "*\\\\System32\\\\wscript.exe", "*\\\\System32\\\\mshta.exe", "*\\\\winword.exe", "*\\\\excel.exe"] TargetImage="*\\\\SysWOW64\\\\*" -StartModule=*)
```


### grep
    
```
grep -P '^(?:.*(?=.*8)(?=.*(?:.*.*\\System32\\cscript\\.exe|.*.*\\System32\\wscript\\.exe|.*.*\\System32\\mshta\\.exe|.*.*\\winword\\.exe|.*.*\\excel\\.exe))(?=.*.*\\SysWOW64\\\\.*)(?=.*(?!StartModule)))'
```



