| Title                | Detection of PowerShell Execution via DLL                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects PowerShell Strings applied to rundllas seen in PowerShdll.dll                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://github.com/p3nt4/PowerShdll/blob/master/README.md](https://github.com/p3nt4/PowerShdll/blob/master/README.md)</li></ul>                                                          |
| Author               | Markus Neis                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Detection of PowerShell Execution via DLL
status: experimental
description: Detects PowerShell Strings applied to rundllas seen in PowerShdll.dll
references:
    - https://github.com/p3nt4/PowerShdll/blob/master/README.md
tags:
    - attack.execution
    - attack.t1086
author: Markus Neis
date: 2018/08/25
logsource:
    product: windows
    service: sysmon
detection:
    selection1:
        EventID: 1
        Image:
            - '*\rundll32.exe'
    selection2:
        EventID: 1
        Description:
            - '*Windows-Hostprozess (Rundll32)*'
    selection3:
        EventID: 1
        CommandLine:
            - '*Default.GetString*'
            - '*FromBase64String*'
    condition: (selection1 or selection2) and selection3
falsepositives:
    - Unknown
level: high

```





### Kibana query

```
(EventID:"1" AND (Image.keyword:(*\\\\rundll32.exe) OR Description.keyword:(*Windows\\-Hostprozess\\ \\(Rundll32\\)*)) AND CommandLine.keyword:(*Default.GetString* *FromBase64String*))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Detection-of-PowerShell-Execution-via-DLL <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"1\\" AND (Image.keyword:(*\\\\\\\\rundll32.exe) OR Description.keyword:(*Windows\\\\-Hostprozess\\\\ \\\\(Rundll32\\\\)*)) AND CommandLine.keyword:(*Default.GetString* *FromBase64String*))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Detection of PowerShell Execution via DLL\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"1" AND (Image:("*\\\\rundll32.exe") OR Description:("*Windows\\-Hostprozess \\(Rundll32\\)*")) AND CommandLine:("*Default.GetString*" "*FromBase64String*"))
```





### Splunk

```
(EventID="1" ((Image="*\\\\rundll32.exe") OR (Description="*Windows-Hostprozess (Rundll32)*")) (CommandLine="*Default.GetString*" OR CommandLine="*FromBase64String*"))
```





### Logpoint

```
(EventID="1" (Image IN ["*\\\\rundll32.exe"] OR Description IN ["*Windows-Hostprozess (Rundll32)*"]) CommandLine IN ["*Default.GetString*", "*FromBase64String*"])
```





### Grep

```
grep -P '^(?:.*(?=.*1)(?=.*(?:.*(?:.*(?:.*.*\\rundll32\\.exe)|.*(?:.*.*Windows-Hostprozess \\(Rundll32\\).*))))(?=.*(?:.*.*Default\\.GetString.*|.*.*FromBase64String.*)))'
```





### Fieldlist

```
CommandLine\nDescription\nEventID\nImage
```

