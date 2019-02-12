| Title                | Suspicious Control Panel DLL Load                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious Rundll32 execution from control.exe as used by Equation Group and Exploit Kits                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://twitter.com/rikvduijn/status/853251879320662017](https://twitter.com/rikvduijn/status/853251879320662017)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Suspicious Control Panel DLL Load
status: experimental
description: Detects suspicious Rundll32 execution from control.exe as used by Equation Group and Exploit Kits
author: Florian Roth
date: 2017/04/15
references:
    - https://twitter.com/rikvduijn/status/853251879320662017
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        ParentImage: '*\System32\control.exe'
        CommandLine: '*\rundll32.exe *'
    filter:
        CommandLine: '*Shell32.dll*'
    condition: selection and not filter
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: high

```





### Kibana query

```
((EventID:"1" AND ParentImage:"*\\\\System32\\\\control.exe" AND CommandLine:"*\\\\rundll32.exe *") AND NOT (CommandLine:"*Shell32.dll*"))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Suspicious-Control-Panel-DLL-Load <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "((EventID:\\"1\\" AND ParentImage:\\"*\\\\\\\\System32\\\\\\\\control.exe\\" AND CommandLine:\\"*\\\\\\\\rundll32.exe *\\") AND NOT (CommandLine:\\"*Shell32.dll*\\"))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Suspicious Control Panel DLL Load\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
((EventID:"1" AND ParentImage:"*\\\\System32\\\\control.exe" AND CommandLine:"*\\\\rundll32.exe *") AND NOT (CommandLine:"*Shell32.dll*"))
```

