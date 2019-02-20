| Title                | MavInject Process Injection                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects process injection using the signed Windows tool Mavinject32.exe                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1055: Process Injection](https://attack.mitre.org/techniques/T1055)</li><li>[T1218: Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1055: Process Injection](../Triggers/T1055.md)</li><li>[T1218: Signed Binary Proxy Execution](../Triggers/T1218.md)</li></ul>  |
| Severity Level       | critical                                                                                                                                                 |
| False Positives      | <ul><li>unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://twitter.com/gN3mes1s/status/941315826107510784](https://twitter.com/gN3mes1s/status/941315826107510784)</li><li>[https://reaqta.com/2017/12/mavinject-microsoft-injector/](https://reaqta.com/2017/12/mavinject-microsoft-injector/)</li><li>[https://twitter.com/Hexacorn/status/776122138063409152](https://twitter.com/Hexacorn/status/776122138063409152)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |
| Other Tags           | <ul><li>attack.process_injection</li><li>attack.signed_binary_proxy_execution</li></ul> | 

## Detection Rules

### Sigma rule

```
---
action: global
title: MavInject Process Injection
status: experimental
description: Detects process injection using the signed Windows tool Mavinject32.exe
references:
    - https://twitter.com/gN3mes1s/status/941315826107510784
    - https://reaqta.com/2017/12/mavinject-microsoft-injector/
    - https://twitter.com/Hexacorn/status/776122138063409152
author: Florian Roth
date: 2018/12/12
tags:
    - attack.process_injection
    - attack.t1055
    - attack.signed_binary_proxy_execution
    - attack.t1218
detection:
    condition: selection
falsepositives: 
    - unknown
level: critical
---
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        CommandLine: '* /INJECTRUNNING *'
---
logsource:
    product: windows
    service: security
    definition: 'Requirements: Audit Policy : Detailed Tracking > Audit Process creation, Group Policy : Administrative Templates\System\Audit Process Creation'
detection:
    selection:
        EventID: 4688
        ProcessCommandLine: '* /INJECTRUNNING *'

```





### Kibana query

```
(EventID:"1" AND CommandLine.keyword:*\\ \\/INJECTRUNNING\\ *)\n(EventID:"4688" AND ProcessCommandLine.keyword:*\\ \\/INJECTRUNNING\\ *)
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/MavInject-Process-Injection <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"1\\" AND CommandLine.keyword:*\\\\ \\\\/INJECTRUNNING\\\\ *)",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'MavInject Process Injection\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/MavInject-Process-Injection-2 <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"4688\\" AND ProcessCommandLine.keyword:*\\\\ \\\\/INJECTRUNNING\\\\ *)",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'MavInject Process Injection\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"1" AND CommandLine:"* \\/INJECTRUNNING *")\n(EventID:"4688" AND ProcessCommandLine:"* \\/INJECTRUNNING *")
```

