| Title                | Suspicious Svchost Processes                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious svchost processes with parent process that is not services.exe, command line missing -k parameter or running outside Windows folder                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Renamed %SystemRoot%s</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://twitter.com/Moti_B/status/1002280132143394816](https://twitter.com/Moti_B/status/1002280132143394816)</li><li>[https://twitter.com/Moti_B/status/1002280287840153601](https://twitter.com/Moti_B/status/1002280287840153601)</li></ul>                                                          |
| Author               | Florian Roth, @c_APT_ure                                                                                                                                                |


## Detection Rules

### Sigma rule

```
---
action: global
title: Suspicious Svchost Processes
description: Detects suspicious svchost processes with parent process that is not services.exe, command line missing -k parameter or running outside Windows folder
author: Florian Roth, @c_APT_ure
date: 2018/10/26
status: experimental
references:
    - https://twitter.com/Moti_B/status/1002280132143394816
    - https://twitter.com/Moti_B/status/1002280287840153601
falsepositives: 
    - Renamed %SystemRoot%s 
level: high
---
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        Image: '*\svchost.exe'
    filter1:
        ParentImage: 
            - '*\services.exe'
            - '*\MsMpEng.exe'
    filter2:
        CommandLine: '* -k *'
    filter3:
        Image: 'C:\Windows\S*'  # \* is a reserved expression
    condition: selection and not ( filter1 or filter2 or filter3 )
---
logsource:
    product: windows
    service: security
    definition: 'Requirements: Audit Policy : Detailed Tracking > Audit Process creation, Group Policy : Administrative Templates\System\Audit Process Creation'
detection:
    selection:
        EventID: 4688
        NewProcessName: '*\svchost.exe'
    # Deactivated as long as some backends do not fully support the 'null' expression
    # filter2:
    #    ProcessCommandLine:
    #        - null  # Missing KB3004375 and Group Policy setting
    #        - '* -k *'
    filter3:
        NewProcessName: 'C:\Windows\S*'  # \* is a reserved expression
    condition: selection and not filter3

        

```





### Kibana query

```
((EventID:"1" AND Image:"*\\\\svchost.exe") AND NOT ((ParentImage:("*\\\\services.exe" "*\\\\MsMpEng.exe") OR CommandLine:"* \\-k *" OR Image:"C\\:\\\\Windows\\\\S*")))\n((EventID:"4688" AND NewProcessName:"*\\\\svchost.exe") AND NOT (NewProcessName:"C\\:\\\\Windows\\\\S*"))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Suspicious-Svchost-Processes <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "((EventID:\\"1\\" AND Image:\\"*\\\\\\\\svchost.exe\\") AND NOT ((ParentImage:(\\"*\\\\\\\\services.exe\\" \\"*\\\\\\\\MsMpEng.exe\\") OR CommandLine:\\"* \\\\-k *\\" OR Image:\\"C\\\\:\\\\\\\\Windows\\\\\\\\S*\\")))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Suspicious Svchost Processes\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Suspicious-Svchost-Processes-2 <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "((EventID:\\"4688\\" AND NewProcessName:\\"*\\\\\\\\svchost.exe\\") AND NOT (NewProcessName:\\"C\\\\:\\\\\\\\Windows\\\\\\\\S*\\"))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Suspicious Svchost Processes\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
((EventID:"1" AND Image:"*\\\\svchost.exe") AND NOT ((ParentImage:("*\\\\services.exe" "*\\\\MsMpEng.exe") OR CommandLine:"* \\-k *" OR Image:"C\\:\\\\Windows\\\\S*")))\n((EventID:"4688" AND NewProcessName:"*\\\\svchost.exe") AND NOT (NewProcessName:"C\\:\\\\Windows\\\\S*"))
```

