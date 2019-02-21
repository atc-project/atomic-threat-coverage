| Title                | Adwind RAT / JRAT                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects javaw.exe in AppData folder as used by Adwind / JRAT                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0015_11_windows_sysmon_FileCreate](../Data_Needed/DN_0015_11_windows_sysmon_FileCreate.md)</li><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://www.hybrid-analysis.com/sample/ba86fa0d4b6af2db0656a88b1dd29f36fe362473ae8ad04255c4e52f214a541c?environmentId=100](https://www.hybrid-analysis.com/sample/ba86fa0d4b6af2db0656a88b1dd29f36fe362473ae8ad04255c4e52f214a541c?environmentId=100)</li><li>[https://www.first.org/resources/papers/conf2017/Advanced-Incident-Detection-and-Threat-Hunting-using-Sysmon-and-Splunk.pdf](https://www.first.org/resources/papers/conf2017/Advanced-Incident-Detection-and-Threat-Hunting-using-Sysmon-and-Splunk.pdf)</li></ul>                                                          |
| Author               | Florian Roth, Tom Ueltschi                                                                                                                                                |


## Detection Rules

### Sigma rule

```
---
action: global
title: Adwind RAT / JRAT
status: experimental
description: Detects javaw.exe in AppData folder as used by Adwind / JRAT
references:
    - https://www.hybrid-analysis.com/sample/ba86fa0d4b6af2db0656a88b1dd29f36fe362473ae8ad04255c4e52f214a541c?environmentId=100
    - https://www.first.org/resources/papers/conf2017/Advanced-Incident-Detection-and-Threat-Hunting-using-Sysmon-and-Splunk.pdf
author: Florian Roth, Tom Ueltschi
date: 2017/11/10
detection:
    condition: selection
level: high
---
# Windows Security Eventlog: Process Creation with Full Command Line
logsource:
    product: windows
    service: security
    definition: 'Requirements: Audit Policy : Detailed Tracking > Audit Process creation, Group Policy : Administrative Templates\System\Audit Process Creation'
detection:
    selection:
        EventID: 4688
        CommandLine: 
            - '*\AppData\Roaming\Oracle*\java*.exe *'
            - '*cscript.exe *Retrive*.vbs *'
---
# Sysmon: Process Creation (ID 1)
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        Image: '*\AppData\Roaming\Oracle\bin\java*.exe'
---
# Sysmon: File Creation (ID 11)
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 11
        TargetFilename: 
            - '*\AppData\Roaming\Oracle\bin\java*.exe'
            - '*\Retrive*.vbs'
---
# Sysmon: Registry Value Set (ID 13)
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        TargetObject: '\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run*'
        Details: '%AppData%\Roaming\Oracle\bin\*'

```





### Kibana query

```
(EventID:"4688" AND CommandLine.keyword:(*\\\\AppData\\\\Roaming\\\\Oracle*\\\\java*.exe\\ * *cscript.exe\\ *Retrive*.vbs\\ *))\n(EventID:"1" AND Image.keyword:*\\\\AppData\\\\Roaming\\\\Oracle\\\\bin\\\\java*.exe)\n(EventID:"11" AND TargetFilename.keyword:(*\\\\AppData\\\\Roaming\\\\Oracle\\\\bin\\\\java*.exe *\\\\Retrive*.vbs))\n(EventID:"13" AND TargetObject.keyword:\\\\REGISTRY\\\\MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run* AND Details:"%AppData%\\\\Roaming\\\\Oracle\\\\bin\\*")
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Adwind-RAT-/-JRAT <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"4688\\" AND CommandLine.keyword:(*\\\\\\\\AppData\\\\\\\\Roaming\\\\\\\\Oracle*\\\\\\\\java*.exe\\\\ * *cscript.exe\\\\ *Retrive*.vbs\\\\ *))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Adwind RAT / JRAT\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Adwind-RAT-/-JRAT-2 <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"1\\" AND Image.keyword:*\\\\\\\\AppData\\\\\\\\Roaming\\\\\\\\Oracle\\\\\\\\bin\\\\\\\\java*.exe)",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Adwind RAT / JRAT\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Adwind-RAT-/-JRAT-3 <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"11\\" AND TargetFilename.keyword:(*\\\\\\\\AppData\\\\\\\\Roaming\\\\\\\\Oracle\\\\\\\\bin\\\\\\\\java*.exe *\\\\\\\\Retrive*.vbs))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Adwind RAT / JRAT\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Adwind-RAT-/-JRAT-4 <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"13\\" AND TargetObject.keyword:\\\\\\\\REGISTRY\\\\\\\\MACHINE\\\\\\\\SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\CurrentVersion\\\\\\\\Run* AND Details:\\"%AppData%\\\\\\\\Roaming\\\\\\\\Oracle\\\\\\\\bin\\\\*\\")",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Adwind RAT / JRAT\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"4688" AND CommandLine:("*\\\\AppData\\\\Roaming\\\\Oracle*\\\\java*.exe *" "*cscript.exe *Retrive*.vbs *"))\n(EventID:"1" AND Image:"*\\\\AppData\\\\Roaming\\\\Oracle\\\\bin\\\\java*.exe")\n(EventID:"11" AND TargetFilename:("*\\\\AppData\\\\Roaming\\\\Oracle\\\\bin\\\\java*.exe" "*\\\\Retrive*.vbs"))\n(EventID:"13" AND TargetObject:"\\\\REGISTRY\\\\MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run*" AND Details:"%AppData%\\\\Roaming\\\\Oracle\\\\bin\\*")
```

