| Title                | New RUN Key Pointing to Suspicious Folder                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious new RUN key element pointing to an executable in a suspicious folder                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1060](https://attack.mitre.org/tactics/T1060)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1060](../Triggers/T1060.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Software with rare behaviour</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html](https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html)</li></ul>                                                          |
| Author               | Florian Roth, Markus Neis                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: New RUN Key Pointing to Suspicious Folder
status: experimental
description: Detects suspicious new RUN key element pointing to an executable in a suspicious folder
references:
    - https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html
author: Florian Roth, Markus Neis
tags:
    - attack.persistence
    - attack.t1060
date: 2018/25/08
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        TargetObject: 
          - '*\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\*'
          - '*\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\*'
        Details:
          - 'C:\Windows\Temp\*'
          - '*\AppData\*'
          - 'C:\$Recycle.bin\*'
          - 'C:\Temp\*'
          - 'C:\Users\Public\*'
          - 'C:\Users\Default\*'
          - 'C:\Users\Desktop\*'
    condition: selection
fields:
    - Image
falsepositives:
    - Software with rare behaviour
level: high

```





### Kibana query

```
(EventID:"13" AND TargetObject.keyword:(*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\* *\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce\\*) AND Details.keyword:(C\\:\\\\Windows\\\\Temp\\* *\\\\AppData\\* C\\:\\\\$Recycle.bin\\* C\\:\\\\Temp\\* C\\:\\\\Users\\\\Public\\* C\\:\\\\Users\\\\Default\\* C\\:\\\\Users\\\\Desktop\\*))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/New-RUN-Key-Pointing-to-Suspicious-Folder <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"13\\" AND TargetObject.keyword:(*\\\\\\\\SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\CurrentVersion\\\\\\\\Run\\\\* *\\\\\\\\SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\CurrentVersion\\\\\\\\RunOnce\\\\*) AND Details.keyword:(C\\\\:\\\\\\\\Windows\\\\\\\\Temp\\\\* *\\\\\\\\AppData\\\\* C\\\\:\\\\\\\\$Recycle.bin\\\\* C\\\\:\\\\\\\\Temp\\\\* C\\\\:\\\\\\\\Users\\\\\\\\Public\\\\* C\\\\:\\\\\\\\Users\\\\\\\\Default\\\\* C\\\\:\\\\\\\\Users\\\\\\\\Desktop\\\\*))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'New RUN Key Pointing to Suspicious Folder\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\nImage = {{_source.Image}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"13" AND TargetObject:("*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\*" "*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce\\*") AND Details:("C\\:\\\\Windows\\\\Temp\\*" "*\\\\AppData\\*" "C\\:\\\\$Recycle.bin\\*" "C\\:\\\\Temp\\*" "C\\:\\\\Users\\\\Public\\*" "C\\:\\\\Users\\\\Default\\*" "C\\:\\\\Users\\\\Desktop\\*"))
```

