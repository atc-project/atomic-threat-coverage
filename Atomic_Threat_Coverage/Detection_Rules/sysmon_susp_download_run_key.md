| Title                | Suspicious RUN Key from Download                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the suspicious RUN keys created by software located in Download or temporary Outlook/Internet Explorer directories                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1060: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1060)</li></ul>  |
| Data Needed          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| Trigger              | <ul><li>[T1060: Registry Run Keys / Startup Folder](../Triggers/T1060.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Software installers downloaded and used by users</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://app.any.run/tasks/c5bef5b7-f484-4c43-9cf3-d5c5c7839def/](https://app.any.run/tasks/c5bef5b7-f484-4c43-9cf3-d5c5c7839def/)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious RUN Key from Download
id: 9c5037d1-c568-49b3-88c7-9846a5bdc2be
status: experimental
description: Detects the suspicious RUN keys created by software located in Download or temporary Outlook/Internet Explorer directories
references:
    - https://app.any.run/tasks/c5bef5b7-f484-4c43-9cf3-d5c5c7839def/
author: Florian Roth
date: 2019/10/01
tags:
    - attack.persistence
    - attack.t1060
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        Image: 
            - '*\Downloads\\*'
            - '*\Temporary Internet Files\Content.Outlook\\*'
            - '*\Local Settings\Temporary Internet Files\\*'
        TargetObject: '*\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\\*'
    condition: selection
falsepositives:
    - Software installers downloaded and used by users
level: high
```





### es-qs
    
```
(EventID:"13" AND Image.keyword:(*\\\\Downloads\\\\* OR *\\\\Temporary\\ Internet\\ Files\\\\Content.Outlook\\\\* OR *\\\\Local\\ Settings\\\\Temporary\\ Internet\\ Files\\\\*) AND TargetObject.keyword:*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Suspicious-RUN-Key-from-Download <<EOF\n{\n  "metadata": {\n    "title": "Suspicious RUN Key from Download",\n    "description": "Detects the suspicious RUN keys created by software located in Download or temporary Outlook/Internet Explorer directories",\n    "tags": [\n      "attack.persistence",\n      "attack.t1060"\n    ],\n    "query": "(EventID:\\"13\\" AND Image.keyword:(*\\\\\\\\Downloads\\\\\\\\* OR *\\\\\\\\Temporary\\\\ Internet\\\\ Files\\\\\\\\Content.Outlook\\\\\\\\* OR *\\\\\\\\Local\\\\ Settings\\\\\\\\Temporary\\\\ Internet\\\\ Files\\\\\\\\*) AND TargetObject.keyword:*\\\\\\\\SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\CurrentVersion\\\\\\\\Run\\\\\\\\*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"13\\" AND Image.keyword:(*\\\\\\\\Downloads\\\\\\\\* OR *\\\\\\\\Temporary\\\\ Internet\\\\ Files\\\\\\\\Content.Outlook\\\\\\\\* OR *\\\\\\\\Local\\\\ Settings\\\\\\\\Temporary\\\\ Internet\\\\ Files\\\\\\\\*) AND TargetObject.keyword:*\\\\\\\\SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\CurrentVersion\\\\\\\\Run\\\\\\\\*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious RUN Key from Download\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"13" AND Image.keyword:(*\\\\Downloads\\\\* *\\\\Temporary Internet Files\\\\Content.Outlook\\\\* *\\\\Local Settings\\\\Temporary Internet Files\\\\*) AND TargetObject.keyword:*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\*)
```


### splunk
    
```
(EventID="13" (Image="*\\\\Downloads\\\\*" OR Image="*\\\\Temporary Internet Files\\\\Content.Outlook\\\\*" OR Image="*\\\\Local Settings\\\\Temporary Internet Files\\\\*") TargetObject="*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\*")
```


### logpoint
    
```
(event_id="13" Image IN ["*\\\\Downloads\\\\*", "*\\\\Temporary Internet Files\\\\Content.Outlook\\\\*", "*\\\\Local Settings\\\\Temporary Internet Files\\\\*"] TargetObject="*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\*")
```


### grep
    
```
grep -P '^(?:.*(?=.*13)(?=.*(?:.*.*\\Downloads\\\\.*|.*.*\\Temporary Internet Files\\Content\\.Outlook\\\\.*|.*.*\\Local Settings\\Temporary Internet Files\\\\.*))(?=.*.*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\\\.*))'
```



