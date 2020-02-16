| Title                | Suspicious Csc.exe Source File Folder                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a suspicious execution of csc.exe, which uses a source in a suspicious folder (e.g. AppData)                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1500: Compile After Delivery](https://attack.mitre.org/techniques/T1500)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Trigger              | <ul><li>[T1500: Compile After Delivery](../Triggers/T1500.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>https://twitter.com/gN3mes1s/status/1206874118282448897</li><li>https://twitter.com/gabriele_pippi/status/1206907900268072962</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://securityboulevard.com/2019/08/agent-tesla-evading-edr-by-removing-api-hooks/](https://securityboulevard.com/2019/08/agent-tesla-evading-edr-by-removing-api-hooks/)</li><li>[https://www.clearskysec.com/wp-content/uploads/2018/11/MuddyWater-Operations-in-Lebanon-and-Oman.pdf](https://www.clearskysec.com/wp-content/uploads/2018/11/MuddyWater-Operations-in-Lebanon-and-Oman.pdf)</li><li>[https://app.any.run/tasks/c6993447-d1d8-414e-b856-675325e5aa09/](https://app.any.run/tasks/c6993447-d1d8-414e-b856-675325e5aa09/)</li><li>[https://twitter.com/gN3mes1s/status/1206874118282448897](https://twitter.com/gN3mes1s/status/1206874118282448897)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious Csc.exe Source File Folder
id: dcaa3f04-70c3-427a-80b4-b870d73c94c4
description: Detects a suspicious execution of csc.exe, which uses a source in a suspicious folder (e.g. AppData)
status: experimental
references:
    - https://securityboulevard.com/2019/08/agent-tesla-evading-edr-by-removing-api-hooks/
    - https://www.clearskysec.com/wp-content/uploads/2018/11/MuddyWater-Operations-in-Lebanon-and-Oman.pdf
    - https://app.any.run/tasks/c6993447-d1d8-414e-b856-675325e5aa09/
    - https://twitter.com/gN3mes1s/status/1206874118282448897
author: Florian Roth
date: 2019/08/24
modified: 2019/12/17
tags:
    - attack.defense_evasion
    - attack.t1500
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\csc.exe'
        CommandLine: 
            - '*\AppData\\*'
            - '*\Windows\Temp\\*'
    filter:
        ParentImage: 
            - 'C:\Program Files*'  # https://twitter.com/gN3mes1s/status/1206874118282448897
            - '*\sdiagnhost.exe'  # https://twitter.com/gN3mes1s/status/1206874118282448897
            - '*\w3wp.exe'  # https://twitter.com/gabriele_pippi/status/1206907900268072962
    condition: selection and not filter
falsepositives:
    - https://twitter.com/gN3mes1s/status/1206874118282448897
    - https://twitter.com/gabriele_pippi/status/1206907900268072962
level: high

```





### es-qs
    
```
((Image.keyword:*\\\\csc.exe AND CommandLine.keyword:(*\\\\AppData\\\\* OR *\\\\Windows\\\\Temp\\\\*)) AND (NOT (ParentImage.keyword:(C\\:\\\\Program\\ Files* OR *\\\\sdiagnhost.exe OR *\\\\w3wp.exe))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Suspicious-Csc.exe-Source-File-Folder <<EOF\n{\n  "metadata": {\n    "title": "Suspicious Csc.exe Source File Folder",\n    "description": "Detects a suspicious execution of csc.exe, which uses a source in a suspicious folder (e.g. AppData)",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1500"\n    ],\n    "query": "((Image.keyword:*\\\\\\\\csc.exe AND CommandLine.keyword:(*\\\\\\\\AppData\\\\\\\\* OR *\\\\\\\\Windows\\\\\\\\Temp\\\\\\\\*)) AND (NOT (ParentImage.keyword:(C\\\\:\\\\\\\\Program\\\\ Files* OR *\\\\\\\\sdiagnhost.exe OR *\\\\\\\\w3wp.exe))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((Image.keyword:*\\\\\\\\csc.exe AND CommandLine.keyword:(*\\\\\\\\AppData\\\\\\\\* OR *\\\\\\\\Windows\\\\\\\\Temp\\\\\\\\*)) AND (NOT (ParentImage.keyword:(C\\\\:\\\\\\\\Program\\\\ Files* OR *\\\\\\\\sdiagnhost.exe OR *\\\\\\\\w3wp.exe))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious Csc.exe Source File Folder\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((Image.keyword:*\\\\csc.exe AND CommandLine.keyword:(*\\\\AppData\\\\* *\\\\Windows\\\\Temp\\\\*)) AND (NOT (ParentImage.keyword:(C\\:\\\\Program Files* *\\\\sdiagnhost.exe *\\\\w3wp.exe))))
```


### splunk
    
```
((Image="*\\\\csc.exe" (CommandLine="*\\\\AppData\\\\*" OR CommandLine="*\\\\Windows\\\\Temp\\\\*")) NOT ((ParentImage="C:\\\\Program Files*" OR ParentImage="*\\\\sdiagnhost.exe" OR ParentImage="*\\\\w3wp.exe")))
```


### logpoint
    
```
(event_id="1" (Image="*\\\\csc.exe" CommandLine IN ["*\\\\AppData\\\\*", "*\\\\Windows\\\\Temp\\\\*"])  -(ParentImage IN ["C:\\\\Program Files*", "*\\\\sdiagnhost.exe", "*\\\\w3wp.exe"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*.*\\csc\\.exe)(?=.*(?:.*.*\\AppData\\\\.*|.*.*\\Windows\\Temp\\\\.*))))(?=.*(?!.*(?:.*(?=.*(?:.*C:\\Program Files.*|.*.*\\sdiagnhost\\.exe|.*.*\\w3wp\\.exe))))))'
```



