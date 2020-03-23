| Title                | Exfiltration and Tunneling Tools Execution                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Execution of well known tools for data exfiltration and tunneling                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0010: Exfiltration](https://attack.mitre.org/tactics/TA0010)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1020: Automated Exfiltration](https://attack.mitre.org/techniques/T1020)</li></ul>  |
| Data Needed          | <ul><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Trigger              | <ul><li>[T1020: Automated Exfiltration](../Triggers/T1020.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Legitimate Administrator using tools</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Daniil Yugoslavskiy, oscd.community |


## Detection Rules

### Sigma rule

```
title: Exfiltration and Tunneling Tools Execution
id: c75309a3-59f8-4a8d-9c2c-4c927ad50555
description: Execution of well known tools for data exfiltration and tunneling
status: experimental
author: Daniil Yugoslavskiy, oscd.community
date: 2019/10/24
tags:
    - attack.exfiltration
    - attack.t1020
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        NewProcessName|endswith:
            - '\plink.exe'
            - '\socat.exe'
            - '\stunnel.exe'
            - '\httptunnel.exe'
    condition: selection
falsepositives:
    - Legitimate Administrator using tools
level: medium

```





### es-qs
    
```
NewProcessName.keyword:(*\\\\plink.exe OR *\\\\socat.exe OR *\\\\stunnel.exe OR *\\\\httptunnel.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/c75309a3-59f8-4a8d-9c2c-4c927ad50555 <<EOF\n{\n  "metadata": {\n    "title": "Exfiltration and Tunneling Tools Execution",\n    "description": "Execution of well known tools for data exfiltration and tunneling",\n    "tags": [\n      "attack.exfiltration",\n      "attack.t1020"\n    ],\n    "query": "NewProcessName.keyword:(*\\\\\\\\plink.exe OR *\\\\\\\\socat.exe OR *\\\\\\\\stunnel.exe OR *\\\\\\\\httptunnel.exe)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "NewProcessName.keyword:(*\\\\\\\\plink.exe OR *\\\\\\\\socat.exe OR *\\\\\\\\stunnel.exe OR *\\\\\\\\httptunnel.exe)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Exfiltration and Tunneling Tools Execution\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
NewProcessName.keyword:(*\\\\plink.exe *\\\\socat.exe *\\\\stunnel.exe *\\\\httptunnel.exe)
```


### splunk
    
```
(NewProcessName="*\\\\plink.exe" OR NewProcessName="*\\\\socat.exe" OR NewProcessName="*\\\\stunnel.exe" OR NewProcessName="*\\\\httptunnel.exe")
```


### logpoint
    
```
(event_id="1" NewProcessName IN ["*\\\\plink.exe", "*\\\\socat.exe", "*\\\\stunnel.exe", "*\\\\httptunnel.exe"])
```


### grep
    
```
grep -P '^(?:.*.*\\plink\\.exe|.*.*\\socat\\.exe|.*.*\\stunnel\\.exe|.*.*\\httptunnel\\.exe)'
```



