| Title                | Regsvr32 Network Activity                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects network connections and DNS queries initiated by Regsvr32.exe                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1117: Regsvr32](https://attack.mitre.org/techniques/T1117)</li></ul>  |
| Data Needed          | <ul><li>[DN_0007_3_windows_sysmon_network_connection](../Data_Needed/DN_0007_3_windows_sysmon_network_connection.md)</li><li>[DN_0085_22_windows_sysmon_DnsQuery](../Data_Needed/DN_0085_22_windows_sysmon_DnsQuery.md)</li></ul>  |
| Trigger              | <ul><li>[T1117: Regsvr32](../Triggers/T1117.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://pentestlab.blog/2017/05/11/applocker-bypass-regsvr32/](https://pentestlab.blog/2017/05/11/applocker-bypass-regsvr32/)</li><li>[https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/](https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/)</li><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1117/T1117.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1117/T1117.md)</li></ul>  |
| Author               | Dmitriy Lifanov, oscd.community |


## Detection Rules

### Sigma rule

```
title: Regsvr32 Network Activity
id: c7e91a02-d771-4a6d-a700-42587e0b1095
description: Detects network connections and DNS queries initiated by Regsvr32.exe
references:
    - https://pentestlab.blog/2017/05/11/applocker-bypass-regsvr32/
    - https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1117/T1117.md
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1117
author: Dmitriy Lifanov, oscd.community
status: experimental
date: 2019/10/25
modified: 2019/11/10
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID:
         - 3
         - 22
        Image|endswith: '\regsvr32.exe'
    condition: selection
fields:
    - ComputerName
    - User
    - Image
    - DestinationIp
    - DestinationPort
falsepositives:
    - unknown
level: high

```





### es-qs
    
```
(EventID:("3" OR "22") AND Image.keyword:*\\\\regsvr32.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/c7e91a02-d771-4a6d-a700-42587e0b1095 <<EOF\n{\n  "metadata": {\n    "title": "Regsvr32 Network Activity",\n    "description": "Detects network connections and DNS queries initiated by Regsvr32.exe",\n    "tags": [\n      "attack.execution",\n      "attack.defense_evasion",\n      "attack.t1117"\n    ],\n    "query": "(EventID:(\\"3\\" OR \\"22\\") AND Image.keyword:*\\\\\\\\regsvr32.exe)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:(\\"3\\" OR \\"22\\") AND Image.keyword:*\\\\\\\\regsvr32.exe)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Regsvr32 Network Activity\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n   ComputerName = {{_source.ComputerName}}\\n           User = {{_source.User}}\\n          Image = {{_source.Image}}\\n  DestinationIp = {{_source.DestinationIp}}\\nDestinationPort = {{_source.DestinationPort}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:("3" "22") AND Image.keyword:*\\\\regsvr32.exe)
```


### splunk
    
```
((EventID="3" OR EventID="22") Image="*\\\\regsvr32.exe") | table ComputerName,User,Image,DestinationIp,DestinationPort
```


### logpoint
    
```
(event_id IN ["3", "22"] Image="*\\\\regsvr32.exe")
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*3|.*22))(?=.*.*\\regsvr32\\.exe))'
```



