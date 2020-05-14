| Title                    | PowerShell Create Local User       |
|:-------------------------|:------------------|
| **Description**          | Detects creation of a local user via PowerShell |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li><li>[T1136: Create Account](https://attack.mitre.org/techniques/T1136)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0036_4104_windows_powershell_script_block](../Data_Needed/DN_0036_4104_windows_powershell_script_block.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li><li>[T1136: Create Account](../Triggers/T1136.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate user creation</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136/T1136.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136/T1136.md)</li></ul>  |
| **Author**               | @ROxPinTeddy |


## Detection Rules

### Sigma rule

```
title: PowerShell Create Local User
id: 243de76f-4725-4f2e-8225-a8a69b15ad61
status: experimental 
description: Detects creation of a local user via PowerShell
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136/T1136.md
tags:
    - attack.execution
    - attack.t1086
    - attack.persistence
    - attack.t1136
author: '@ROxPinTeddy' 
date: 2020/04/11 
logsource:
    product: windows
    service: powershell
detection:
    selection:
        EventID: 4104
        Message|contains:
            - 'New-LocalUser'
    condition: selection 
falsepositives:
    - Legitimate user creation 
level: medium

```





### es-qs
    
```
(EventID:"4104" AND Message.keyword:(*New\\-LocalUser*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/243de76f-4725-4f2e-8225-a8a69b15ad61 <<EOF\n{\n  "metadata": {\n    "title": "PowerShell Create Local User",\n    "description": "Detects creation of a local user via PowerShell",\n    "tags": [\n      "attack.execution",\n      "attack.t1086",\n      "attack.persistence",\n      "attack.t1136"\n    ],\n    "query": "(EventID:\\"4104\\" AND Message.keyword:(*New\\\\-LocalUser*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"4104\\" AND Message.keyword:(*New\\\\-LocalUser*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'PowerShell Create Local User\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"4104" AND Message.keyword:(*New\\-LocalUser*))
```


### splunk
    
```
(EventID="4104" (Message="*New-LocalUser*"))
```


### logpoint
    
```
(event_id="4104" Message IN ["*New-LocalUser*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*4104)(?=.*(?:.*.*New-LocalUser.*)))'
```



