| Title                | PowerShell Credential Prompt                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects PowerShell calling a credential prompt                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0036_4104_windows_powershell_script_block](../Data_Needed/DN_0036_4104_windows_powershell_script_block.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/JohnLaTwC/status/850381440629981184](https://twitter.com/JohnLaTwC/status/850381440629981184)</li><li>[https://t.co/ezOTGy1a1G](https://t.co/ezOTGy1a1G)</li></ul>  |
| Author               | John Lambert (idea), Florian Roth (rule) |


## Detection Rules

### Sigma rule

```
title: PowerShell Credential Prompt
status: experimental
description: Detects PowerShell calling a credential prompt
references:
    - https://twitter.com/JohnLaTwC/status/850381440629981184
    - https://t.co/ezOTGy1a1G
tags:
    - attack.execution
    - attack.credential_access    
    - attack.t1086
author: John Lambert (idea), Florian Roth (rule)
logsource:
    product: windows
    service: powershell
    definition: 'Script block logging must be enabled'
detection:
    selection:
        EventID: 4104
    keyword:
        - 'PromptForCredential'
    condition: all of them
falsepositives:
    - Unknown
level: high

```





### es-qs
    
```
(EventID:"4104" AND "PromptForCredential")
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/PowerShell-Credential-Prompt <<EOF\n{\n  "metadata": {\n    "title": "PowerShell Credential Prompt",\n    "description": "Detects PowerShell calling a credential prompt",\n    "tags": [\n      "attack.execution",\n      "attack.credential_access",\n      "attack.t1086"\n    ],\n    "query": "(EventID:\\"4104\\" AND \\"PromptForCredential\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"4104\\" AND \\"PromptForCredential\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'PowerShell Credential Prompt\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"4104" AND "PromptForCredential")
```


### splunk
    
```
(EventID="4104" "PromptForCredential")
```


### logpoint
    
```
(EventID="4104" "PromptForCredential")
```


### grep
    
```
grep -P '^(?:.*(?=.*4104)(?=.*PromptForCredential))'
```



