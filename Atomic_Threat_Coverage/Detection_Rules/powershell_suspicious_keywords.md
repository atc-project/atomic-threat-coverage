| Title                | Suspicious PowerShell Keywords                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects keywords that could indicate the use of some PowerShell exploitation framework                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0036_4104_windows_powershell_script_block](../Data_Needed/DN_0036_4104_windows_powershell_script_block.md)</li><li>[DN_0037_4103_windows_powershell_executing_pipeline](../Data_Needed/DN_0037_4103_windows_powershell_executing_pipeline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Penetration tests</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://posts.specterops.io/entering-a-covenant-net-command-and-control-e11038bcf462](https://posts.specterops.io/entering-a-covenant-net-command-and-control-e11038bcf462)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious PowerShell Keywords
status: experimental
description: Detects keywords that could indicate the use of some PowerShell exploitation framework
date: 2019/02/11
author: Florian Roth
references:
    - https://posts.specterops.io/entering-a-covenant-net-command-and-control-e11038bcf462
tags:
    - attack.execution
    - attack.t1086
logsource:
    product: windows
    service: powershell
    definition: 'It is recommended to use the new "Script Block Logging" of PowerShell v5 https://adsecurity.org/?p=2277'
detection:
    keywords:
        - System.Reflection.Assembly.Load
    condition: keywords
falsepositives:
    - Penetration tests
level: high

```





### es-qs
    
```
System.Reflection.Assembly.Load
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Suspicious-PowerShell-Keywords <<EOF\n{\n  "metadata": {\n    "title": "Suspicious PowerShell Keywords",\n    "description": "Detects keywords that could indicate the use of some PowerShell exploitation framework",\n    "tags": [\n      "attack.execution",\n      "attack.t1086"\n    ],\n    "query": "System.Reflection.Assembly.Load"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "System.Reflection.Assembly.Load",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious PowerShell Keywords\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
"System.Reflection.Assembly.Load"
```


### splunk
    
```
"System.Reflection.Assembly.Load"
```


### logpoint
    
```
"System.Reflection.Assembly.Load"
```


### grep
    
```
grep -P '^System\\.Reflection\\.Assembly\\.Load'
```



