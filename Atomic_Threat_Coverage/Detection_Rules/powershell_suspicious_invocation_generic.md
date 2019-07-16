| Title                | Suspicious PowerShell Invocations - Generic                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious PowerShell invocation command parameters                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0036_4104_windows_powershell_script_block](../Data_Needed/DN_0036_4104_windows_powershell_script_block.md)</li><li>[DN_0037_4103_windows_powershell_executing_pipeline](../Data_Needed/DN_0037_4103_windows_powershell_executing_pipeline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Penetration tests</li><li>Very special / sneaky PowerShell scripts</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth (rule) |


## Detection Rules

### Sigma rule

```
title: Suspicious PowerShell Invocations - Generic
status: experimental
description: Detects suspicious PowerShell invocation command parameters
tags:
    - attack.execution
    - attack.t1086
author: Florian Roth (rule)
logsource:
    product: windows
    service: powershell
detection:
    encoded:
        - ' -enc '
        - ' -EncodedCommand '
    hidden:
        - ' -w hidden '
        - ' -window hidden '
        - ' - windowstyle hidden '
    noninteractive:
        - ' -noni '
        - ' -noninteractive '
    condition: all of them
falsepositives:
    - Penetration tests
    - Very special / sneaky PowerShell scripts
level: high


```





### es-qs
    
```
((\\ \\-enc\\  OR \\ \\-EncodedCommand\\ ) AND (\\ \\-w\\ hidden\\  OR \\ \\-window\\ hidden\\  OR \\ \\-\\ windowstyle\\ hidden\\ ) AND (\\ \\-noni\\  OR \\ \\-noninteractive\\ ))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Suspicious-PowerShell-Invocations---Generic <<EOF\n{\n  "metadata": {\n    "title": "Suspicious PowerShell Invocations - Generic",\n    "description": "Detects suspicious PowerShell invocation command parameters",\n    "tags": [\n      "attack.execution",\n      "attack.t1086"\n    ],\n    "query": "((\\\\ \\\\-enc\\\\  OR \\\\ \\\\-EncodedCommand\\\\ ) AND (\\\\ \\\\-w\\\\ hidden\\\\  OR \\\\ \\\\-window\\\\ hidden\\\\  OR \\\\ \\\\-\\\\ windowstyle\\\\ hidden\\\\ ) AND (\\\\ \\\\-noni\\\\  OR \\\\ \\\\-noninteractive\\\\ ))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((\\\\ \\\\-enc\\\\  OR \\\\ \\\\-EncodedCommand\\\\ ) AND (\\\\ \\\\-w\\\\ hidden\\\\  OR \\\\ \\\\-window\\\\ hidden\\\\  OR \\\\ \\\\-\\\\ windowstyle\\\\ hidden\\\\ ) AND (\\\\ \\\\-noni\\\\  OR \\\\ \\\\-noninteractive\\\\ ))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious PowerShell Invocations - Generic\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((" \\-enc " OR " \\-EncodedCommand ") AND (" \\-w hidden " OR " \\-window hidden " OR " \\- windowstyle hidden ") AND (" \\-noni " OR " \\-noninteractive "))
```


### splunk
    
```
((" -enc " OR " -EncodedCommand ") (" -w hidden " OR " -window hidden " OR " - windowstyle hidden ") (" -noni " OR " -noninteractive "))
```


### logpoint
    
```
((" -enc " OR " -EncodedCommand ") (" -w hidden " OR " -window hidden " OR " - windowstyle hidden ") (" -noni " OR " -noninteractive "))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?:.* -enc |.* -EncodedCommand )))(?=.*(?:.*(?:.* -w hidden |.* -window hidden |.* - windowstyle hidden )))(?=.*(?:.*(?:.* -noni |.* -noninteractive ))))'
```



