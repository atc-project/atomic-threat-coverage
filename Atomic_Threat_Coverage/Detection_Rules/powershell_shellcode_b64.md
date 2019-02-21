| Title                | PowerShell ShellCode                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects Base64 encoded Shellcode                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0036_4104_windows_powershell_script_block](../Data_Needed/DN_0036_4104_windows_powershell_script_block.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | critical                                                                                                                                                 |
| False Positives      | <ul><li>Unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://twitter.com/cyb3rops/status/1063072865992523776](https://twitter.com/cyb3rops/status/1063072865992523776)</li></ul>                                                          |
| Author               | David Ledbetter (shellcode), Florian Roth (rule)                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: PowerShell ShellCode
status: experimental
description: Detects Base64 encoded Shellcode
references:
    - https://twitter.com/cyb3rops/status/1063072865992523776
tags:
    - attack.execution
author: David Ledbetter (shellcode), Florian Roth (rule)
date: 2018/11/17
logsource:
    product: windows
    service: powershell
    description: 'Script block logging must be enabled'
detection:
    selection:
        EventID: 4104
    keyword1: 
        - '*AAAAYInlM*'
    keyword2: 
        - '*OiCAAAAYInlM*'
        - '*OiJAAAAYInlM*'
    condition: selection and keyword1 and keyword2
falsepositives:
    - Unknown
level: critical

```




### es-qs
    
```
((EventID:"4104" AND "*AAAAYInlM*") AND ("*OiCAAAAYInlM*" OR "*OiJAAAAYInlM*"))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/PowerShell-ShellCode <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "((EventID:\\"4104\\" AND \\"*AAAAYInlM*\\") AND (\\"*OiCAAAAYInlM*\\" OR \\"*OiJAAAAYInlM*\\"))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'PowerShell ShellCode\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:"4104" AND "*AAAAYInlM*") AND ("*OiCAAAAYInlM*" OR "*OiJAAAAYInlM*"))
```


### splunk
    
```
((EventID="4104" "*AAAAYInlM*") ("*OiCAAAAYInlM*" OR "*OiJAAAAYInlM*"))
```


### logpoint
    
```
((EventID="4104" "*AAAAYInlM*") ("*OiCAAAAYInlM*" OR "*OiJAAAAYInlM*"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*4104)(?=.*.*AAAAYInlM.*)))(?=.*(?:.*(?:.*.*OiCAAAAYInlM.*|.*.*OiJAAAAYInlM.*))))'
```


