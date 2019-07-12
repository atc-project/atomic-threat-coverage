| Title                | Suspicious PowerShell Invocations - Specific                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious PowerShell invocation command parameters                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0036_4104_windows_powershell_script_block](../Data_Needed/DN_0036_4104_windows_powershell_script_block.md)</li><li>[DN_0037_4103_windows_powershell_executing_pipeline](../Data_Needed/DN_0037_4103_windows_powershell_executing_pipeline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Penetration tests</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth (rule) |


## Detection Rules

### Sigma rule

```
title: Suspicious PowerShell Invocations - Specific
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
    keywords:
        - ' -nop -w hidden -c * [Convert]::FromBase64String'
        - ' -w hidden -noni -nop -c "iex(New-Object'
        - ' -w hidden -ep bypass -Enc'
        - 'powershell.exe reg add HKCU\software\microsoft\windows\currentversion\run'
        - 'bypass -noprofile -windowstyle hidden (new-object system.net.webclient).download'
        - 'iex(New-Object Net.WebClient).Download'
    condition: keywords
falsepositives:
    - Penetration tests
level: high

```





### es-qs
    
```
(\\ \\-nop\\ \\-w\\ hidden\\ \\-c\\ *\\ \\[Convert\\]\\:\\:FromBase64String OR \\ \\-w\\ hidden\\ \\-noni\\ \\-nop\\ \\-c\\ \\"iex\\(New\\-Object OR \\ \\-w\\ hidden\\ \\-ep\\ bypass\\ \\-Enc OR powershell.exe\\ reg\\ add\\ HKCU\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\run OR bypass\\ \\-noprofile\\ \\-windowstyle\\ hidden\\ \\(new\\-object\\ system.net.webclient\\).download OR iex\\(New\\-Object\\ Net.WebClient\\).Download)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Suspicious-PowerShell-Invocations---Specific <<EOF\n{\n  "metadata": {\n    "title": "Suspicious PowerShell Invocations - Specific",\n    "description": "Detects suspicious PowerShell invocation command parameters",\n    "tags": [\n      "attack.execution",\n      "attack.t1086"\n    ],\n    "query": "(\\\\ \\\\-nop\\\\ \\\\-w\\\\ hidden\\\\ \\\\-c\\\\ *\\\\ \\\\[Convert\\\\]\\\\:\\\\:FromBase64String OR \\\\ \\\\-w\\\\ hidden\\\\ \\\\-noni\\\\ \\\\-nop\\\\ \\\\-c\\\\ \\\\\\"iex\\\\(New\\\\-Object OR \\\\ \\\\-w\\\\ hidden\\\\ \\\\-ep\\\\ bypass\\\\ \\\\-Enc OR powershell.exe\\\\ reg\\\\ add\\\\ HKCU\\\\\\\\software\\\\\\\\microsoft\\\\\\\\windows\\\\\\\\currentversion\\\\\\\\run OR bypass\\\\ \\\\-noprofile\\\\ \\\\-windowstyle\\\\ hidden\\\\ \\\\(new\\\\-object\\\\ system.net.webclient\\\\).download OR iex\\\\(New\\\\-Object\\\\ Net.WebClient\\\\).Download)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(\\\\ \\\\-nop\\\\ \\\\-w\\\\ hidden\\\\ \\\\-c\\\\ *\\\\ \\\\[Convert\\\\]\\\\:\\\\:FromBase64String OR \\\\ \\\\-w\\\\ hidden\\\\ \\\\-noni\\\\ \\\\-nop\\\\ \\\\-c\\\\ \\\\\\"iex\\\\(New\\\\-Object OR \\\\ \\\\-w\\\\ hidden\\\\ \\\\-ep\\\\ bypass\\\\ \\\\-Enc OR powershell.exe\\\\ reg\\\\ add\\\\ HKCU\\\\\\\\software\\\\\\\\microsoft\\\\\\\\windows\\\\\\\\currentversion\\\\\\\\run OR bypass\\\\ \\\\-noprofile\\\\ \\\\-windowstyle\\\\ hidden\\\\ \\\\(new\\\\-object\\\\ system.net.webclient\\\\).download OR iex\\\\(New\\\\-Object\\\\ Net.WebClient\\\\).Download)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious PowerShell Invocations - Specific\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(" \\-nop \\-w hidden \\-c * \\[Convert\\]\\:\\:FromBase64String" OR " \\-w hidden \\-noni \\-nop \\-c \\"iex\\(New\\-Object" OR " \\-w hidden \\-ep bypass \\-Enc" OR "powershell.exe reg add HKCU\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\run" OR "bypass \\-noprofile \\-windowstyle hidden \\(new\\-object system.net.webclient\\).download" OR "iex\\(New\\-Object Net.WebClient\\).Download")
```


### splunk
    
```
(" -nop -w hidden -c * [Convert]::FromBase64String" OR " -w hidden -noni -nop -c \\"iex(New-Object" OR " -w hidden -ep bypass -Enc" OR "powershell.exe reg add HKCU\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\run" OR "bypass -noprofile -windowstyle hidden (new-object system.net.webclient).download" OR "iex(New-Object Net.WebClient).Download")
```


### logpoint
    
```
(" -nop -w hidden -c * [Convert]::FromBase64String" OR " -w hidden -noni -nop -c \\"iex(New-Object" OR " -w hidden -ep bypass -Enc" OR "powershell.exe reg add HKCU\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\run" OR "bypass -noprofile -windowstyle hidden (new-object system.net.webclient).download" OR "iex(New-Object Net.WebClient).Download")
```


### grep
    
```
grep -P \'^(?:.*(?:.* -nop -w hidden -c .* \\[Convert\\]::FromBase64String|.* -w hidden -noni -nop -c "iex\\(New-Object|.* -w hidden -ep bypass -Enc|.*powershell\\.exe reg add HKCU\\software\\microsoft\\windows\\currentversion\\run|.*bypass -noprofile -windowstyle hidden \\(new-object system\\.net\\.webclient\\)\\.download|.*iex\\(New-Object Net\\.WebClient\\)\\.Download))\'
```



