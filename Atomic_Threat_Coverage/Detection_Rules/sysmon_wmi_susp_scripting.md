| Title                | Suspicious Scripting in a WMI Consumer                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious scripting in WMI Event Consumers                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0023_20_windows_sysmon_WmiEvent](../Data_Needed/DN_0023_20_windows_sysmon_WmiEvent.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Administrative scripts</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://in.security/an-intro-into-abusing-and-identifying-wmi-event-subscriptions-for-persistence/](https://in.security/an-intro-into-abusing-and-identifying-wmi-event-subscriptions-for-persistence/)</li><li>[https://github.com/Neo23x0/signature-base/blob/master/yara/gen_susp_lnk_files.yar#L19](https://github.com/Neo23x0/signature-base/blob/master/yara/gen_susp_lnk_files.yar#L19)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious Scripting in a WMI Consumer
status: experimental
description: Detects suspicious scripting in WMI Event Consumers 
author: Florian Roth
references:
    - https://in.security/an-intro-into-abusing-and-identifying-wmi-event-subscriptions-for-persistence/
    - https://github.com/Neo23x0/signature-base/blob/master/yara/gen_susp_lnk_files.yar#L19
date: 2019/04/15
tags:
    - attack.t1086
    - attack.execution
logsource:
   product: windows
   service: sysmon
detection:
    selection:
        EventID: 20
        Destination:
            - '*new-object system.net.webclient).downloadstring(*'
            - '*new-object system.net.webclient).downloadfile(*'
            - '*new-object net.webclient).downloadstring(*'
            - '*new-object net.webclient).downloadfile(*'
            - '* iex(*'
            - '*WScript.shell*'
            - '* -nop *'
            - '* -noprofile *'
            - '* -decode *'
            - '* -enc *'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Administrative scripts
level: high

```





### es-qs
    
```
(EventID:"20" AND Destination.keyword:(*new\\-object\\ system.net.webclient\\).downloadstring\\(* *new\\-object\\ system.net.webclient\\).downloadfile\\(* *new\\-object\\ net.webclient\\).downloadstring\\(* *new\\-object\\ net.webclient\\).downloadfile\\(* *\\ iex\\(* *WScript.shell* *\\ \\-nop\\ * *\\ \\-noprofile\\ * *\\ \\-decode\\ * *\\ \\-enc\\ *))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Suspicious-Scripting-in-a-WMI-Consumer <<EOF\n{\n  "metadata": {\n    "title": "Suspicious Scripting in a WMI Consumer",\n    "description": "Detects suspicious scripting in WMI Event Consumers",\n    "tags": [\n      "attack.t1086",\n      "attack.execution"\n    ],\n    "query": "(EventID:\\"20\\" AND Destination.keyword:(*new\\\\-object\\\\ system.net.webclient\\\\).downloadstring\\\\(* *new\\\\-object\\\\ system.net.webclient\\\\).downloadfile\\\\(* *new\\\\-object\\\\ net.webclient\\\\).downloadstring\\\\(* *new\\\\-object\\\\ net.webclient\\\\).downloadfile\\\\(* *\\\\ iex\\\\(* *WScript.shell* *\\\\ \\\\-nop\\\\ * *\\\\ \\\\-noprofile\\\\ * *\\\\ \\\\-decode\\\\ * *\\\\ \\\\-enc\\\\ *))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"20\\" AND Destination.keyword:(*new\\\\-object\\\\ system.net.webclient\\\\).downloadstring\\\\(* *new\\\\-object\\\\ system.net.webclient\\\\).downloadfile\\\\(* *new\\\\-object\\\\ net.webclient\\\\).downloadstring\\\\(* *new\\\\-object\\\\ net.webclient\\\\).downloadfile\\\\(* *\\\\ iex\\\\(* *WScript.shell* *\\\\ \\\\-nop\\\\ * *\\\\ \\\\-noprofile\\\\ * *\\\\ \\\\-decode\\\\ * *\\\\ \\\\-enc\\\\ *))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious Scripting in a WMI Consumer\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"20" AND Destination:("*new\\-object system.net.webclient\\).downloadstring\\(*" "*new\\-object system.net.webclient\\).downloadfile\\(*" "*new\\-object net.webclient\\).downloadstring\\(*" "*new\\-object net.webclient\\).downloadfile\\(*" "* iex\\(*" "*WScript.shell*" "* \\-nop *" "* \\-noprofile *" "* \\-decode *" "* \\-enc *"))
```


### splunk
    
```
(EventID="20" (Destination="*new-object system.net.webclient).downloadstring(*" OR Destination="*new-object system.net.webclient).downloadfile(*" OR Destination="*new-object net.webclient).downloadstring(*" OR Destination="*new-object net.webclient).downloadfile(*" OR Destination="* iex(*" OR Destination="*WScript.shell*" OR Destination="* -nop *" OR Destination="* -noprofile *" OR Destination="* -decode *" OR Destination="* -enc *")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(EventID="20" Destination IN ["*new-object system.net.webclient).downloadstring(*", "*new-object system.net.webclient).downloadfile(*", "*new-object net.webclient).downloadstring(*", "*new-object net.webclient).downloadfile(*", "* iex(*", "*WScript.shell*", "* -nop *", "* -noprofile *", "* -decode *", "* -enc *"])
```


### grep
    
```
grep -P '^(?:.*(?=.*20)(?=.*(?:.*.*new-object system\\.net\\.webclient\\)\\.downloadstring\\(.*|.*.*new-object system\\.net\\.webclient\\)\\.downloadfile\\(.*|.*.*new-object net\\.webclient\\)\\.downloadstring\\(.*|.*.*new-object net\\.webclient\\)\\.downloadfile\\(.*|.*.* iex\\(.*|.*.*WScript\\.shell.*|.*.* -nop .*|.*.* -noprofile .*|.*.* -decode .*|.*.* -enc .*)))'
```



