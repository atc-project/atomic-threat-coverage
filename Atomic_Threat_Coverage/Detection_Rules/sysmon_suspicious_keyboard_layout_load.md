| Title                    | Suspicious Keyboard Layout Load       |
|:-------------------------|:------------------|
| **Description**          | Detects the keyboard preload installation with a suspicious keyboard layout, e.g. Chinese, Iranian or Vietnamese layout load in user session on systems maintained by US staff only |
| **ATT&amp;CK Tactic**    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Administrators or users that actually use the selected keyboard layouts (heavily depends on the organisation's user base)</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://renenyffenegger.ch/notes/Windows/registry/tree/HKEY_CURRENT_USER/Keyboard-Layout/Preload/index](https://renenyffenegger.ch/notes/Windows/registry/tree/HKEY_CURRENT_USER/Keyboard-Layout/Preload/index)</li><li>[https://github.com/SwiftOnSecurity/sysmon-config/pull/92/files](https://github.com/SwiftOnSecurity/sysmon-config/pull/92/files)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious Keyboard Layout Load
id: 34aa0252-6039-40ff-951f-939fd6ce47d8
description: Detects the keyboard preload installation with a suspicious keyboard layout, e.g. Chinese, Iranian or Vietnamese layout load in user session on systems
    maintained by US staff only
references:
    - https://renenyffenegger.ch/notes/Windows/registry/tree/HKEY_CURRENT_USER/Keyboard-Layout/Preload/index
    - https://github.com/SwiftOnSecurity/sysmon-config/pull/92/files
author: Florian Roth
date: 2019/10/12
modified: 2019/10/15
logsource:
    product: windows
    service: sysmon
    definition: 'Requirements: Sysmon config that monitors \Keyboard Layout\Preload subkey of the HKLU hives - see https://github.com/SwiftOnSecurity/sysmon-config/pull/92/files'
detection:
    selection_registry:
        EventID: 13
        TargetObject: 
            - '*\Keyboard Layout\Preload\*'
            - '*\Keyboard Layout\Substitutes\*'
        Details|contains:
            - 00000429  # Persian (Iran)
            - 00050429  # Persian (Iran)
            - 0000042a  # Vietnamese
    condition: selection_registry
falsepositives:
    - "Administrators or users that actually use the selected keyboard layouts (heavily depends on the organisation's user base)"
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "13" -and ($_.message -match "TargetObject.*.*\\\\Keyboard Layout\\\\Preload\\\\.*" -or $_.message -match "TargetObject.*.*\\\\Keyboard Layout\\\\Substitutes\\\\.*") -and ($_.message -match "Details.*.*00000429.*" -or $_.message -match "Details.*.*00050429.*" -or $_.message -match "Details.*.*0000042a.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\\-Windows\\-Sysmon\\/Operational" AND winlog.event_id:"13" AND winlog.event_data.TargetObject.keyword:(*\\\\Keyboard\\ Layout\\\\Preload\\* OR *\\\\Keyboard\\ Layout\\\\Substitutes\\*) AND winlog.event_data.Details.keyword:(*00000429* OR *00050429* OR *0000042a*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/34aa0252-6039-40ff-951f-939fd6ce47d8 <<EOF\n{\n  "metadata": {\n    "title": "Suspicious Keyboard Layout Load",\n    "description": "Detects the keyboard preload installation with a suspicious keyboard layout, e.g. Chinese, Iranian or Vietnamese layout load in user session on systems maintained by US staff only",\n    "tags": "",\n    "query": "(winlog.channel:\\"Microsoft\\\\-Windows\\\\-Sysmon\\\\/Operational\\" AND winlog.event_id:\\"13\\" AND winlog.event_data.TargetObject.keyword:(*\\\\\\\\Keyboard\\\\ Layout\\\\\\\\Preload\\\\* OR *\\\\\\\\Keyboard\\\\ Layout\\\\\\\\Substitutes\\\\*) AND winlog.event_data.Details.keyword:(*00000429* OR *00050429* OR *0000042a*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Microsoft\\\\-Windows\\\\-Sysmon\\\\/Operational\\" AND winlog.event_id:\\"13\\" AND winlog.event_data.TargetObject.keyword:(*\\\\\\\\Keyboard\\\\ Layout\\\\\\\\Preload\\\\* OR *\\\\\\\\Keyboard\\\\ Layout\\\\\\\\Substitutes\\\\*) AND winlog.event_data.Details.keyword:(*00000429* OR *00050429* OR *0000042a*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious Keyboard Layout Load\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"13" AND TargetObject.keyword:(*\\\\Keyboard Layout\\\\Preload\\* *\\\\Keyboard Layout\\\\Substitutes\\*) AND Details.keyword:(*00000429* *00050429* *0000042a*))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="13" (TargetObject="*\\\\Keyboard Layout\\\\Preload\\*" OR TargetObject="*\\\\Keyboard Layout\\\\Substitutes\\*") (Details="*00000429*" OR Details="*00050429*" OR Details="*0000042a*"))
```


### logpoint
    
```
(event_id="13" TargetObject IN ["*\\\\Keyboard Layout\\\\Preload\\*", "*\\\\Keyboard Layout\\\\Substitutes\\*"] Details IN ["*00000429*", "*00050429*", "*0000042a*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*13)(?=.*(?:.*.*\\Keyboard Layout\\Preload\\.*|.*.*\\Keyboard Layout\\Substitutes\\.*))(?=.*(?:.*.*00000429.*|.*.*00050429.*|.*.*0000042a.*)))'
```



