| Title                    | Suspicious Desktopimgdownldr Command       |
|:-------------------------|:------------------|
| **Description**          | Detects a suspicious Microsoft desktopimgdownldr execution with parameters used to download files from the Internet |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0011: Command and Control](https://attack.mitre.org/tactics/TA0011)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1105: Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1105: Ingress Tool Transfer](../Triggers/T1105.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://labs.sentinelone.com/living-off-windows-land-a-new-native-file-downldr/](https://labs.sentinelone.com/living-off-windows-land-a-new-native-file-downldr/)</li><li>[https://twitter.com/SBousseaden/status/1278977301745741825](https://twitter.com/SBousseaden/status/1278977301745741825)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious Desktopimgdownldr Command
id: bb58aa4a-b80b-415a-a2c0-2f65a4c81009
status: experimental
description: Detects a suspicious Microsoft desktopimgdownldr execution with parameters used to download files from the Internet
author: Florian Roth
date: 2020/07/03
modified: 2020/08/30
references:
    - https://labs.sentinelone.com/living-off-windows-land-a-new-native-file-downldr/
    - https://twitter.com/SBousseaden/status/1278977301745741825
logsource:
    category: process_creation
    product: windows
tags:
    - attack.command_and_control
    - attack.t1105
detection:
    selection1:
        CommandLine|contains: ' /lockscreenurl:'
    selection1_filter:
        CommandLine|contains:
            - '.jpg'
            - '.jpeg'
            - '.png'
    selection_reg:
        CommandLine|contains|all:
            - 'reg delete'
            - '\PersonalizationCSP'
    condition: ( selection1 and not selection1_filter ) or selection_reg
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: high

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "CommandLine.*.* /lockscreenurl:.*" -and  -not (($_.message -match "CommandLine.*.*.jpg.*" -or $_.message -match "CommandLine.*.*.jpeg.*" -or $_.message -match "CommandLine.*.*.png.*"))) -or ($_.message -match "CommandLine.*.*reg delete.*" -and $_.message -match "CommandLine.*.*\\\\PersonalizationCSP.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.CommandLine.keyword:*\\ \\/lockscreenurl\\:* AND (NOT (winlog.event_data.CommandLine.keyword:(*.jpg* OR *.jpeg* OR *.png*)))) OR (winlog.event_data.CommandLine.keyword:*reg\\ delete* AND winlog.event_data.CommandLine.keyword:*\\\\PersonalizationCSP*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/bb58aa4a-b80b-415a-a2c0-2f65a4c81009 <<EOF\n{\n  "metadata": {\n    "title": "Suspicious Desktopimgdownldr Command",\n    "description": "Detects a suspicious Microsoft desktopimgdownldr execution with parameters used to download files from the Internet",\n    "tags": [\n      "attack.command_and_control",\n      "attack.t1105"\n    ],\n    "query": "((winlog.event_data.CommandLine.keyword:*\\\\ \\\\/lockscreenurl\\\\:* AND (NOT (winlog.event_data.CommandLine.keyword:(*.jpg* OR *.jpeg* OR *.png*)))) OR (winlog.event_data.CommandLine.keyword:*reg\\\\ delete* AND winlog.event_data.CommandLine.keyword:*\\\\\\\\PersonalizationCSP*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((winlog.event_data.CommandLine.keyword:*\\\\ \\\\/lockscreenurl\\\\:* AND (NOT (winlog.event_data.CommandLine.keyword:(*.jpg* OR *.jpeg* OR *.png*)))) OR (winlog.event_data.CommandLine.keyword:*reg\\\\ delete* AND winlog.event_data.CommandLine.keyword:*\\\\\\\\PersonalizationCSP*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious Desktopimgdownldr Command\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((CommandLine.keyword:* \\/lockscreenurl\\:* AND (NOT (CommandLine.keyword:(*.jpg* *.jpeg* *.png*)))) OR (CommandLine.keyword:*reg delete* AND CommandLine.keyword:*\\\\PersonalizationCSP*))
```


### splunk
    
```
((CommandLine="* /lockscreenurl:*" NOT ((CommandLine="*.jpg*" OR CommandLine="*.jpeg*" OR CommandLine="*.png*"))) OR (CommandLine="*reg delete*" CommandLine="*\\\\PersonalizationCSP*")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
((CommandLine="* /lockscreenurl:*"  -(CommandLine IN ["*.jpg*", "*.jpeg*", "*.png*"])) OR (CommandLine="*reg delete*" CommandLine="*\\\\PersonalizationCSP*"))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*.* /lockscreenurl:.*)(?=.*(?!.*(?:.*(?=.*(?:.*.*\\.jpg.*|.*.*\\.jpeg.*|.*.*\\.png.*))))))|.*(?:.*(?=.*.*reg delete.*)(?=.*.*\\PersonalizationCSP.*))))'
```



