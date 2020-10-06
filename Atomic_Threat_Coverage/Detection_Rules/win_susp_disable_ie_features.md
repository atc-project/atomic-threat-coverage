| Title                    | Disabled IE Security Features       |
|:-------------------------|:------------------|
| **Description**          | Detects command lines that indicate unwanted modifications to registry keys that disable important Internet Explorer security features |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1562.001: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001)</li><li>[T1089: Disabling Security Tools](https://attack.mitre.org/techniques/T1089)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1562.001: Disable or Modify Tools](../Triggers/T1562.001.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown, maybe some security software installer disables these features temporarily</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://unit42.paloaltonetworks.com/operation-ke3chang-resurfaces-with-new-tidepool-malware/](https://unit42.paloaltonetworks.com/operation-ke3chang-resurfaces-with-new-tidepool-malware/)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Disabled IE Security Features
id: fb50eb7a-5ab1-43ae-bcc9-091818cb8424
status: experimental
description: Detects command lines that indicate unwanted modifications to registry keys that disable important Internet Explorer security features
references:
    - https://unit42.paloaltonetworks.com/operation-ke3chang-resurfaces-with-new-tidepool-malware/
tags:
    - attack.defense_evasion
    - attack.t1562.001
    - attack.t1089      # an old one
author: Florian Roth 
date: 2020/06/19
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|contains|all:
            - ' -name IEHarden '
            - ' -value 0 '        
    selection2:
        CommandLine|contains|all:
            - ' -name DEPOff '
            - ' -value 1 '
    selection3:
        CommandLine|contains|all:
            - ' -name DisableFirstRunCustomize '
            - ' -value 2 '
    condition: 1 of them
falsepositives:
    - Unknown, maybe some security software installer disables these features temporarily
level: high

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "CommandLine.*.* -name IEHarden .*" -and $_.message -match "CommandLine.*.* -value 0 .*") -or ($_.message -match "CommandLine.*.* -name DEPOff .*" -and $_.message -match "CommandLine.*.* -value 1 .*") -or ($_.message -match "CommandLine.*.* -name DisableFirstRunCustomize .*" -and $_.message -match "CommandLine.*.* -value 2 .*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.CommandLine.keyword:*\\ \\-name\\ IEHarden\\ * AND winlog.event_data.CommandLine.keyword:*\\ \\-value\\ 0\\ *) OR (winlog.event_data.CommandLine.keyword:*\\ \\-name\\ DEPOff\\ * AND winlog.event_data.CommandLine.keyword:*\\ \\-value\\ 1\\ *) OR (winlog.event_data.CommandLine.keyword:*\\ \\-name\\ DisableFirstRunCustomize\\ * AND winlog.event_data.CommandLine.keyword:*\\ \\-value\\ 2\\ *))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/fb50eb7a-5ab1-43ae-bcc9-091818cb8424 <<EOF\n{\n  "metadata": {\n    "title": "Disabled IE Security Features",\n    "description": "Detects command lines that indicate unwanted modifications to registry keys that disable important Internet Explorer security features",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1562.001",\n      "attack.t1089"\n    ],\n    "query": "((winlog.event_data.CommandLine.keyword:*\\\\ \\\\-name\\\\ IEHarden\\\\ * AND winlog.event_data.CommandLine.keyword:*\\\\ \\\\-value\\\\ 0\\\\ *) OR (winlog.event_data.CommandLine.keyword:*\\\\ \\\\-name\\\\ DEPOff\\\\ * AND winlog.event_data.CommandLine.keyword:*\\\\ \\\\-value\\\\ 1\\\\ *) OR (winlog.event_data.CommandLine.keyword:*\\\\ \\\\-name\\\\ DisableFirstRunCustomize\\\\ * AND winlog.event_data.CommandLine.keyword:*\\\\ \\\\-value\\\\ 2\\\\ *))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((winlog.event_data.CommandLine.keyword:*\\\\ \\\\-name\\\\ IEHarden\\\\ * AND winlog.event_data.CommandLine.keyword:*\\\\ \\\\-value\\\\ 0\\\\ *) OR (winlog.event_data.CommandLine.keyword:*\\\\ \\\\-name\\\\ DEPOff\\\\ * AND winlog.event_data.CommandLine.keyword:*\\\\ \\\\-value\\\\ 1\\\\ *) OR (winlog.event_data.CommandLine.keyword:*\\\\ \\\\-name\\\\ DisableFirstRunCustomize\\\\ * AND winlog.event_data.CommandLine.keyword:*\\\\ \\\\-value\\\\ 2\\\\ *))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Disabled IE Security Features\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((CommandLine.keyword:* \\-name IEHarden * AND CommandLine.keyword:* \\-value 0 *) OR (CommandLine.keyword:* \\-name DEPOff * AND CommandLine.keyword:* \\-value 1 *) OR (CommandLine.keyword:* \\-name DisableFirstRunCustomize * AND CommandLine.keyword:* \\-value 2 *))
```


### splunk
    
```
((CommandLine="* -name IEHarden *" CommandLine="* -value 0 *") OR (CommandLine="* -name DEPOff *" CommandLine="* -value 1 *") OR (CommandLine="* -name DisableFirstRunCustomize *" CommandLine="* -value 2 *"))
```


### logpoint
    
```
((CommandLine="* -name IEHarden *" CommandLine="* -value 0 *") OR (CommandLine="* -name DEPOff *" CommandLine="* -value 1 *") OR (CommandLine="* -name DisableFirstRunCustomize *" CommandLine="* -value 2 *"))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*.* -name IEHarden .*)(?=.*.* -value 0 .*))|.*(?:.*(?=.*.* -name DEPOff .*)(?=.*.* -value 1 .*))|.*(?:.*(?=.*.* -name DisableFirstRunCustomize .*)(?=.*.* -value 2 .*))))'
```



