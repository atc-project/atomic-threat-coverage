| Title                    | Netsh Port or Application Allowed       |
|:-------------------------|:------------------|
| **Description**          | Allow Incoming Connections by Port or Application on Windows Firewall |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1089: Disabling Security Tools](https://attack.mitre.org/techniques/T1089)</li><li>[T1562.004: Disable or Modify System Firewall](https://attack.mitre.org/techniques/T1562.004)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1562.004: Disable or Modify System Firewall](../Triggers/T1562.004.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate administration</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://attack.mitre.org/software/S0246/ (Lazarus HARDRAIN)](https://attack.mitre.org/software/S0246/ (Lazarus HARDRAIN))</li><li>[https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-RAT-and-Staging-Report.pdf](https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-RAT-and-Staging-Report.pdf)</li></ul>  |
| **Author**               | Markus Neis, Sander Wiebing |


## Detection Rules

### Sigma rule

```
title: Netsh Port or Application Allowed
id: cd5cfd80-aa5f-44c0-9c20-108c4ae12e3c
description: Allow Incoming Connections by Port or Application on Windows Firewall
references:
    - https://attack.mitre.org/software/S0246/ (Lazarus HARDRAIN)
    - https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-RAT-and-Staging-Report.pdf
date: 2019/01/29
modified: 2020/09/01
tags:
    - attack.defense_evasion
    - attack.t1089          # an old one
    - attack.t1562.004
status: experimental
author: Markus Neis, Sander Wiebing
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine:
            - '*netsh*'
    selection2:
        CommandLine:
            - '*firewall add*'
    condition: selection1 and selection2
falsepositives:
    - Legitimate administration
level: medium

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "CommandLine.*.*netsh.*") -and ($_.message -match "CommandLine.*.*firewall add.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:(*netsh*) AND winlog.event_data.CommandLine.keyword:(*firewall\\ add*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/cd5cfd80-aa5f-44c0-9c20-108c4ae12e3c <<EOF\n{\n  "metadata": {\n    "title": "Netsh Port or Application Allowed",\n    "description": "Allow Incoming Connections by Port or Application on Windows Firewall",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1089",\n      "attack.t1562.004"\n    ],\n    "query": "(winlog.event_data.CommandLine.keyword:(*netsh*) AND winlog.event_data.CommandLine.keyword:(*firewall\\\\ add*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.CommandLine.keyword:(*netsh*) AND winlog.event_data.CommandLine.keyword:(*firewall\\\\ add*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Netsh Port or Application Allowed\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(CommandLine.keyword:(*netsh*) AND CommandLine.keyword:(*firewall add*))
```


### splunk
    
```
((CommandLine="*netsh*") (CommandLine="*firewall add*"))
```


### logpoint
    
```
(CommandLine IN ["*netsh*"] CommandLine IN ["*firewall add*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*netsh.*))(?=.*(?:.*.*firewall add.*)))'
```



