| Title                    | DNS Tunnel Technique from MuddyWater       |
|:-------------------------|:------------------|
| **Description**          | Detecting DNS tunnel activity for Muddywater actor |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0011: Command and Control](https://attack.mitre.org/tactics/TA0011)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1071: Application Layer Protocol](https://attack.mitre.org/techniques/T1071)</li><li>[T1071.004: DNS](https://attack.mitre.org/techniques/T1071.004)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1071.004: DNS](../Triggers/T1071.004.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.virustotal.com/gui/file/5ad401c3a568bd87dd13f8a9ddc4e450ece61cd9ce4d1b23f68ce0b1f3c190b7/](https://www.virustotal.com/gui/file/5ad401c3a568bd87dd13f8a9ddc4e450ece61cd9ce4d1b23f68ce0b1f3c190b7/)</li><li>[https://www.vmray.com/analyses/5ad401c3a568/report/overview.html](https://www.vmray.com/analyses/5ad401c3a568/report/overview.html)</li></ul>  |
| **Author**               | @caliskanfurkan_ |


## Detection Rules

### Sigma rule

```
title: DNS Tunnel Technique from MuddyWater
id: 36222790-0d43-4fe8-86e4-674b27809543
description: Detecting DNS tunnel activity for Muddywater actor
author: '@caliskanfurkan_'
status: experimental
date: 2020/06/04
references:
    - https://www.virustotal.com/gui/file/5ad401c3a568bd87dd13f8a9ddc4e450ece61cd9ce4d1b23f68ce0b1f3c190b7/
    - https://www.vmray.com/analyses/5ad401c3a568/report/overview.html
tags:
    - attack.command_and_control
    - attack.t1071 # an old one
    - attack.t1071.004
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\powershell.exe'
        ParentImage|endswith:
            - '\excel.exe'
        CommandLine|contains:
            - 'DataExchange.dll'
    condition: selection
falsepositives:
    - Unknown
level: critical

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "Image.*.*\\\\powershell.exe") -and ($_.message -match "ParentImage.*.*\\\\excel.exe") -and ($_.message -match "CommandLine.*.*DataExchange.dll.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:(*\\\\powershell.exe) AND winlog.event_data.ParentImage.keyword:(*\\\\excel.exe) AND winlog.event_data.CommandLine.keyword:(*DataExchange.dll*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/36222790-0d43-4fe8-86e4-674b27809543 <<EOF\n{\n  "metadata": {\n    "title": "DNS Tunnel Technique from MuddyWater",\n    "description": "Detecting DNS tunnel activity for Muddywater actor",\n    "tags": [\n      "attack.command_and_control",\n      "attack.t1071",\n      "attack.t1071.004"\n    ],\n    "query": "(winlog.event_data.Image.keyword:(*\\\\\\\\powershell.exe) AND winlog.event_data.ParentImage.keyword:(*\\\\\\\\excel.exe) AND winlog.event_data.CommandLine.keyword:(*DataExchange.dll*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.Image.keyword:(*\\\\\\\\powershell.exe) AND winlog.event_data.ParentImage.keyword:(*\\\\\\\\excel.exe) AND winlog.event_data.CommandLine.keyword:(*DataExchange.dll*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'DNS Tunnel Technique from MuddyWater\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:(*\\\\powershell.exe) AND ParentImage.keyword:(*\\\\excel.exe) AND CommandLine.keyword:(*DataExchange.dll*))
```


### splunk
    
```
((Image="*\\\\powershell.exe") (ParentImage="*\\\\excel.exe") (CommandLine="*DataExchange.dll*"))
```


### logpoint
    
```
(Image IN ["*\\\\powershell.exe"] ParentImage IN ["*\\\\excel.exe"] CommandLine IN ["*DataExchange.dll*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\\powershell\\.exe))(?=.*(?:.*.*\\excel\\.exe))(?=.*(?:.*.*DataExchange\\.dll.*)))'
```



