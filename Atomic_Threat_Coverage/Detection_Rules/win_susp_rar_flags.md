| Title                    | Rar with Password or Compression Level       |
|:-------------------------|:------------------|
| **Description**          | Detects the use of rar.exe, on the command line, to create an archive with password protection or with a specific compression level. This is pretty indicative of malicious actions. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0009: Collection](https://attack.mitre.org/tactics/TA0009)</li><li>[TA0010: Exfiltration](https://attack.mitre.org/tactics/TA0010)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1560.001: Archive via Utility](https://attack.mitre.org/techniques/T1560.001)</li><li>[T1002: Data Compressed](https://attack.mitre.org/techniques/T1002)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1560.001: Archive via Utility](../Triggers/T1560.001.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate use of Winrar command line version</li><li>Other command line tools, that use these flags</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://labs.sentinelone.com/the-anatomy-of-an-apt-attack-and-cobaltstrike-beacons-encoded-configuration/](https://labs.sentinelone.com/the-anatomy-of-an-apt-attack-and-cobaltstrike-beacons-encoded-configuration/)</li></ul>  |
| **Author**               | @ROxPinTeddy |


## Detection Rules

### Sigma rule

```
title: Rar with Password or Compression Level 
id: faa48cae-6b25-4f00-a094-08947fef582f
status: experimental
description: Detects the use of rar.exe, on the command line, to create an archive with password protection or with a specific compression level. This is pretty indicative of malicious actions. 
references:
    - https://labs.sentinelone.com/the-anatomy-of-an-apt-attack-and-cobaltstrike-beacons-encoded-configuration/
author: '@ROxPinTeddy'
date: 2020/05/12
modified: 2020/08/28
tags:
    - attack.collection
    - attack.t1560.001
    - attack.exfiltration # an old one  
    - attack.t1002        # an old one  

logsource:
    category: process_creation
    product: windows
detection:
    selection:
       CommandLine|contains|all:
               - ' -hp'
               - ' -m'
    condition: selection
falsepositives:
    - Legitimate use of Winrar command line version
    - Other command line tools, that use these flags
level: medium
```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.* -hp.*" -and $_.message -match "CommandLine.*.* -m.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:*\\ \\-hp* AND winlog.event_data.CommandLine.keyword:*\\ \\-m*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/faa48cae-6b25-4f00-a094-08947fef582f <<EOF\n{\n  "metadata": {\n    "title": "Rar with Password or Compression Level",\n    "description": "Detects the use of rar.exe, on the command line, to create an archive with password protection or with a specific compression level. This is pretty indicative of malicious actions.",\n    "tags": [\n      "attack.collection",\n      "attack.t1560.001",\n      "attack.exfiltration",\n      "attack.t1002"\n    ],\n    "query": "(winlog.event_data.CommandLine.keyword:*\\\\ \\\\-hp* AND winlog.event_data.CommandLine.keyword:*\\\\ \\\\-m*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.CommandLine.keyword:*\\\\ \\\\-hp* AND winlog.event_data.CommandLine.keyword:*\\\\ \\\\-m*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Rar with Password or Compression Level\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(CommandLine.keyword:* \\-hp* AND CommandLine.keyword:* \\-m*)
```


### splunk
    
```
(CommandLine="* -hp*" CommandLine="* -m*")
```


### logpoint
    
```
(CommandLine="* -hp*" CommandLine="* -m*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.* -hp.*)(?=.*.* -m.*))'
```



