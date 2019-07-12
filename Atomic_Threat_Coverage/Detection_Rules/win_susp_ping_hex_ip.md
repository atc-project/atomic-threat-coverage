| Title                | Ping Hex IP                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a ping command that uses a hex encoded IP address                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1140: Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140)</li><li>[T1027: Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1140: Deobfuscate/Decode Files or Information](../Triggers/T1140.md)</li><li>[T1027: Obfuscated Files or Information](../Triggers/T1027.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unlikely, because no sane admin pings IP addresses in a hexadecimal form</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://github.com/vysec/Aggressor-VYSEC/blob/master/ping.cna](https://github.com/vysec/Aggressor-VYSEC/blob/master/ping.cna)</li><li>[https://twitter.com/vysecurity/status/977198418354491392](https://twitter.com/vysecurity/status/977198418354491392)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Ping Hex IP
description: Detects a ping command that uses a hex encoded IP address
references:
    - https://github.com/vysec/Aggressor-VYSEC/blob/master/ping.cna
    - https://twitter.com/vysecurity/status/977198418354491392
author: Florian Roth
date: 2018/03/23
tags:
    - attack.defense_evasion
    - attack.t1140
    - attack.t1027
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '*\ping.exe 0x*'
            - '*\ping 0x*'
    condition: selection
fields:
    - ParentCommandLine
falsepositives:
    - Unlikely, because no sane admin pings IP addresses in a hexadecimal form
level: high

```





### es-qs
    
```
CommandLine.keyword:(*\\\\ping.exe\\ 0x* *\\\\ping\\ 0x*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Ping-Hex-IP <<EOF\n{\n  "metadata": {\n    "title": "Ping Hex IP",\n    "description": "Detects a ping command that uses a hex encoded IP address",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1140",\n      "attack.t1027"\n    ],\n    "query": "CommandLine.keyword:(*\\\\\\\\ping.exe\\\\ 0x* *\\\\\\\\ping\\\\ 0x*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "CommandLine.keyword:(*\\\\\\\\ping.exe\\\\ 0x* *\\\\\\\\ping\\\\ 0x*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Ping Hex IP\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine:("*\\\\ping.exe 0x*" "*\\\\ping 0x*")
```


### splunk
    
```
(CommandLine="*\\\\ping.exe 0x*" OR CommandLine="*\\\\ping 0x*") | table ParentCommandLine
```


### logpoint
    
```
CommandLine IN ["*\\\\ping.exe 0x*", "*\\\\ping 0x*"]
```


### grep
    
```
grep -P '^(?:.*.*\\ping\\.exe 0x.*|.*.*\\ping 0x.*)'
```



