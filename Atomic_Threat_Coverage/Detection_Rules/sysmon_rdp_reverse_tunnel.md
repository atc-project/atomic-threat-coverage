| Title                | RDP over Reverse SSH Tunnel                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects svchost hosting RDP termsvcs communicating with the loopback address and on TCP port 3389                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0011: Command and Control](https://attack.mitre.org/tactics/TA0011)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1076: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1076)</li></ul>  |
| Data Needed          | <ul><li>[DN_0007_3_windows_sysmon_network_connection](../Data_Needed/DN_0007_3_windows_sysmon_network_connection.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1076: Remote Desktop Protocol](../Triggers/T1076.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/SBousseaden/status/1096148422984384514](https://twitter.com/SBousseaden/status/1096148422984384514)</li></ul>  |
| Author               | Samir Bousseaden |
| Other Tags           | <ul><li>car.2013-07-002</li><li>car.2013-07-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: RDP over Reverse SSH Tunnel
status: experimental
description: Detects svchost hosting RDP termsvcs communicating with the loopback address and on TCP port 3389
references:
    - https://twitter.com/SBousseaden/status/1096148422984384514
author: Samir Bousseaden
date: 2019/02/16
tags:
    - attack.defense_evasion
    - attack.command_and_control
    - attack.t1076
    - car.2013-07-002
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 3
        Image: '*\svchost.exe'
        SourcePort: 3389 
        DestinationIp:
            - '127.*'
            - '::1'
    condition: selection
falsepositives:
    - unknown
level: high
```





### es-qs
    
```
(EventID:"3" AND Image.keyword:*\\\\svchost.exe AND SourcePort:"3389" AND DestinationIp.keyword:(127.* \\:\\:1))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/RDP-over-Reverse-SSH-Tunnel <<EOF\n{\n  "metadata": {\n    "title": "RDP over Reverse SSH Tunnel",\n    "description": "Detects svchost hosting RDP termsvcs communicating with the loopback address and on TCP port 3389",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.command_and_control",\n      "attack.t1076",\n      "car.2013-07-002"\n    ],\n    "query": "(EventID:\\"3\\" AND Image.keyword:*\\\\\\\\svchost.exe AND SourcePort:\\"3389\\" AND DestinationIp.keyword:(127.* \\\\:\\\\:1))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"3\\" AND Image.keyword:*\\\\\\\\svchost.exe AND SourcePort:\\"3389\\" AND DestinationIp.keyword:(127.* \\\\:\\\\:1))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'RDP over Reverse SSH Tunnel\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"3" AND Image:"*\\\\svchost.exe" AND SourcePort:"3389" AND DestinationIp:("127.*" "\\:\\:1"))
```


### splunk
    
```
(EventID="3" Image="*\\\\svchost.exe" SourcePort="3389" (DestinationIp="127.*" OR DestinationIp="::1"))
```


### logpoint
    
```
(EventID="3" Image="*\\\\svchost.exe" SourcePort="3389" DestinationIp IN ["127.*", "::1"])
```


### grep
    
```
grep -P '^(?:.*(?=.*3)(?=.*.*\\svchost\\.exe)(?=.*3389)(?=.*(?:.*127\\..*|.*::1)))'
```



