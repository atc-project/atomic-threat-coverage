| Title                | Netsh RDP Port Forwarding                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects netsh commands that configure a port forwarding of port 3389 used for RDP                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1021: Remote Services](https://attack.mitre.org/techniques/T1021)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1021: Remote Services](../Triggers/T1021.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Legitimate administration</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html](https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html)</li></ul>  |
| Author               | Florian Roth |
| Other Tags           | <ul><li>car.2013-07-002</li><li>car.2013-07-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Netsh RDP Port Forwarding
description: Detects netsh commands that configure a port forwarding of port 3389 used for RDP
references:
    - https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html
date: 2019/01/29
tags:
    - attack.lateral_movement
    - attack.t1021
    - car.2013-07-002
status: experimental
author: Florian Roth
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - netsh i* p*=3389 c*
    condition: selection
falsepositives:
    - Legitimate administration
level: high

```





### es-qs
    
```
CommandLine.keyword:(netsh\\ i*\\ p*\\=3389\\ c*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Netsh-RDP-Port-Forwarding <<EOF\n{\n  "metadata": {\n    "title": "Netsh RDP Port Forwarding",\n    "description": "Detects netsh commands that configure a port forwarding of port 3389 used for RDP",\n    "tags": [\n      "attack.lateral_movement",\n      "attack.t1021",\n      "car.2013-07-002"\n    ],\n    "query": "CommandLine.keyword:(netsh\\\\ i*\\\\ p*\\\\=3389\\\\ c*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "CommandLine.keyword:(netsh\\\\ i*\\\\ p*\\\\=3389\\\\ c*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Netsh RDP Port Forwarding\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine:("netsh i* p*=3389 c*")
```


### splunk
    
```
(CommandLine="netsh i* p*=3389 c*")
```


### logpoint
    
```
CommandLine IN ["netsh i* p*=3389 c*"]
```


### grep
    
```
grep -P '^(?:.*netsh i.* p.*=3389 c.*)'
```



