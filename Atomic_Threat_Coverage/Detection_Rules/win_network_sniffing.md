| Title                | Network Sniffing                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1040: Network Sniffing](https://attack.mitre.org/techniques/T1040)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1040: Network Sniffing](../Triggers/T1040.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>Admin activity</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1040/T1040.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1040/T1040.yaml)</li></ul>  |
| Author               | Timur Zinniatullin, oscd.community |


## Detection Rules

### Sigma rule

```
title: Network Sniffing
id: ba1f7802-adc7-48b4-9ecb-81e227fddfd5
status: experimental
description: Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary
    may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.
author: Timur Zinniatullin, oscd.community
date: 2019/10/21
modified: 2019/11/04
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1040/T1040.yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection:
      - Image|endswith: '\tshark.exe'
        CommandLine|contains: '-i'
      - Image|endswith: '\windump.exe'
    condition: selection
falsepositives:
    - Admin activity
fields:
    - Image
    - CommandLine
    - User
    - LogonGuid
    - Hashes
    - ParentProcessGuid
    - ParentCommandLine
level: low
tags:
    - attack.credential_access
    - attack.discovery
    - attack.t1040

```





### es-qs
    
```
((Image.keyword:*\\\\tshark.exe AND CommandLine.keyword:*\\-i*) OR Image.keyword:*\\\\windump.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Network-Sniffing <<EOF\n{\n  "metadata": {\n    "title": "Network Sniffing",\n    "description": "Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.",\n    "tags": [\n      "attack.credential_access",\n      "attack.discovery",\n      "attack.t1040"\n    ],\n    "query": "((Image.keyword:*\\\\\\\\tshark.exe AND CommandLine.keyword:*\\\\-i*) OR Image.keyword:*\\\\\\\\windump.exe)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((Image.keyword:*\\\\\\\\tshark.exe AND CommandLine.keyword:*\\\\-i*) OR Image.keyword:*\\\\\\\\windump.exe)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Network Sniffing\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n            Image = {{_source.Image}}\\n      CommandLine = {{_source.CommandLine}}\\n             User = {{_source.User}}\\n        LogonGuid = {{_source.LogonGuid}}\\n           Hashes = {{_source.Hashes}}\\nParentProcessGuid = {{_source.ParentProcessGuid}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((Image.keyword:*\\\\tshark.exe AND CommandLine.keyword:*\\-i*) OR Image.keyword:*\\\\windump.exe)
```


### splunk
    
```
((Image="*\\\\tshark.exe" CommandLine="*-i*") OR Image="*\\\\windump.exe") | table Image,CommandLine,User,LogonGuid,Hashes,ParentProcessGuid,ParentCommandLine
```


### logpoint
    
```
(event_id="1" ((Image="*\\\\tshark.exe" CommandLine="*-i*") OR Image="*\\\\windump.exe"))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*.*\\tshark\\.exe)(?=.*.*-i.*))|.*.*\\windump\\.exe))'
```



