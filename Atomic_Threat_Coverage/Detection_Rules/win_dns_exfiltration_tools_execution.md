| Title                | DNS exfiltration tools execution                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Well-known DNS Exfiltration tools execution                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0010: Exfiltration](https://attack.mitre.org/tactics/TA0010)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1048: Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)</li></ul>  |
| Data Needed          | <ul><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1048: Exfiltration Over Alternative Protocol](../Triggers/T1048.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Legitimate usage of iodine or dnscat2 — DNS Exfiltration tools (unlikely)</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Daniil Yugoslavskiy, oscd.community |


## Detection Rules

### Sigma rule

```
title: DNS exfiltration tools execution
id: 98a96a5a-64a0-4c42-92c5-489da3866cb0
description: Well-known DNS Exfiltration tools execution
status: experimental
author: Daniil Yugoslavskiy, oscd.community
date: 2019/10/24
tags:
    - attack.exfiltration
    - attack.t1048
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '*\iodine.exe'
        - Image|contains: '\dnscat2'
    condition: selection
falsepositives:
    - Legitimate usage of iodine or dnscat2 — DNS Exfiltration tools (unlikely)
level: medium

```





### es-qs
    
```
(Image.keyword:*\\\\iodine.exe OR Image.keyword:*\\\\dnscat2*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/DNS-exfiltration-tools-execution <<EOF\n{\n  "metadata": {\n    "title": "DNS exfiltration tools execution",\n    "description": "Well-known DNS Exfiltration tools execution",\n    "tags": [\n      "attack.exfiltration",\n      "attack.t1048"\n    ],\n    "query": "(Image.keyword:*\\\\\\\\iodine.exe OR Image.keyword:*\\\\\\\\dnscat2*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Image.keyword:*\\\\\\\\iodine.exe OR Image.keyword:*\\\\\\\\dnscat2*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'DNS exfiltration tools execution\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:*\\\\iodine.exe OR Image.keyword:*\\\\dnscat2*)
```


### splunk
    
```
(Image="*\\\\iodine.exe" OR Image="*\\\\dnscat2*")
```


### logpoint
    
```
(event_id="1" (Image="*\\\\iodine.exe" OR Image="*\\\\dnscat2*"))
```


### grep
    
```
grep -P '^(?:.*(?:.*.*\\iodine\\.exe|.*.*\\dnscat2.*))'
```



