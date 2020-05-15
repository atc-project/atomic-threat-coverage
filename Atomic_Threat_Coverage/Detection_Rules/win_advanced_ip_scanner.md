| Title                    | Advanced IP Scanner       |
|:-------------------------|:------------------|
| **Description**          | Detects the use of Advanced IP Scanner. Seems to be a popular tool for ransomware groups. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1046: Network Service Scanning](https://attack.mitre.org/techniques/T1046)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1046: Network Service Scanning](../Triggers/T1046.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate administrative use</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://news.sophos.com/en-us/2019/12/09/snatch-ransomware-reboots-pcs-into-safe-mode-to-bypass-protection/](https://news.sophos.com/en-us/2019/12/09/snatch-ransomware-reboots-pcs-into-safe-mode-to-bypass-protection/)</li><li>[https://www.fireeye.com/blog/threat-research/2020/05/tactics-techniques-procedures-associated-with-maze-ransomware-incidents.html](https://www.fireeye.com/blog/threat-research/2020/05/tactics-techniques-procedures-associated-with-maze-ransomware-incidents.html)</li></ul>  |
| **Author**               | @ROxPinTeddy |


## Detection Rules

### Sigma rule

```
title: Advanced IP Scanner 
id: bef37fa2-f205-4a7b-b484-0759bfd5f86f
status: experimental
description: Detects the use of Advanced IP Scanner. Seems to be a popular tool for ransomware groups.
references:
    - https://news.sophos.com/en-us/2019/12/09/snatch-ransomware-reboots-pcs-into-safe-mode-to-bypass-protection/
    - https://www.fireeye.com/blog/threat-research/2020/05/tactics-techniques-procedures-associated-with-maze-ransomware-incidents.html
author: '@ROxPinTeddy'
date: 2020/05/12
tags:
    - attack.discovery
    - attack.t1046
logsource:
    category: process_creation
    product: windows
detection:
    selection:
       Image|contains: '\advanced_ip_scanner'
    condition: selection
falsepositives:
    - Legitimate administrative use
level: medium

```





### powershell
    
```
Get-WinEvent | where {$_.message -match "Image.*.*\\\\advanced_ip_scanner.*" } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.Image.keyword:*\\\\advanced_ip_scanner*
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/bef37fa2-f205-4a7b-b484-0759bfd5f86f <<EOF\n{\n  "metadata": {\n    "title": "Advanced IP Scanner",\n    "description": "Detects the use of Advanced IP Scanner. Seems to be a popular tool for ransomware groups.",\n    "tags": [\n      "attack.discovery",\n      "attack.t1046"\n    ],\n    "query": "winlog.event_data.Image.keyword:*\\\\\\\\advanced_ip_scanner*"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "winlog.event_data.Image.keyword:*\\\\\\\\advanced_ip_scanner*",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Advanced IP Scanner\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
Image.keyword:*\\\\advanced_ip_scanner*
```


### splunk
    
```
Image="*\\\\advanced_ip_scanner*"
```


### logpoint
    
```
Image="*\\\\advanced_ip_scanner*"
```


### grep
    
```
grep -P '^.*\\advanced_ip_scanner.*'
```



