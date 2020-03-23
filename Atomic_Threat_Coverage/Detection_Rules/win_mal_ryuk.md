| Title                | Ryuk Ransomware                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects Ryuk Ransomware command lines                                                                                                                                           |
| ATT&amp;CK Tactic    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unlikely</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://research.checkpoint.com/ryuk-ransomware-targeted-campaign-break/](https://research.checkpoint.com/ryuk-ransomware-targeted-campaign-break/)</li></ul>  |
| Author               | Vasiliy Burov |


## Detection Rules

### Sigma rule

```
title: Ryuk Ransomware
id: 0acaad27-9f02-4136-a243-c357202edd74
description: Detects Ryuk Ransomware command lines
status: experimental
references:
    - https://research.checkpoint.com/ryuk-ransomware-targeted-campaign-break/
author: Vasiliy Burov
date: 2019/08/06
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '*\net.exe stop "samss" *'
            - '*\net.exe stop "audioendpointbuilder" *'
            - '*\net.exe stop "unistoresvc_?????" *'
    condition: selection
falsepositives:
    - Unlikely
level: critical

```





### es-qs
    
```
CommandLine.keyword:(*\\\\net.exe\\ stop\\ \\"samss\\"\\ * OR *\\\\net.exe\\ stop\\ \\"audioendpointbuilder\\"\\ * OR *\\\\net.exe\\ stop\\ \\"unistoresvc_?????\\"\\ *)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/0acaad27-9f02-4136-a243-c357202edd74 <<EOF\n{\n  "metadata": {\n    "title": "Ryuk Ransomware",\n    "description": "Detects Ryuk Ransomware command lines",\n    "tags": "",\n    "query": "CommandLine.keyword:(*\\\\\\\\net.exe\\\\ stop\\\\ \\\\\\"samss\\\\\\"\\\\ * OR *\\\\\\\\net.exe\\\\ stop\\\\ \\\\\\"audioendpointbuilder\\\\\\"\\\\ * OR *\\\\\\\\net.exe\\\\ stop\\\\ \\\\\\"unistoresvc_?????\\\\\\"\\\\ *)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "CommandLine.keyword:(*\\\\\\\\net.exe\\\\ stop\\\\ \\\\\\"samss\\\\\\"\\\\ * OR *\\\\\\\\net.exe\\\\ stop\\\\ \\\\\\"audioendpointbuilder\\\\\\"\\\\ * OR *\\\\\\\\net.exe\\\\ stop\\\\ \\\\\\"unistoresvc_?????\\\\\\"\\\\ *)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Ryuk Ransomware\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine.keyword:(*\\\\net.exe stop \\"samss\\" * *\\\\net.exe stop \\"audioendpointbuilder\\" * *\\\\net.exe stop \\"unistoresvc_?????\\" *)
```


### splunk
    
```
(CommandLine="*\\\\net.exe stop \\"samss\\" *" OR CommandLine="*\\\\net.exe stop \\"audioendpointbuilder\\" *" OR CommandLine="*\\\\net.exe stop \\"unistoresvc_?????\\" *")
```


### logpoint
    
```
(event_id="1" CommandLine IN ["*\\\\net.exe stop \\"samss\\" *", "*\\\\net.exe stop \\"audioendpointbuilder\\" *", "*\\\\net.exe stop \\"unistoresvc_?????\\" *"])
```


### grep
    
```
grep -P \'^(?:.*.*\\net\\.exe stop "samss" .*|.*.*\\net\\.exe stop "audioendpointbuilder" .*|.*.*\\net\\.exe stop "unistoresvc_?????" .*)\'
```



