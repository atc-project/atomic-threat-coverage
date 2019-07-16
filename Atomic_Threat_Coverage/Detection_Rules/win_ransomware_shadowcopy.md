| Title                | Ransomware Deleting Shadow Volume Copies                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a command that deletes all local shadow volume copies as often used by Ransomware                                                                                                                                           |
| ATT&amp;CK Tactic    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | critical |
| False Positives      | <ul><li>Adminsitrative scripts - e.g. to prepare image for golden image creation</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa?environmentId=100](https://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa?environmentId=100)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Ransomware Deleting Shadow Volume Copies
status: experimental
description: Detects a command that deletes all local shadow volume copies as often used by Ransomware
references:
    - https://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa?environmentId=100
author: Florian Roth
date: 2019/06/01
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '*vssadmin delete shadows*'
            - '*wmic SHADOWCOPY DELETE*'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Adminsitrative scripts - e.g. to prepare image for golden image creation
level: critical

```





### es-qs
    
```
CommandLine.keyword:(*vssadmin\\ delete\\ shadows* *wmic\\ SHADOWCOPY\\ DELETE*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Ransomware-Deleting-Shadow-Volume-Copies <<EOF\n{\n  "metadata": {\n    "title": "Ransomware Deleting Shadow Volume Copies",\n    "description": "Detects a command that deletes all local shadow volume copies as often used by Ransomware",\n    "tags": "",\n    "query": "CommandLine.keyword:(*vssadmin\\\\ delete\\\\ shadows* *wmic\\\\ SHADOWCOPY\\\\ DELETE*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "CommandLine.keyword:(*vssadmin\\\\ delete\\\\ shadows* *wmic\\\\ SHADOWCOPY\\\\ DELETE*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Ransomware Deleting Shadow Volume Copies\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine:("*vssadmin delete shadows*" "*wmic SHADOWCOPY DELETE*")
```


### splunk
    
```
(CommandLine="*vssadmin delete shadows*" OR CommandLine="*wmic SHADOWCOPY DELETE*") | table CommandLine,ParentCommandLine
```


### logpoint
    
```
CommandLine IN ["*vssadmin delete shadows*", "*wmic SHADOWCOPY DELETE*"]
```


### grep
    
```
grep -P '^(?:.*.*vssadmin delete shadows.*|.*.*wmic SHADOWCOPY DELETE.*)'
```



