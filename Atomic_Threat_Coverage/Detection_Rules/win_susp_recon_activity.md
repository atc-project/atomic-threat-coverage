| Title                | Suspicious Reconnaissance Activity                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious command line activity on Windows systems                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1087: Account Discovery](https://attack.mitre.org/techniques/T1087)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1087: Account Discovery](../Triggers/T1087.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Inventory tool runs</li><li>Penetration tests</li><li>Administrative activity</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious Reconnaissance Activity
status: experimental
description: Detects suspicious command line activity on Windows systems
author: Florian Roth
tags:
    - attack.discovery
    - attack.t1087
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - net group "domain admins" /domain
            - net localgroup administrators
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Inventory tool runs
    - Penetration tests
    - Administrative activity
analysis:
    recommendation: Check if the user that executed the commands is suspicious (e.g. service accounts, LOCAL_SYSTEM)
level: medium

```





### es-qs
    
```
CommandLine:("net\\ group\\ \\"domain\\ admins\\"\\ \\/domain" "net\\ localgroup\\ administrators")
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Suspicious-Reconnaissance-Activity <<EOF\n{\n  "metadata": {\n    "title": "Suspicious Reconnaissance Activity",\n    "description": "Detects suspicious command line activity on Windows systems",\n    "tags": [\n      "attack.discovery",\n      "attack.t1087"\n    ],\n    "query": "CommandLine:(\\"net\\\\ group\\\\ \\\\\\"domain\\\\ admins\\\\\\"\\\\ \\\\/domain\\" \\"net\\\\ localgroup\\\\ administrators\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "CommandLine:(\\"net\\\\ group\\\\ \\\\\\"domain\\\\ admins\\\\\\"\\\\ \\\\/domain\\" \\"net\\\\ localgroup\\\\ administrators\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious Reconnaissance Activity\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine:("net group \\"domain admins\\" \\/domain" "net localgroup administrators")
```


### splunk
    
```
(CommandLine="net group \\"domain admins\\" /domain" OR CommandLine="net localgroup administrators") | table CommandLine,ParentCommandLine
```


### logpoint
    
```
CommandLine IN ["net group \\"domain admins\\" /domain", "net localgroup administrators"]
```


### grep
    
```
grep -P \'^(?:.*net group "domain admins" /domain|.*net localgroup administrators)\'
```



