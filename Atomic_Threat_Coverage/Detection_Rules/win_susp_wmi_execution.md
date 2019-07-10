| Title                | Suspicious WMI execution                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects WMI executing suspicious commands                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1047: Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1047: Windows Management Instrumentation](../Triggers/T1047.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Will need to be tuned</li><li>If using Splunk, I recommend | stats count by Computer,CommandLine following for easy hunting by Computer/CommandLine.</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://digital-forensics.sans.org/blog/2010/06/04/wmic-draft/](https://digital-forensics.sans.org/blog/2010/06/04/wmic-draft/)</li><li>[https://www.hybrid-analysis.com/sample/4be06ecd234e2110bd615649fe4a6fa95403979acf889d7e45a78985eb50acf9?environmentId=1](https://www.hybrid-analysis.com/sample/4be06ecd234e2110bd615649fe4a6fa95403979acf889d7e45a78985eb50acf9?environmentId=1)</li><li>[https://blog.malwarebytes.com/threat-analysis/2016/04/rokku-ransomware/](https://blog.malwarebytes.com/threat-analysis/2016/04/rokku-ransomware/)</li></ul>  |
| Author               | Michael Haag, Florian Roth, juju4 |
| Other Tags           | <ul><li>car.2016-03-002</li><li>car.2016-03-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Suspicious WMI execution
status: experimental
description: Detects WMI executing suspicious commands
references:
    - https://digital-forensics.sans.org/blog/2010/06/04/wmic-draft/
    - https://www.hybrid-analysis.com/sample/4be06ecd234e2110bd615649fe4a6fa95403979acf889d7e45a78985eb50acf9?environmentId=1
    - https://blog.malwarebytes.com/threat-analysis/2016/04/rokku-ransomware/
author: Michael Haag, Florian Roth, juju4
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\wmic.exe'
        CommandLine:
            - '*/NODE:*process call create *'
            - '* path AntiVirusProduct get *'
            - '* path FirewallProduct get *'
            - '* shadowcopy delete *'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.execution
    - attack.t1047
    - car.2016-03-002
falsepositives:
    - Will need to be tuned
    - If using Splunk, I recommend | stats count by Computer,CommandLine following for easy hunting by Computer/CommandLine.
level: medium

```





### es-qs
    
```
(Image.keyword:(*\\\\wmic.exe) AND CommandLine.keyword:(*\\/NODE\\:*process\\ call\\ create\\ * *\\ path\\ AntiVirusProduct\\ get\\ * *\\ path\\ FirewallProduct\\ get\\ * *\\ shadowcopy\\ delete\\ *))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Suspicious-WMI-execution <<EOF\n{\n  "metadata": {\n    "title": "Suspicious WMI execution",\n    "description": "Detects WMI executing suspicious commands",\n    "tags": [\n      "attack.execution",\n      "attack.t1047",\n      "car.2016-03-002"\n    ],\n    "query": "(Image.keyword:(*\\\\\\\\wmic.exe) AND CommandLine.keyword:(*\\\\/NODE\\\\:*process\\\\ call\\\\ create\\\\ * *\\\\ path\\\\ AntiVirusProduct\\\\ get\\\\ * *\\\\ path\\\\ FirewallProduct\\\\ get\\\\ * *\\\\ shadowcopy\\\\ delete\\\\ *))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Image.keyword:(*\\\\\\\\wmic.exe) AND CommandLine.keyword:(*\\\\/NODE\\\\:*process\\\\ call\\\\ create\\\\ * *\\\\ path\\\\ AntiVirusProduct\\\\ get\\\\ * *\\\\ path\\\\ FirewallProduct\\\\ get\\\\ * *\\\\ shadowcopy\\\\ delete\\\\ *))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious WMI execution\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image:("*\\\\wmic.exe") AND CommandLine:("*\\/NODE\\:*process call create *" "* path AntiVirusProduct get *" "* path FirewallProduct get *" "* shadowcopy delete *"))
```


### splunk
    
```
((Image="*\\\\wmic.exe") (CommandLine="*/NODE:*process call create *" OR CommandLine="* path AntiVirusProduct get *" OR CommandLine="* path FirewallProduct get *" OR CommandLine="* shadowcopy delete *")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(Image IN ["*\\\\wmic.exe"] CommandLine IN ["*/NODE:*process call create *", "* path AntiVirusProduct get *", "* path FirewallProduct get *", "* shadowcopy delete *"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\\wmic\\.exe))(?=.*(?:.*.*/NODE:.*process call create .*|.*.* path AntiVirusProduct get .*|.*.* path FirewallProduct get .*|.*.* shadowcopy delete .*)))'
```



