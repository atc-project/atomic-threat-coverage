| Title                | Net.exe Execution                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects execution of Net.exe, whether suspicious or benign.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | low |
| False Positives      | <ul><li>Will need to be tuned. If using Splunk, I recommend | stats count by Computer,CommandLine following the search for easy hunting by computer/CommandLine.</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)</li></ul>  |
| Author               | Michael Haag, Mark Woan (improvements) |
| Other Tags           | <ul><li>attack.s0039</li><li>attack.s0039</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Net.exe Execution
status: experimental
description: Detects execution of Net.exe, whether suspicious or benign.
references:
    - https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/
author: Michael Haag, Mark Woan (improvements)
tags:
    - attack.s0039
    - attack.lateral_movement
    - attack.discovery
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\net.exe'
            - '*\net1.exe'
        CommandLine:
            - '* group*'
            - '* localgroup*'
            - '* user*'
            - '* view*'
            - '* share'
            - '* accounts*'
            - '* use*'
            - '* stop *'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Will need to be tuned. If using Splunk, I recommend | stats count by Computer,CommandLine following the search for easy hunting by computer/CommandLine.
level: low

```





### es-qs
    
```
(Image.keyword:(*\\\\net.exe *\\\\net1.exe) AND CommandLine.keyword:(*\\ group* *\\ localgroup* *\\ user* *\\ view* *\\ share *\\ accounts* *\\ use* *\\ stop\\ *))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Net.exe-Execution <<EOF\n{\n  "metadata": {\n    "title": "Net.exe Execution",\n    "description": "Detects execution of Net.exe, whether suspicious or benign.",\n    "tags": [\n      "attack.s0039",\n      "attack.lateral_movement",\n      "attack.discovery"\n    ],\n    "query": "(Image.keyword:(*\\\\\\\\net.exe *\\\\\\\\net1.exe) AND CommandLine.keyword:(*\\\\ group* *\\\\ localgroup* *\\\\ user* *\\\\ view* *\\\\ share *\\\\ accounts* *\\\\ use* *\\\\ stop\\\\ *))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Image.keyword:(*\\\\\\\\net.exe *\\\\\\\\net1.exe) AND CommandLine.keyword:(*\\\\ group* *\\\\ localgroup* *\\\\ user* *\\\\ view* *\\\\ share *\\\\ accounts* *\\\\ use* *\\\\ stop\\\\ *))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Net.exe Execution\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image:("*\\\\net.exe" "*\\\\net1.exe") AND CommandLine:("* group*" "* localgroup*" "* user*" "* view*" "* share" "* accounts*" "* use*" "* stop *"))
```


### splunk
    
```
((Image="*\\\\net.exe" OR Image="*\\\\net1.exe") (CommandLine="* group*" OR CommandLine="* localgroup*" OR CommandLine="* user*" OR CommandLine="* view*" OR CommandLine="* share" OR CommandLine="* accounts*" OR CommandLine="* use*" OR CommandLine="* stop *")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(Image IN ["*\\\\net.exe", "*\\\\net1.exe"] CommandLine IN ["* group*", "* localgroup*", "* user*", "* view*", "* share", "* accounts*", "* use*", "* stop *"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\\net\\.exe|.*.*\\net1\\.exe))(?=.*(?:.*.* group.*|.*.* localgroup.*|.*.* user.*|.*.* view.*|.*.* share|.*.* accounts.*|.*.* use.*|.*.* stop .*)))'
```



