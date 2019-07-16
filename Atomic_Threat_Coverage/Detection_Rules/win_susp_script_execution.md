| Title                | WSF/JSE/JS/VBA/VBE File Execution                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious file execution by wscript and cscript                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1064: Scripting](https://attack.mitre.org/techniques/T1064)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1064: Scripting](../Triggers/T1064.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Will need to be tuned. I recommend adding the user profile path in CommandLine if it is getting too noisy.</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Michael Haag |


## Detection Rules

### Sigma rule

```
title: WSF/JSE/JS/VBA/VBE File Execution
status: experimental
description: Detects suspicious file execution by wscript and cscript
author: Michael Haag
tags:
    - attack.execution
    - attack.t1064
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\wscript.exe'
            - '*\cscript.exe'
        CommandLine:
            - '*.jse'
            - '*.vbe'
            - '*.js'
            - '*.vba'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Will need to be tuned. I recommend adding the user profile path in CommandLine if it is getting too noisy.
level: medium

```





### es-qs
    
```
(Image.keyword:(*\\\\wscript.exe *\\\\cscript.exe) AND CommandLine.keyword:(*.jse *.vbe *.js *.vba))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/WSF/JSE/JS/VBA/VBE-File-Execution <<EOF\n{\n  "metadata": {\n    "title": "WSF/JSE/JS/VBA/VBE File Execution",\n    "description": "Detects suspicious file execution by wscript and cscript",\n    "tags": [\n      "attack.execution",\n      "attack.t1064"\n    ],\n    "query": "(Image.keyword:(*\\\\\\\\wscript.exe *\\\\\\\\cscript.exe) AND CommandLine.keyword:(*.jse *.vbe *.js *.vba))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Image.keyword:(*\\\\\\\\wscript.exe *\\\\\\\\cscript.exe) AND CommandLine.keyword:(*.jse *.vbe *.js *.vba))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'WSF/JSE/JS/VBA/VBE File Execution\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image:("*\\\\wscript.exe" "*\\\\cscript.exe") AND CommandLine:("*.jse" "*.vbe" "*.js" "*.vba"))
```


### splunk
    
```
((Image="*\\\\wscript.exe" OR Image="*\\\\cscript.exe") (CommandLine="*.jse" OR CommandLine="*.vbe" OR CommandLine="*.js" OR CommandLine="*.vba")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(Image IN ["*\\\\wscript.exe", "*\\\\cscript.exe"] CommandLine IN ["*.jse", "*.vbe", "*.js", "*.vba"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\\wscript\\.exe|.*.*\\cscript\\.exe))(?=.*(?:.*.*\\.jse|.*.*\\.vbe|.*.*\\.js|.*.*\\.vba)))'
```



