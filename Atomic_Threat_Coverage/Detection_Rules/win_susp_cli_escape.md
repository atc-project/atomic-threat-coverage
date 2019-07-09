| Title                | Suspicious Commandline Escape                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious process that use escape characters                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1140: Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1140: Deobfuscate/Decode Files or Information](../Triggers/T1140.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/vysecurity/status/885545634958385153](https://twitter.com/vysecurity/status/885545634958385153)</li><li>[https://twitter.com/Hexacorn/status/885553465417756673](https://twitter.com/Hexacorn/status/885553465417756673)</li><li>[https://twitter.com/Hexacorn/status/885570278637678592](https://twitter.com/Hexacorn/status/885570278637678592)</li><li>[https://www.fireeye.com/blog/threat-research/2017/06/obfuscation-in-the-wild.html](https://www.fireeye.com/blog/threat-research/2017/06/obfuscation-in-the-wild.html)</li><li>[http://www.windowsinspired.com/understanding-the-command-line-string-and-arguments-received-by-a-windows-program/](http://www.windowsinspired.com/understanding-the-command-line-string-and-arguments-received-by-a-windows-program/)</li></ul>  |
| Author               | juju4 |


## Detection Rules

### Sigma rule

```
title: Suspicious Commandline Escape
description: Detects suspicious process that use escape characters
status: experimental
references:
    - https://twitter.com/vysecurity/status/885545634958385153
    - https://twitter.com/Hexacorn/status/885553465417756673
    - https://twitter.com/Hexacorn/status/885570278637678592
    - https://www.fireeye.com/blog/threat-research/2017/06/obfuscation-in-the-wild.html
    - http://www.windowsinspired.com/understanding-the-command-line-string-and-arguments-received-by-a-windows-program/
author: juju4
modified: 2018/12/11
tags:
    - attack.defense_evasion
    - attack.t1140
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - <TAB>
            - ^h^t^t^p
            - h"t"t"p
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: low

```





### es-qs
    
```
CommandLine:("TAB" "\\^h\\^t\\^t\\^p" "h\\"t\\"t\\"p")
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Suspicious-Commandline-Escape <<EOF\n{\n  "metadata": {\n    "title": "Suspicious Commandline Escape",\n    "description": "Detects suspicious process that use escape characters",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1140"\n    ],\n    "query": "CommandLine:(\\"TAB\\" \\"\\\\^h\\\\^t\\\\^t\\\\^p\\" \\"h\\\\\\"t\\\\\\"t\\\\\\"p\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "CommandLine:(\\"TAB\\" \\"\\\\^h\\\\^t\\\\^t\\\\^p\\" \\"h\\\\\\"t\\\\\\"t\\\\\\"p\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious Commandline Escape\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine:("<TAB>" "\\^h\\^t\\^t\\^p" "h\\"t\\"t\\"p")
```


### splunk
    
```
(CommandLine="<TAB>" OR CommandLine="^h^t^t^p" OR CommandLine="h\\"t\\"t\\"p")
```


### logpoint
    
```
CommandLine IN ["<TAB>", "^h^t^t^p", "h\\"t\\"t\\"p"]
```


### grep
    
```
grep -P \'^(?:.*<TAB>|.*\\^h\\^t\\^t\\^p|.*h"t"t"p)\'
```



