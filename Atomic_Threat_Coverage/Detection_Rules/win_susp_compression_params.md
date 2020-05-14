| Title                    | Suspicious Compression Tool Parameters       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious command line arguments of common data compression tools |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0010: Exfiltration](https://attack.mitre.org/tactics/TA0010)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1020: Automated Exfiltration](https://attack.mitre.org/techniques/T1020)</li><li>[T1002: Data Compressed](https://attack.mitre.org/techniques/T1002)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1002: Data Compressed](../Triggers/T1002.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/SBousseaden/status/1184067445612535811](https://twitter.com/SBousseaden/status/1184067445612535811)</li></ul>  |
| **Author**               | Florian Roth, Samir Bousseaden |


## Detection Rules

### Sigma rule

```
title: Suspicious Compression Tool Parameters
id: 27a72a60-7e5e-47b1-9d17-909c9abafdcd
status: experimental
description: Detects suspicious command line arguments of common data compression tools
references:
    - https://twitter.com/SBousseaden/status/1184067445612535811
tags:
    - attack.exfiltration
    - attack.t1020
    - attack.t1002
author: Florian Roth, Samir Bousseaden
date: 2019/10/15
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName:
            - '7z*.exe'
            - '*rar.exe'
            - '*Command*Line*RAR*'
        CommandLine:
            - '* -p*'
            - '* -ta*'
            - '* -tb*'
            - '* -sdel*'
            - '* -dw*'
            - '* -hp*'
    falsepositive:
        ParentImage: 'C:\Program*'
    condition: selection and not falsepositive
falsepositives:
    - unknown
level: high

```





### es-qs
    
```
((OriginalFileName.keyword:(7z*.exe OR *rar.exe OR *Command*Line*RAR*) AND CommandLine.keyword:(*\\ \\-p* OR *\\ \\-ta* OR *\\ \\-tb* OR *\\ \\-sdel* OR *\\ \\-dw* OR *\\ \\-hp*)) AND (NOT (ParentImage.keyword:C\\:\\\\Program*)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/27a72a60-7e5e-47b1-9d17-909c9abafdcd <<EOF\n{\n  "metadata": {\n    "title": "Suspicious Compression Tool Parameters",\n    "description": "Detects suspicious command line arguments of common data compression tools",\n    "tags": [\n      "attack.exfiltration",\n      "attack.t1020",\n      "attack.t1002"\n    ],\n    "query": "((OriginalFileName.keyword:(7z*.exe OR *rar.exe OR *Command*Line*RAR*) AND CommandLine.keyword:(*\\\\ \\\\-p* OR *\\\\ \\\\-ta* OR *\\\\ \\\\-tb* OR *\\\\ \\\\-sdel* OR *\\\\ \\\\-dw* OR *\\\\ \\\\-hp*)) AND (NOT (ParentImage.keyword:C\\\\:\\\\\\\\Program*)))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((OriginalFileName.keyword:(7z*.exe OR *rar.exe OR *Command*Line*RAR*) AND CommandLine.keyword:(*\\\\ \\\\-p* OR *\\\\ \\\\-ta* OR *\\\\ \\\\-tb* OR *\\\\ \\\\-sdel* OR *\\\\ \\\\-dw* OR *\\\\ \\\\-hp*)) AND (NOT (ParentImage.keyword:C\\\\:\\\\\\\\Program*)))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious Compression Tool Parameters\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((OriginalFileName.keyword:(7z*.exe *rar.exe *Command*Line*RAR*) AND CommandLine.keyword:(* \\-p* * \\-ta* * \\-tb* * \\-sdel* * \\-dw* * \\-hp*)) AND (NOT (ParentImage.keyword:C\\:\\\\Program*)))
```


### splunk
    
```
(((OriginalFileName="7z*.exe" OR OriginalFileName="*rar.exe" OR OriginalFileName="*Command*Line*RAR*") (CommandLine="* -p*" OR CommandLine="* -ta*" OR CommandLine="* -tb*" OR CommandLine="* -sdel*" OR CommandLine="* -dw*" OR CommandLine="* -hp*")) NOT (ParentImage="C:\\\\Program*"))
```


### logpoint
    
```
(event_id="1" (OriginalFileName IN ["7z*.exe", "*rar.exe", "*Command*Line*RAR*"] CommandLine IN ["* -p*", "* -ta*", "* -tb*", "* -sdel*", "* -dw*", "* -hp*"])  -(ParentImage="C:\\\\Program*"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*(?:.*7z.*\\.exe|.*.*rar\\.exe|.*.*Command.*Line.*RAR.*))(?=.*(?:.*.* -p.*|.*.* -ta.*|.*.* -tb.*|.*.* -sdel.*|.*.* -dw.*|.*.* -hp.*))))(?=.*(?!.*(?:.*(?=.*C:\\Program.*)))))'
```



