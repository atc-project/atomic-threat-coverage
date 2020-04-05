| Title                    | Suspicious Code Page Switch       |
|:-------------------------|:------------------|
| **Description**          | Detects a code page switch in command line or batch scripts to a rare language |
| **ATT&amp;CK Tactic**    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Administrative activity (adjust code pages according to your organisation's region)</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://docs.microsoft.com/en-us/windows/win32/intl/code-page-identifiers](https://docs.microsoft.com/en-us/windows/win32/intl/code-page-identifiers)</li><li>[https://twitter.com/cglyer/status/1183756892952248325](https://twitter.com/cglyer/status/1183756892952248325)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious Code Page Switch
id: c7942406-33dd-4377-a564-0f62db0593a3
status: experimental
description: Detects a code page switch in command line or batch scripts to a rare language
author: Florian Roth
date: 2019/10/14
references:
    - https://docs.microsoft.com/en-us/windows/win32/intl/code-page-identifiers
    - https://twitter.com/cglyer/status/1183756892952248325
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: 
            - 'chcp* 936'  # Chinese
            # - 'chcp* 1256' # Arabic
            - 'chcp* 1258' # Vietnamese
            # - 'chcp* 855'  # Russian
            # - 'chcp* 866'  # Russian
            # - 'chcp* 864'  # Arabic
    condition: selection
fields:
    - ParentCommandLine
falsepositives:
    - "Administrative activity (adjust code pages according to your organisation's region)"
level: medium

```





### es-qs
    
```
CommandLine.keyword:(chcp*\\ 936 OR chcp*\\ 1258)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/c7942406-33dd-4377-a564-0f62db0593a3 <<EOF\n{\n  "metadata": {\n    "title": "Suspicious Code Page Switch",\n    "description": "Detects a code page switch in command line or batch scripts to a rare language",\n    "tags": "",\n    "query": "CommandLine.keyword:(chcp*\\\\ 936 OR chcp*\\\\ 1258)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "CommandLine.keyword:(chcp*\\\\ 936 OR chcp*\\\\ 1258)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious Code Page Switch\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine.keyword:(chcp* 936 chcp* 1258)
```


### splunk
    
```
(CommandLine="chcp* 936" OR CommandLine="chcp* 1258") | table ParentCommandLine
```


### logpoint
    
```
(event_id="1" CommandLine IN ["chcp* 936", "chcp* 1258"])
```


### grep
    
```
grep -P '^(?:.*chcp.* 936|.*chcp.* 1258)'
```



