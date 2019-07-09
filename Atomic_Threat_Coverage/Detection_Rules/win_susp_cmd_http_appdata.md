| Title                | Command Line Execution with suspicious URL and AppData Strings                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a suspicious command line execution that includes an URL and AppData string in the command line parameters as used by several droppers (js/vbs > powershell)                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1059: Command-Line Interface](https://attack.mitre.org/techniques/T1059)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1059: Command-Line Interface](../Triggers/T1059.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>High</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.hybrid-analysis.com/sample/3a1f01206684410dbe8f1900bbeaaa543adfcd07368ba646b499fa5274b9edf6?environmentId=100](https://www.hybrid-analysis.com/sample/3a1f01206684410dbe8f1900bbeaaa543adfcd07368ba646b499fa5274b9edf6?environmentId=100)</li><li>[https://www.hybrid-analysis.com/sample/f16c729aad5c74f19784a24257236a8bbe27f7cdc4a89806031ec7f1bebbd475?environmentId=100](https://www.hybrid-analysis.com/sample/f16c729aad5c74f19784a24257236a8bbe27f7cdc4a89806031ec7f1bebbd475?environmentId=100)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Command Line Execution with suspicious URL and AppData Strings
status: experimental
description: Detects a suspicious command line execution that includes an URL and AppData string in the command line parameters as used by several droppers (js/vbs > powershell)
references:
    - https://www.hybrid-analysis.com/sample/3a1f01206684410dbe8f1900bbeaaa543adfcd07368ba646b499fa5274b9edf6?environmentId=100
    - https://www.hybrid-analysis.com/sample/f16c729aad5c74f19784a24257236a8bbe27f7cdc4a89806031ec7f1bebbd475?environmentId=100
author: Florian Roth
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - cmd.exe /c *http://*%AppData%
            - cmd.exe /c *https://*%AppData%
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - High
level: medium

```





### es-qs
    
```
CommandLine.keyword:(cmd.exe\\ \\/c\\ *http\\:\\/\\/*%AppData% cmd.exe\\ \\/c\\ *https\\:\\/\\/*%AppData%)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Command-Line-Execution-with-suspicious-URL-and-AppData-Strings <<EOF\n{\n  "metadata": {\n    "title": "Command Line Execution with suspicious URL and AppData Strings",\n    "description": "Detects a suspicious command line execution that includes an URL and AppData string in the command line parameters as used by several droppers (js/vbs > powershell)",\n    "tags": [\n      "attack.execution",\n      "attack.t1059"\n    ],\n    "query": "CommandLine.keyword:(cmd.exe\\\\ \\\\/c\\\\ *http\\\\:\\\\/\\\\/*%AppData% cmd.exe\\\\ \\\\/c\\\\ *https\\\\:\\\\/\\\\/*%AppData%)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "CommandLine.keyword:(cmd.exe\\\\ \\\\/c\\\\ *http\\\\:\\\\/\\\\/*%AppData% cmd.exe\\\\ \\\\/c\\\\ *https\\\\:\\\\/\\\\/*%AppData%)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Command Line Execution with suspicious URL and AppData Strings\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine:("cmd.exe \\/c *http\\:\\/\\/*%AppData%" "cmd.exe \\/c *https\\:\\/\\/*%AppData%")
```


### splunk
    
```
(CommandLine="cmd.exe /c *http://*%AppData%" OR CommandLine="cmd.exe /c *https://*%AppData%") | table CommandLine,ParentCommandLine
```


### logpoint
    
```
CommandLine IN ["cmd.exe /c *http://*%AppData%", "cmd.exe /c *https://*%AppData%"]
```


### grep
    
```
grep -P '^(?:.*cmd\\.exe /c .*http://.*%AppData%|.*cmd\\.exe /c .*https://.*%AppData%)'
```



