| Title                | Run PowerShell script from ADS                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects PowerShell script execution from Alternate Data Stream (ADS)                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1096: NTFS File Attributes](https://attack.mitre.org/techniques/T1096)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Trigger              | <ul><li>[T1096: NTFS File Attributes](../Triggers/T1096.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/p0shkatz/Get-ADS/blob/master/Get-ADS.ps1](https://github.com/p0shkatz/Get-ADS/blob/master/Get-ADS.ps1)</li></ul>  |
| Author               | Sergey Soldatov, Kaspersky Lab, oscd.community |


## Detection Rules

### Sigma rule

```
title: Run PowerShell script from ADS
id: 45a594aa-1fbd-4972-a809-ff5a99dd81b8
status: experimental
description: Detects PowerShell script execution from Alternate Data Stream (ADS)
references:
    - https://github.com/p0shkatz/Get-ADS/blob/master/Get-ADS.ps1
author: Sergey Soldatov, Kaspersky Lab, oscd.community
date: 2019/10/30
tags:
    - attack.defense_evasion
    - attack.t1096
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\powershell.exe'
        Image|endswith: '\powershell.exe'
        CommandLine|contains|all: 
          - 'Get-Content'
          - '-Stream'
    condition: selection
falsepositives:
    - Unknown
level: high

```





### es-qs
    
```
(ParentImage.keyword:*\\\\powershell.exe AND Image.keyword:*\\\\powershell.exe AND CommandLine.keyword:*Get\\-Content* AND CommandLine.keyword:*\\-Stream*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Run-PowerShell-script-from-ADS <<EOF\n{\n  "metadata": {\n    "title": "Run PowerShell script from ADS",\n    "description": "Detects PowerShell script execution from Alternate Data Stream (ADS)",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1096"\n    ],\n    "query": "(ParentImage.keyword:*\\\\\\\\powershell.exe AND Image.keyword:*\\\\\\\\powershell.exe AND CommandLine.keyword:*Get\\\\-Content* AND CommandLine.keyword:*\\\\-Stream*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(ParentImage.keyword:*\\\\\\\\powershell.exe AND Image.keyword:*\\\\\\\\powershell.exe AND CommandLine.keyword:*Get\\\\-Content* AND CommandLine.keyword:*\\\\-Stream*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Run PowerShell script from ADS\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(ParentImage.keyword:*\\\\powershell.exe AND Image.keyword:*\\\\powershell.exe AND CommandLine.keyword:*Get\\-Content* AND CommandLine.keyword:*\\-Stream*)
```


### splunk
    
```
(ParentImage="*\\\\powershell.exe" Image="*\\\\powershell.exe" CommandLine="*Get-Content*" CommandLine="*-Stream*")
```


### logpoint
    
```
(event_id="1" ParentImage="*\\\\powershell.exe" Image="*\\\\powershell.exe" CommandLine="*Get-Content*" CommandLine="*-Stream*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\powershell\\.exe)(?=.*.*\\powershell\\.exe)(?=.*.*Get-Content.*)(?=.*.*-Stream.*))'
```



