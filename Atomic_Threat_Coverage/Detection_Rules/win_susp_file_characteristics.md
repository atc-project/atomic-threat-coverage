| Title                    | Suspicious File Characteristics Due to Missing Fields       |
|:-------------------------|:------------------|
| **Description**          | Detects Executables in the Downloads folder without FileVersion,Description,Product,Company likely created with py2exe |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1059.006: Python](https://attack.mitre.org/techniques/T1059.006)</li><li>[T1064: Scripting](https://attack.mitre.org/techniques/T1064)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://securelist.com/muddywater/88059/](https://securelist.com/muddywater/88059/)</li><li>[https://www.virustotal.com/#/file/276a765a10f98cda1a38d3a31e7483585ca3722ecad19d784441293acf1b7beb/detection](https://www.virustotal.com/#/file/276a765a10f98cda1a38d3a31e7483585ca3722ecad19d784441293acf1b7beb/detection)</li></ul>  |
| **Author**               | Markus Neis, Sander Wiebing |


## Detection Rules

### Sigma rule

```
title: Suspicious File Characteristics Due to Missing Fields
id: 9637e8a5-7131-4f7f-bdc7-2b05d8670c43
description: Detects Executables in the Downloads folder without FileVersion,Description,Product,Company likely created with py2exe
status: experimental
references:
    - https://securelist.com/muddywater/88059/
    - https://www.virustotal.com/#/file/276a765a10f98cda1a38d3a31e7483585ca3722ecad19d784441293acf1b7beb/detection
author: Markus Neis, Sander Wiebing
date: 2018/11/22
modified: 2020/05/26
tags:
    - attack.execution
    - attack.t1059.006
    - attack.defense_evasion        # an old one
    - attack.t1064      # an old one
logsource:
    product: windows
    category: process_creation
detection:
    selection1:
        Description: '\?'
        FileVersion: '\?'
    selection2:
        Description: '\?'
        Product: '\?'
    selection3:
        Description: '\?'
        Company: '\?'
    folder:
        Image: '*\Downloads\\*'
    condition: (selection1 or selection2 or selection3) and folder
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: medium

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Description.*\\?" -and ($_.message -match "FileVersion.*\\?" -or $_.message -match "Product.*\\?" -or $_.message -match "Company.*\\?") -and $_.message -match "Image.*.*\\\\Downloads\\\\.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Description:"\\?" AND (FileVersion:"\\?" OR Product:"\\?" OR Company:"\\?") AND winlog.event_data.Image.keyword:*\\\\Downloads\\\\*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/9637e8a5-7131-4f7f-bdc7-2b05d8670c43 <<EOF\n{\n  "metadata": {\n    "title": "Suspicious File Characteristics Due to Missing Fields",\n    "description": "Detects Executables in the Downloads folder without FileVersion,Description,Product,Company likely created with py2exe",\n    "tags": [\n      "attack.execution",\n      "attack.t1059.006",\n      "attack.defense_evasion",\n      "attack.t1064"\n    ],\n    "query": "(winlog.event_data.Description:\\"\\\\?\\" AND (FileVersion:\\"\\\\?\\" OR Product:\\"\\\\?\\" OR Company:\\"\\\\?\\") AND winlog.event_data.Image.keyword:*\\\\\\\\Downloads\\\\\\\\*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.Description:\\"\\\\?\\" AND (FileVersion:\\"\\\\?\\" OR Product:\\"\\\\?\\" OR Company:\\"\\\\?\\") AND winlog.event_data.Image.keyword:*\\\\\\\\Downloads\\\\\\\\*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious File Characteristics Due to Missing Fields\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Description:"\\?" AND (FileVersion:"\\?" OR Product:"\\?" OR Company:"\\?") AND Image.keyword:*\\\\Downloads\\\\*)
```


### splunk
    
```
(Description="\\?" (FileVersion="\\?" OR Product="\\?" OR Company="\\?") Image="*\\\\Downloads\\\\*") | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(Description="\\?" (FileVersion="\\?" OR Product="\\?" OR Company="\\?") Image="*\\\\Downloads\\\\*")
```


### grep
    
```
grep -P '^(?:.*(?=.*\\?)(?=.*(?:.*(?:.*\\?|.*\\?|.*\\?)))(?=.*.*\\Downloads\\\\.*))'
```



