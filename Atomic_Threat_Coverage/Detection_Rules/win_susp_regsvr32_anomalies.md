| Title                | Regsvr32 Anomaly                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects various anomalies in relation to regsvr32.exe                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1117: Regsvr32](https://attack.mitre.org/techniques/T1117)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1117: Regsvr32](../Triggers/T1117.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://subt0x10.blogspot.de/2017/04/bypass-application-whitelisting-script.html](https://subt0x10.blogspot.de/2017/04/bypass-application-whitelisting-script.html)</li></ul>  |
| Author               | Florian Roth |
| Other Tags           | <ul><li>car.2019-04-002</li><li>car.2019-04-002</li><li>car.2019-04-003</li><li>car.2019-04-003</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Regsvr32 Anomaly
status: experimental
description: Detects various anomalies in relation to regsvr32.exe
author: Florian Roth
references:
    - https://subt0x10.blogspot.de/2017/04/bypass-application-whitelisting-script.html
tags:
    - attack.t1117
    - attack.defense_evasion
    - attack.execution
    - car.2019-04-002
    - car.2019-04-003
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Image: '*\regsvr32.exe'
        CommandLine: '*\Temp\\*'
    selection2:
        Image: '*\regsvr32.exe'
        ParentImage: '*\powershell.exe'
    selection3:
        Image: '*\regsvr32.exe'
        CommandLine:
            - '*/i:http* scrobj.dll'
            - '*/i:ftp* scrobj.dll'
    selection4:
        Image: '*\wscript.exe'
        ParentImage: '*\regsvr32.exe'
    selection5:
        Image: '*\EXCEL.EXE'
        CommandLine: '*..\..\..\Windows\System32\regsvr32.exe *'
    condition: 1 of them
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: high

```





### es-qs
    
```
((Image.keyword:*\\\\regsvr32.exe AND CommandLine.keyword:*\\\\Temp\\\\*) OR (Image.keyword:*\\\\regsvr32.exe AND ParentImage.keyword:*\\\\powershell.exe) OR (Image.keyword:*\\\\regsvr32.exe AND CommandLine.keyword:(*\\/i\\:http*\\ scrobj.dll *\\/i\\:ftp*\\ scrobj.dll)) OR (Image.keyword:*\\\\wscript.exe AND ParentImage.keyword:*\\\\regsvr32.exe) OR (Image.keyword:*\\\\EXCEL.EXE AND CommandLine.keyword:*..\\\\..\\\\..\\\\Windows\\\\System32\\\\regsvr32.exe\\ *))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Regsvr32-Anomaly <<EOF\n{\n  "metadata": {\n    "title": "Regsvr32 Anomaly",\n    "description": "Detects various anomalies in relation to regsvr32.exe",\n    "tags": [\n      "attack.t1117",\n      "attack.defense_evasion",\n      "attack.execution",\n      "car.2019-04-002",\n      "car.2019-04-003"\n    ],\n    "query": "((Image.keyword:*\\\\\\\\regsvr32.exe AND CommandLine.keyword:*\\\\\\\\Temp\\\\\\\\*) OR (Image.keyword:*\\\\\\\\regsvr32.exe AND ParentImage.keyword:*\\\\\\\\powershell.exe) OR (Image.keyword:*\\\\\\\\regsvr32.exe AND CommandLine.keyword:(*\\\\/i\\\\:http*\\\\ scrobj.dll *\\\\/i\\\\:ftp*\\\\ scrobj.dll)) OR (Image.keyword:*\\\\\\\\wscript.exe AND ParentImage.keyword:*\\\\\\\\regsvr32.exe) OR (Image.keyword:*\\\\\\\\EXCEL.EXE AND CommandLine.keyword:*..\\\\\\\\..\\\\\\\\..\\\\\\\\Windows\\\\\\\\System32\\\\\\\\regsvr32.exe\\\\ *))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((Image.keyword:*\\\\\\\\regsvr32.exe AND CommandLine.keyword:*\\\\\\\\Temp\\\\\\\\*) OR (Image.keyword:*\\\\\\\\regsvr32.exe AND ParentImage.keyword:*\\\\\\\\powershell.exe) OR (Image.keyword:*\\\\\\\\regsvr32.exe AND CommandLine.keyword:(*\\\\/i\\\\:http*\\\\ scrobj.dll *\\\\/i\\\\:ftp*\\\\ scrobj.dll)) OR (Image.keyword:*\\\\\\\\wscript.exe AND ParentImage.keyword:*\\\\\\\\regsvr32.exe) OR (Image.keyword:*\\\\\\\\EXCEL.EXE AND CommandLine.keyword:*..\\\\\\\\..\\\\\\\\..\\\\\\\\Windows\\\\\\\\System32\\\\\\\\regsvr32.exe\\\\ *))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Regsvr32 Anomaly\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((Image:"*\\\\regsvr32.exe" AND CommandLine:"*\\\\Temp\\\\*") OR (Image:"*\\\\regsvr32.exe" AND ParentImage:"*\\\\powershell.exe") OR (Image:"*\\\\regsvr32.exe" AND CommandLine:("*\\/i\\:http* scrobj.dll" "*\\/i\\:ftp* scrobj.dll")) OR (Image:"*\\\\wscript.exe" AND ParentImage:"*\\\\regsvr32.exe") OR (Image:"*\\\\EXCEL.EXE" AND CommandLine:"*..\\\\..\\\\..\\\\Windows\\\\System32\\\\regsvr32.exe *"))
```


### splunk
    
```
((Image="*\\\\regsvr32.exe" CommandLine="*\\\\Temp\\\\*") OR (Image="*\\\\regsvr32.exe" ParentImage="*\\\\powershell.exe") OR (Image="*\\\\regsvr32.exe" (CommandLine="*/i:http* scrobj.dll" OR CommandLine="*/i:ftp* scrobj.dll")) OR (Image="*\\\\wscript.exe" ParentImage="*\\\\regsvr32.exe") OR (Image="*\\\\EXCEL.EXE" CommandLine="*..\\\\..\\\\..\\\\Windows\\\\System32\\\\regsvr32.exe *")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
((Image="*\\\\regsvr32.exe" CommandLine="*\\\\Temp\\\\*") OR (Image="*\\\\regsvr32.exe" ParentImage="*\\\\powershell.exe") OR (Image="*\\\\regsvr32.exe" CommandLine IN ["*/i:http* scrobj.dll", "*/i:ftp* scrobj.dll"]) OR (Image="*\\\\wscript.exe" ParentImage="*\\\\regsvr32.exe") OR (Image="*\\\\EXCEL.EXE" CommandLine="*..\\\\..\\\\..\\\\Windows\\\\System32\\\\regsvr32.exe *"))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*.*\\regsvr32\\.exe)(?=.*.*\\Temp\\\\.*))|.*(?:.*(?=.*.*\\regsvr32\\.exe)(?=.*.*\\powershell\\.exe))|.*(?:.*(?=.*.*\\regsvr32\\.exe)(?=.*(?:.*.*/i:http.* scrobj\\.dll|.*.*/i:ftp.* scrobj\\.dll)))|.*(?:.*(?=.*.*\\wscript\\.exe)(?=.*.*\\regsvr32\\.exe))|.*(?:.*(?=.*.*\\EXCEL\\.EXE)(?=.*.*\\.\\.\\\\.\\.\\\\.\\.\\Windows\\System32\\regsvr32\\.exe .*))))'
```



