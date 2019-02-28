| Title                | Regsvr32 Anomaly                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects various anomalies in relation to regsvr32.exe                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1117: Regsvr32](https://attack.mitre.org/techniques/T1117)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1117: Regsvr32](../Triggers/T1117.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://subt0x10.blogspot.de/2017/04/bypass-application-whitelisting-script.html](https://subt0x10.blogspot.de/2017/04/bypass-application-whitelisting-script.html)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


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
logsource:
    product: windows
    service: sysmon
detection:
    # Loads from Temp folder
    selection1:
        EventID: 1
        Image: '*\regsvr32.exe'
        CommandLine: '*\Temp\\*'
    # Loaded by powershell
    selection2:
        EventID: 1
        Image: '*\regsvr32.exe'
        ParentImage: '*\powershell.exe'
    # Regsvr32.exe used with http(s) address
    selection3:
        EventID: 1
        Image: '*\regsvr32.exe'
        CommandLine: 
            - '*/i:http* scrobj.dll'
            - '*/i:ftp* scrobj.dll'
    # Regsvr32.exe spawned wscript.exe process - indicator of COM scriptlet
    # https://www.hybrid-analysis.com/sample/f34da6d84a9663928606894fbc494cd9bf2f03c98cf0c775462802558d3a50ef?environmentId=100
    selection4:
        EventID: 1
        Image: '*\wscript.exe'
        ParentImage: '*\regsvr32.exe'
    # https://twitter.com/danielhbohannon/status/974321840385531904
    selection5:
        EventID: 1
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





### Kibana query

```
(EventID:"1" AND ((Image.keyword:*\\\\regsvr32.exe AND CommandLine.keyword:*\\\\Temp\\\\*) OR (Image.keyword:*\\\\regsvr32.exe AND ParentImage.keyword:*\\\\powershell.exe) OR (Image.keyword:*\\\\regsvr32.exe AND CommandLine.keyword:(*\\/i\\:http*\\ scrobj.dll *\\/i\\:ftp*\\ scrobj.dll)) OR (Image.keyword:*\\\\wscript.exe AND ParentImage.keyword:*\\\\regsvr32.exe) OR (Image.keyword:*\\\\EXCEL.EXE AND CommandLine.keyword:*..\\\\..\\\\..\\\\Windows\\\\System32\\\\regsvr32.exe\\ *)))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Regsvr32-Anomaly <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"1\\" AND ((Image.keyword:*\\\\\\\\regsvr32.exe AND CommandLine.keyword:*\\\\\\\\Temp\\\\\\\\*) OR (Image.keyword:*\\\\\\\\regsvr32.exe AND ParentImage.keyword:*\\\\\\\\powershell.exe) OR (Image.keyword:*\\\\\\\\regsvr32.exe AND CommandLine.keyword:(*\\\\/i\\\\:http*\\\\ scrobj.dll *\\\\/i\\\\:ftp*\\\\ scrobj.dll)) OR (Image.keyword:*\\\\\\\\wscript.exe AND ParentImage.keyword:*\\\\\\\\regsvr32.exe) OR (Image.keyword:*\\\\\\\\EXCEL.EXE AND CommandLine.keyword:*..\\\\\\\\..\\\\\\\\..\\\\\\\\Windows\\\\\\\\System32\\\\\\\\regsvr32.exe\\\\ *)))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Regsvr32 Anomaly\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"1" AND ((Image:"*\\\\regsvr32.exe" AND CommandLine:"*\\\\Temp\\\\*") OR (Image:"*\\\\regsvr32.exe" AND ParentImage:"*\\\\powershell.exe") OR (Image:"*\\\\regsvr32.exe" AND CommandLine:("*\\/i\\:http* scrobj.dll" "*\\/i\\:ftp* scrobj.dll")) OR (Image:"*\\\\wscript.exe" AND ParentImage:"*\\\\regsvr32.exe") OR (Image:"*\\\\EXCEL.EXE" AND CommandLine:"*..\\\\..\\\\..\\\\Windows\\\\System32\\\\regsvr32.exe *")))
```

