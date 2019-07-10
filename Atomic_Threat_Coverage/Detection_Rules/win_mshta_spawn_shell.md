| Title                | MSHTA Spawning Windows Shell                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a Windows command line executable started from MSHTA.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1170: Mshta](https://attack.mitre.org/techniques/T1170)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1170: Mshta](../Triggers/T1170.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Printer software / driver installations</li><li>HP software</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.trustedsec.com/july-2015/malicious-htas/](https://www.trustedsec.com/july-2015/malicious-htas/)</li></ul>  |
| Author               | Michael Haag |
| Other Tags           | <ul><li>car.2013-02-003</li><li>car.2013-02-003</li><li>car.2013-03-001</li><li>car.2013-03-001</li><li>car.2014-04-003</li><li>car.2014-04-003</li></ul> | 

## Detection Rules

### Sigma rule

```
title: MSHTA Spawning Windows Shell
status: experimental
description: Detects a Windows command line executable started from MSHTA.
references:
    - https://www.trustedsec.com/july-2015/malicious-htas/
author: Michael Haag
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: '*\mshta.exe'
        Image:
            - '*\cmd.exe'
            - '*\powershell.exe'
            - '*\wscript.exe'
            - '*\cscript.exe'
            - '*\sh.exe'
            - '*\bash.exe'
            - '*\reg.exe'
            - '*\regsvr32.exe'
            - '*\BITSADMIN*'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1170
    - car.2013-02-003
    - car.2013-03-001
    - car.2014-04-003
falsepositives:
    - Printer software / driver installations
    - HP software
level: high

```





### es-qs
    
```
(ParentImage.keyword:*\\\\mshta.exe AND Image.keyword:(*\\\\cmd.exe *\\\\powershell.exe *\\\\wscript.exe *\\\\cscript.exe *\\\\sh.exe *\\\\bash.exe *\\\\reg.exe *\\\\regsvr32.exe *\\\\BITSADMIN*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/MSHTA-Spawning-Windows-Shell <<EOF\n{\n  "metadata": {\n    "title": "MSHTA Spawning Windows Shell",\n    "description": "Detects a Windows command line executable started from MSHTA.",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.execution",\n      "attack.t1170",\n      "car.2013-02-003",\n      "car.2013-03-001",\n      "car.2014-04-003"\n    ],\n    "query": "(ParentImage.keyword:*\\\\\\\\mshta.exe AND Image.keyword:(*\\\\\\\\cmd.exe *\\\\\\\\powershell.exe *\\\\\\\\wscript.exe *\\\\\\\\cscript.exe *\\\\\\\\sh.exe *\\\\\\\\bash.exe *\\\\\\\\reg.exe *\\\\\\\\regsvr32.exe *\\\\\\\\BITSADMIN*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(ParentImage.keyword:*\\\\\\\\mshta.exe AND Image.keyword:(*\\\\\\\\cmd.exe *\\\\\\\\powershell.exe *\\\\\\\\wscript.exe *\\\\\\\\cscript.exe *\\\\\\\\sh.exe *\\\\\\\\bash.exe *\\\\\\\\reg.exe *\\\\\\\\regsvr32.exe *\\\\\\\\BITSADMIN*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'MSHTA Spawning Windows Shell\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(ParentImage:"*\\\\mshta.exe" AND Image:("*\\\\cmd.exe" "*\\\\powershell.exe" "*\\\\wscript.exe" "*\\\\cscript.exe" "*\\\\sh.exe" "*\\\\bash.exe" "*\\\\reg.exe" "*\\\\regsvr32.exe" "*\\\\BITSADMIN*"))
```


### splunk
    
```
(ParentImage="*\\\\mshta.exe" (Image="*\\\\cmd.exe" OR Image="*\\\\powershell.exe" OR Image="*\\\\wscript.exe" OR Image="*\\\\cscript.exe" OR Image="*\\\\sh.exe" OR Image="*\\\\bash.exe" OR Image="*\\\\reg.exe" OR Image="*\\\\regsvr32.exe" OR Image="*\\\\BITSADMIN*")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(ParentImage="*\\\\mshta.exe" Image IN ["*\\\\cmd.exe", "*\\\\powershell.exe", "*\\\\wscript.exe", "*\\\\cscript.exe", "*\\\\sh.exe", "*\\\\bash.exe", "*\\\\reg.exe", "*\\\\regsvr32.exe", "*\\\\BITSADMIN*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\mshta\\.exe)(?=.*(?:.*.*\\cmd\\.exe|.*.*\\powershell\\.exe|.*.*\\wscript\\.exe|.*.*\\cscript\\.exe|.*.*\\sh\\.exe|.*.*\\bash\\.exe|.*.*\\reg\\.exe|.*.*\\regsvr32\\.exe|.*.*\\BITSADMIN.*)))'
```



