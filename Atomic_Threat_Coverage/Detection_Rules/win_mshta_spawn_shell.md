| Title                | MSHTA Spawning Windows Shell                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a Windows command line executable started from MSHTA.                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1170: Mshta](https://attack.mitre.org/techniques/T1170)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1170: Mshta](../Triggers/T1170.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Printer software / driver installations</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://www.trustedsec.com/july-2015/malicious-htas/](https://www.trustedsec.com/july-2015/malicious-htas/)</li></ul>                                                          |
| Author               | Michael Haag                                                                                                                                                |


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
    filter:
        CommandLine:
            - '*/HP/HP*'
            - '*\HP\HP*'
    condition: selection and not filter
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1170
falsepositives:
    - Printer software / driver installations
level: high

```





### es-qs
    
```
((ParentImage.keyword:*\\\\mshta.exe AND Image.keyword:(*\\\\cmd.exe *\\\\powershell.exe *\\\\wscript.exe *\\\\cscript.exe *\\\\sh.exe *\\\\bash.exe *\\\\reg.exe *\\\\regsvr32.exe *\\\\BITSADMIN*)) AND NOT (CommandLine.keyword:(*\\/HP\\/HP* *\\\\HP\\\\HP*)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/MSHTA-Spawning-Windows-Shell <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "((ParentImage.keyword:*\\\\\\\\mshta.exe AND Image.keyword:(*\\\\\\\\cmd.exe *\\\\\\\\powershell.exe *\\\\\\\\wscript.exe *\\\\\\\\cscript.exe *\\\\\\\\sh.exe *\\\\\\\\bash.exe *\\\\\\\\reg.exe *\\\\\\\\regsvr32.exe *\\\\\\\\BITSADMIN*)) AND NOT (CommandLine.keyword:(*\\\\/HP\\\\/HP* *\\\\\\\\HP\\\\\\\\HP*)))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'MSHTA Spawning Windows Shell\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((ParentImage:"*\\\\mshta.exe" AND Image:("*\\\\cmd.exe" "*\\\\powershell.exe" "*\\\\wscript.exe" "*\\\\cscript.exe" "*\\\\sh.exe" "*\\\\bash.exe" "*\\\\reg.exe" "*\\\\regsvr32.exe" "*\\\\BITSADMIN*")) AND NOT (CommandLine:("*\\/HP\\/HP*" "*\\\\HP\\\\HP*")))
```


### splunk
    
```
((ParentImage="*\\\\mshta.exe" (Image="*\\\\cmd.exe" OR Image="*\\\\powershell.exe" OR Image="*\\\\wscript.exe" OR Image="*\\\\cscript.exe" OR Image="*\\\\sh.exe" OR Image="*\\\\bash.exe" OR Image="*\\\\reg.exe" OR Image="*\\\\regsvr32.exe" OR Image="*\\\\BITSADMIN*")) NOT ((CommandLine="*/HP/HP*" OR CommandLine="*\\\\HP\\\\HP*"))) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
((ParentImage="*\\\\mshta.exe" Image IN ["*\\\\cmd.exe", "*\\\\powershell.exe", "*\\\\wscript.exe", "*\\\\cscript.exe", "*\\\\sh.exe", "*\\\\bash.exe", "*\\\\reg.exe", "*\\\\regsvr32.exe", "*\\\\BITSADMIN*"])  -(CommandLine IN ["*/HP/HP*", "*\\\\HP\\\\HP*"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*.*\\mshta\\.exe)(?=.*(?:.*.*\\cmd\\.exe|.*.*\\powershell\\.exe|.*.*\\wscript\\.exe|.*.*\\cscript\\.exe|.*.*\\sh\\.exe|.*.*\\bash\\.exe|.*.*\\reg\\.exe|.*.*\\regsvr32\\.exe|.*.*\\BITSADMIN.*))))(?=.*(?!.*(?:.*(?=.*(?:.*.*/HP/HP.*|.*.*\\HP\\HP.*))))))'
```



