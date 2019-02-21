| Title                | Microsoft Office Product Spawning Windows Shell                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a Windows command line executable started from Microsoft Word, Excel, Powerpoint, Publisher and Visio.                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1059: Command-Line Interface](https://attack.mitre.org/techniques/T1059)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1059: Command-Line Interface](../Triggers/T1059.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://www.hybrid-analysis.com/sample/465aabe132ccb949e75b8ab9c5bda36d80cf2fd503d52b8bad54e295f28bbc21?environmentId=100](https://www.hybrid-analysis.com/sample/465aabe132ccb949e75b8ab9c5bda36d80cf2fd503d52b8bad54e295f28bbc21?environmentId=100)</li><li>[https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html](https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html)</li></ul>                                                          |
| Author               | Michael Haag, Florian Roth, Markus Neis                                                                                                                                                |
| Other Tags           | <ul><li>attack.T1202</li><li>attack.T1202</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Microsoft Office Product Spawning Windows Shell
status: experimental
description: Detects a Windows command line executable started from Microsoft Word, Excel, Powerpoint, Publisher and Visio.
references:
    - https://www.hybrid-analysis.com/sample/465aabe132ccb949e75b8ab9c5bda36d80cf2fd503d52b8bad54e295f28bbc21?environmentId=100
    - https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1059
    - attack.T1202
author: Michael Haag, Florian Roth, Markus Neis
date: 2018/04/06
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        ParentImage:
            - '*\WINWORD.EXE'
            - '*\EXCEL.EXE'
            - '*\POWERPNT.exe'
            - '*\MSPUB.exe'
            - '*\VISIO.exe'
            - '*\OUTLOOK.EXE'
        Image:
            - '*\cmd.exe'
            - '*\powershell.exe'
            - '*\wscript.exe'
            - '*\cscript.exe'
            - '*\sh.exe'
            - '*\bash.exe'
            - '*\scrcons.exe'
            - '*\schtasks.exe'  # see https://www.hybrid-analysis.com/sample/b409538c99f99b94a5035d9fa44a506b41be0feb23e89b7e4d272ba791aa6002?environmentId=100
            - '*\regsvr32.exe'  # see https://twitter.com/subTee/status/899283365647458305
            - '*\hh.exe'  # see https://www.hybrid-analysis.com/sample/6abc2b63f1865a847ff7f5a9d49bb944397b36f5503b9718d6f91f93d60f7cd7?environmentId=100
            - '*\wmic.exe'  # see https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html
            - '*\mshta.exe'  # see https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html
            - '*\rundll32.exe'  # see https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html
            - '*\msiexec.exe'  # see https://twitter.com/DissectMalware/status/984252467474026497
            - '*\forfiles.exe' # see https://twitter.com/danielhbohannon/status/896057910123347969?lang=en
            - '*\scriptrunner.exe' # see https://twitter.com/KyleHanslovan/status/914800377580503040
            - '*\mftrace.exe' # see https://github.com/api0cradle/LOLBAS/blob/763d0b115cd702780ca042a8beb6ee684ef7823f/OtherMSBinaries/Mftrace.md
            - '*\AppVLP.exe' # see https://twitter.com/moo_hax/status/892388990686347264
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - unknown
level: high

```





### es-qs
    
```
(EventID:"1" AND ParentImage.keyword:(*\\\\WINWORD.EXE *\\\\EXCEL.EXE *\\\\POWERPNT.exe *\\\\MSPUB.exe *\\\\VISIO.exe *\\\\OUTLOOK.EXE) AND Image.keyword:(*\\\\cmd.exe *\\\\powershell.exe *\\\\wscript.exe *\\\\cscript.exe *\\\\sh.exe *\\\\bash.exe *\\\\scrcons.exe *\\\\schtasks.exe *\\\\regsvr32.exe *\\\\hh.exe *\\\\wmic.exe *\\\\mshta.exe *\\\\rundll32.exe *\\\\msiexec.exe *\\\\forfiles.exe *\\\\scriptrunner.exe *\\\\mftrace.exe *\\\\AppVLP.exe))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Microsoft-Office-Product-Spawning-Windows-Shell <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"1\\" AND ParentImage.keyword:(*\\\\\\\\WINWORD.EXE *\\\\\\\\EXCEL.EXE *\\\\\\\\POWERPNT.exe *\\\\\\\\MSPUB.exe *\\\\\\\\VISIO.exe *\\\\\\\\OUTLOOK.EXE) AND Image.keyword:(*\\\\\\\\cmd.exe *\\\\\\\\powershell.exe *\\\\\\\\wscript.exe *\\\\\\\\cscript.exe *\\\\\\\\sh.exe *\\\\\\\\bash.exe *\\\\\\\\scrcons.exe *\\\\\\\\schtasks.exe *\\\\\\\\regsvr32.exe *\\\\\\\\hh.exe *\\\\\\\\wmic.exe *\\\\\\\\mshta.exe *\\\\\\\\rundll32.exe *\\\\\\\\msiexec.exe *\\\\\\\\forfiles.exe *\\\\\\\\scriptrunner.exe *\\\\\\\\mftrace.exe *\\\\\\\\AppVLP.exe))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Microsoft Office Product Spawning Windows Shell\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"1" AND ParentImage:("*\\\\WINWORD.EXE" "*\\\\EXCEL.EXE" "*\\\\POWERPNT.exe" "*\\\\MSPUB.exe" "*\\\\VISIO.exe" "*\\\\OUTLOOK.EXE") AND Image:("*\\\\cmd.exe" "*\\\\powershell.exe" "*\\\\wscript.exe" "*\\\\cscript.exe" "*\\\\sh.exe" "*\\\\bash.exe" "*\\\\scrcons.exe" "*\\\\schtasks.exe" "*\\\\regsvr32.exe" "*\\\\hh.exe" "*\\\\wmic.exe" "*\\\\mshta.exe" "*\\\\rundll32.exe" "*\\\\msiexec.exe" "*\\\\forfiles.exe" "*\\\\scriptrunner.exe" "*\\\\mftrace.exe" "*\\\\AppVLP.exe"))
```


### splunk
    
```
(EventID="1" (ParentImage="*\\\\WINWORD.EXE" OR ParentImage="*\\\\EXCEL.EXE" OR ParentImage="*\\\\POWERPNT.exe" OR ParentImage="*\\\\MSPUB.exe" OR ParentImage="*\\\\VISIO.exe" OR ParentImage="*\\\\OUTLOOK.EXE") (Image="*\\\\cmd.exe" OR Image="*\\\\powershell.exe" OR Image="*\\\\wscript.exe" OR Image="*\\\\cscript.exe" OR Image="*\\\\sh.exe" OR Image="*\\\\bash.exe" OR Image="*\\\\scrcons.exe" OR Image="*\\\\schtasks.exe" OR Image="*\\\\regsvr32.exe" OR Image="*\\\\hh.exe" OR Image="*\\\\wmic.exe" OR Image="*\\\\mshta.exe" OR Image="*\\\\rundll32.exe" OR Image="*\\\\msiexec.exe" OR Image="*\\\\forfiles.exe" OR Image="*\\\\scriptrunner.exe" OR Image="*\\\\mftrace.exe" OR Image="*\\\\AppVLP.exe")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(EventID="1" ParentImage IN ["*\\\\WINWORD.EXE", "*\\\\EXCEL.EXE", "*\\\\POWERPNT.exe", "*\\\\MSPUB.exe", "*\\\\VISIO.exe", "*\\\\OUTLOOK.EXE"] Image IN ["*\\\\cmd.exe", "*\\\\powershell.exe", "*\\\\wscript.exe", "*\\\\cscript.exe", "*\\\\sh.exe", "*\\\\bash.exe", "*\\\\scrcons.exe", "*\\\\schtasks.exe", "*\\\\regsvr32.exe", "*\\\\hh.exe", "*\\\\wmic.exe", "*\\\\mshta.exe", "*\\\\rundll32.exe", "*\\\\msiexec.exe", "*\\\\forfiles.exe", "*\\\\scriptrunner.exe", "*\\\\mftrace.exe", "*\\\\AppVLP.exe"])
```


### grep
    
```
grep -P '^(?:.*(?=.*1)(?=.*(?:.*.*\\WINWORD\\.EXE|.*.*\\EXCEL\\.EXE|.*.*\\POWERPNT\\.exe|.*.*\\MSPUB\\.exe|.*.*\\VISIO\\.exe|.*.*\\OUTLOOK\\.EXE))(?=.*(?:.*.*\\cmd\\.exe|.*.*\\powershell\\.exe|.*.*\\wscript\\.exe|.*.*\\cscript\\.exe|.*.*\\sh\\.exe|.*.*\\bash\\.exe|.*.*\\scrcons\\.exe|.*.*\\schtasks\\.exe|.*.*\\regsvr32\\.exe|.*.*\\hh\\.exe|.*.*\\wmic\\.exe|.*.*\\mshta\\.exe|.*.*\\rundll32\\.exe|.*.*\\msiexec\\.exe|.*.*\\forfiles\\.exe|.*.*\\scriptrunner\\.exe|.*.*\\mftrace\\.exe|.*.*\\AppVLP\\.exe)))'
```



