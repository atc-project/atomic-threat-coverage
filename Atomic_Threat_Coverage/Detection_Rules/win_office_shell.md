| Title                | Microsoft Office Product Spawning Windows Shell                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a Windows command line executable started from Microsoft Word, Excel, Powerpoint, Publisher and Visio.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1059: Command-Line Interface](https://attack.mitre.org/techniques/T1059)</li><li>[T1202: Indirect Command Execution](https://attack.mitre.org/techniques/T1202)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1059: Command-Line Interface](../Triggers/T1059.md)</li><li>[T1202: Indirect Command Execution](../Triggers/T1202.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.hybrid-analysis.com/sample/465aabe132ccb949e75b8ab9c5bda36d80cf2fd503d52b8bad54e295f28bbc21?environmentId=100](https://www.hybrid-analysis.com/sample/465aabe132ccb949e75b8ab9c5bda36d80cf2fd503d52b8bad54e295f28bbc21?environmentId=100)</li><li>[https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html](https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html)</li></ul>  |
| Author               | Michael Haag, Florian Roth, Markus Neis |
| Other Tags           | <ul><li>car.2013-02-003</li><li>car.2013-02-003</li><li>car.2014-04-003</li><li>car.2014-04-003</li></ul> | 

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
    - attack.t1202
    - car.2013-02-003
    - car.2014-04-003
author: Michael Haag, Florian Roth, Markus Neis
date: 2018/04/06
logsource:
    category: process_creation
    product: windows
detection:
    selection:
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
            - '*\schtasks.exe'
            - '*\regsvr32.exe'
            - '*\hh.exe'
            - '*\wmic.exe'
            - '*\mshta.exe'
            - '*\rundll32.exe'
            - '*\msiexec.exe'
            - '*\forfiles.exe'
            - '*\scriptrunner.exe'
            - '*\mftrace.exe'
            - '*\AppVLP.exe'
            - '*\svchost.exe'  # https://www.vmray.com/analyses/2d2fa29185ad/report/overview.html
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
(ParentImage.keyword:(*\\\\WINWORD.EXE *\\\\EXCEL.EXE *\\\\POWERPNT.exe *\\\\MSPUB.exe *\\\\VISIO.exe *\\\\OUTLOOK.EXE) AND Image.keyword:(*\\\\cmd.exe *\\\\powershell.exe *\\\\wscript.exe *\\\\cscript.exe *\\\\sh.exe *\\\\bash.exe *\\\\scrcons.exe *\\\\schtasks.exe *\\\\regsvr32.exe *\\\\hh.exe *\\\\wmic.exe *\\\\mshta.exe *\\\\rundll32.exe *\\\\msiexec.exe *\\\\forfiles.exe *\\\\scriptrunner.exe *\\\\mftrace.exe *\\\\AppVLP.exe *\\\\svchost.exe))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Microsoft-Office-Product-Spawning-Windows-Shell <<EOF\n{\n  "metadata": {\n    "title": "Microsoft Office Product Spawning Windows Shell",\n    "description": "Detects a Windows command line executable started from Microsoft Word, Excel, Powerpoint, Publisher and Visio.",\n    "tags": [\n      "attack.execution",\n      "attack.defense_evasion",\n      "attack.t1059",\n      "attack.t1202",\n      "car.2013-02-003",\n      "car.2014-04-003"\n    ],\n    "query": "(ParentImage.keyword:(*\\\\\\\\WINWORD.EXE *\\\\\\\\EXCEL.EXE *\\\\\\\\POWERPNT.exe *\\\\\\\\MSPUB.exe *\\\\\\\\VISIO.exe *\\\\\\\\OUTLOOK.EXE) AND Image.keyword:(*\\\\\\\\cmd.exe *\\\\\\\\powershell.exe *\\\\\\\\wscript.exe *\\\\\\\\cscript.exe *\\\\\\\\sh.exe *\\\\\\\\bash.exe *\\\\\\\\scrcons.exe *\\\\\\\\schtasks.exe *\\\\\\\\regsvr32.exe *\\\\\\\\hh.exe *\\\\\\\\wmic.exe *\\\\\\\\mshta.exe *\\\\\\\\rundll32.exe *\\\\\\\\msiexec.exe *\\\\\\\\forfiles.exe *\\\\\\\\scriptrunner.exe *\\\\\\\\mftrace.exe *\\\\\\\\AppVLP.exe *\\\\\\\\svchost.exe))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(ParentImage.keyword:(*\\\\\\\\WINWORD.EXE *\\\\\\\\EXCEL.EXE *\\\\\\\\POWERPNT.exe *\\\\\\\\MSPUB.exe *\\\\\\\\VISIO.exe *\\\\\\\\OUTLOOK.EXE) AND Image.keyword:(*\\\\\\\\cmd.exe *\\\\\\\\powershell.exe *\\\\\\\\wscript.exe *\\\\\\\\cscript.exe *\\\\\\\\sh.exe *\\\\\\\\bash.exe *\\\\\\\\scrcons.exe *\\\\\\\\schtasks.exe *\\\\\\\\regsvr32.exe *\\\\\\\\hh.exe *\\\\\\\\wmic.exe *\\\\\\\\mshta.exe *\\\\\\\\rundll32.exe *\\\\\\\\msiexec.exe *\\\\\\\\forfiles.exe *\\\\\\\\scriptrunner.exe *\\\\\\\\mftrace.exe *\\\\\\\\AppVLP.exe *\\\\\\\\svchost.exe))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Microsoft Office Product Spawning Windows Shell\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(ParentImage:("*\\\\WINWORD.EXE" "*\\\\EXCEL.EXE" "*\\\\POWERPNT.exe" "*\\\\MSPUB.exe" "*\\\\VISIO.exe" "*\\\\OUTLOOK.EXE") AND Image:("*\\\\cmd.exe" "*\\\\powershell.exe" "*\\\\wscript.exe" "*\\\\cscript.exe" "*\\\\sh.exe" "*\\\\bash.exe" "*\\\\scrcons.exe" "*\\\\schtasks.exe" "*\\\\regsvr32.exe" "*\\\\hh.exe" "*\\\\wmic.exe" "*\\\\mshta.exe" "*\\\\rundll32.exe" "*\\\\msiexec.exe" "*\\\\forfiles.exe" "*\\\\scriptrunner.exe" "*\\\\mftrace.exe" "*\\\\AppVLP.exe" "*\\\\svchost.exe"))
```


### splunk
    
```
((ParentImage="*\\\\WINWORD.EXE" OR ParentImage="*\\\\EXCEL.EXE" OR ParentImage="*\\\\POWERPNT.exe" OR ParentImage="*\\\\MSPUB.exe" OR ParentImage="*\\\\VISIO.exe" OR ParentImage="*\\\\OUTLOOK.EXE") (Image="*\\\\cmd.exe" OR Image="*\\\\powershell.exe" OR Image="*\\\\wscript.exe" OR Image="*\\\\cscript.exe" OR Image="*\\\\sh.exe" OR Image="*\\\\bash.exe" OR Image="*\\\\scrcons.exe" OR Image="*\\\\schtasks.exe" OR Image="*\\\\regsvr32.exe" OR Image="*\\\\hh.exe" OR Image="*\\\\wmic.exe" OR Image="*\\\\mshta.exe" OR Image="*\\\\rundll32.exe" OR Image="*\\\\msiexec.exe" OR Image="*\\\\forfiles.exe" OR Image="*\\\\scriptrunner.exe" OR Image="*\\\\mftrace.exe" OR Image="*\\\\AppVLP.exe" OR Image="*\\\\svchost.exe")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(ParentImage IN ["*\\\\WINWORD.EXE", "*\\\\EXCEL.EXE", "*\\\\POWERPNT.exe", "*\\\\MSPUB.exe", "*\\\\VISIO.exe", "*\\\\OUTLOOK.EXE"] Image IN ["*\\\\cmd.exe", "*\\\\powershell.exe", "*\\\\wscript.exe", "*\\\\cscript.exe", "*\\\\sh.exe", "*\\\\bash.exe", "*\\\\scrcons.exe", "*\\\\schtasks.exe", "*\\\\regsvr32.exe", "*\\\\hh.exe", "*\\\\wmic.exe", "*\\\\mshta.exe", "*\\\\rundll32.exe", "*\\\\msiexec.exe", "*\\\\forfiles.exe", "*\\\\scriptrunner.exe", "*\\\\mftrace.exe", "*\\\\AppVLP.exe", "*\\\\svchost.exe"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\\WINWORD\\.EXE|.*.*\\EXCEL\\.EXE|.*.*\\POWERPNT\\.exe|.*.*\\MSPUB\\.exe|.*.*\\VISIO\\.exe|.*.*\\OUTLOOK\\.EXE))(?=.*(?:.*.*\\cmd\\.exe|.*.*\\powershell\\.exe|.*.*\\wscript\\.exe|.*.*\\cscript\\.exe|.*.*\\sh\\.exe|.*.*\\bash\\.exe|.*.*\\scrcons\\.exe|.*.*\\schtasks\\.exe|.*.*\\regsvr32\\.exe|.*.*\\hh\\.exe|.*.*\\wmic\\.exe|.*.*\\mshta\\.exe|.*.*\\rundll32\\.exe|.*.*\\msiexec\\.exe|.*.*\\forfiles\\.exe|.*.*\\scriptrunner\\.exe|.*.*\\mftrace\\.exe|.*.*\\AppVLP\\.exe|.*.*\\svchost\\.exe)))'
```



