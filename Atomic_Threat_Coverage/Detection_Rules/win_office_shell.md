| Title                    | Microsoft Office Product Spawning Windows Shell       |
|:-------------------------|:------------------|
| **Description**          | Detects a Windows command line executable started from Microsoft Word, Excel, Powerpoint, Publisher and Visio. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059)</li><li>[T1202: Indirect Command Execution](https://attack.mitre.org/techniques/T1202)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1202: Indirect Command Execution](../Triggers/T1202.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.hybrid-analysis.com/sample/465aabe132ccb949e75b8ab9c5bda36d80cf2fd503d52b8bad54e295f28bbc21?environmentId=100](https://www.hybrid-analysis.com/sample/465aabe132ccb949e75b8ab9c5bda36d80cf2fd503d52b8bad54e295f28bbc21?environmentId=100)</li><li>[https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html](https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html)</li></ul>  |
| **Author**               | Michael Haag, Florian Roth, Markus Neis |
| Other Tags           | <ul><li>car.2013-02-003</li><li>car.2014-04-003</li><li>attack.t1059.003</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Microsoft Office Product Spawning Windows Shell
id: 438025f9-5856-4663-83f7-52f878a70a50
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
    - attack.t1059.003
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
            - '*\wmic.exe'  # https://app.any.run/tasks/c903e9c8-0350-440c-8688-3881b556b8e0/
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





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "ParentImage.*.*\\WINWORD.EXE" -or $_.message -match "ParentImage.*.*\\EXCEL.EXE" -or $_.message -match "ParentImage.*.*\\POWERPNT.exe" -or $_.message -match "ParentImage.*.*\\MSPUB.exe" -or $_.message -match "ParentImage.*.*\\VISIO.exe" -or $_.message -match "ParentImage.*.*\\OUTLOOK.EXE") -and ($_.message -match "Image.*.*\\cmd.exe" -or $_.message -match "Image.*.*\\powershell.exe" -or $_.message -match "Image.*.*\\wscript.exe" -or $_.message -match "Image.*.*\\cscript.exe" -or $_.message -match "Image.*.*\\sh.exe" -or $_.message -match "Image.*.*\\bash.exe" -or $_.message -match "Image.*.*\\scrcons.exe" -or $_.message -match "Image.*.*\\schtasks.exe" -or $_.message -match "Image.*.*\\regsvr32.exe" -or $_.message -match "Image.*.*\\hh.exe" -or $_.message -match "Image.*.*\\wmic.exe" -or $_.message -match "Image.*.*\\mshta.exe" -or $_.message -match "Image.*.*\\rundll32.exe" -or $_.message -match "Image.*.*\\msiexec.exe" -or $_.message -match "Image.*.*\\forfiles.exe" -or $_.message -match "Image.*.*\\scriptrunner.exe" -or $_.message -match "Image.*.*\\mftrace.exe" -or $_.message -match "Image.*.*\\AppVLP.exe" -or $_.message -match "Image.*.*\\svchost.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.ParentImage.keyword:(*\\WINWORD.EXE OR *\\EXCEL.EXE OR *\\POWERPNT.exe OR *\\MSPUB.exe OR *\\VISIO.exe OR *\\OUTLOOK.EXE) AND winlog.event_data.Image.keyword:(*\\cmd.exe OR *\\powershell.exe OR *\\wscript.exe OR *\\cscript.exe OR *\\sh.exe OR *\\bash.exe OR *\\scrcons.exe OR *\\schtasks.exe OR *\\regsvr32.exe OR *\\hh.exe OR *\\wmic.exe OR *\\mshta.exe OR *\\rundll32.exe OR *\\msiexec.exe OR *\\forfiles.exe OR *\\scriptrunner.exe OR *\\mftrace.exe OR *\\AppVLP.exe OR *\\svchost.exe))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/438025f9-5856-4663-83f7-52f878a70a50 <<EOF
{
  "metadata": {
    "title": "Microsoft Office Product Spawning Windows Shell",
    "description": "Detects a Windows command line executable started from Microsoft Word, Excel, Powerpoint, Publisher and Visio.",
    "tags": [
      "attack.execution",
      "attack.defense_evasion",
      "attack.t1059",
      "attack.t1202",
      "car.2013-02-003",
      "car.2014-04-003",
      "attack.t1059.003"
    ],
    "query": "(winlog.event_data.ParentImage.keyword:(*\\\\WINWORD.EXE OR *\\\\EXCEL.EXE OR *\\\\POWERPNT.exe OR *\\\\MSPUB.exe OR *\\\\VISIO.exe OR *\\\\OUTLOOK.EXE) AND winlog.event_data.Image.keyword:(*\\\\cmd.exe OR *\\\\powershell.exe OR *\\\\wscript.exe OR *\\\\cscript.exe OR *\\\\sh.exe OR *\\\\bash.exe OR *\\\\scrcons.exe OR *\\\\schtasks.exe OR *\\\\regsvr32.exe OR *\\\\hh.exe OR *\\\\wmic.exe OR *\\\\mshta.exe OR *\\\\rundll32.exe OR *\\\\msiexec.exe OR *\\\\forfiles.exe OR *\\\\scriptrunner.exe OR *\\\\mftrace.exe OR *\\\\AppVLP.exe OR *\\\\svchost.exe))"
  },
  "trigger": {
    "schedule": {
      "interval": "30m"
    }
  },
  "input": {
    "search": {
      "request": {
        "body": {
          "size": 0,
          "query": {
            "bool": {
              "must": [
                {
                  "query_string": {
                    "query": "(winlog.event_data.ParentImage.keyword:(*\\\\WINWORD.EXE OR *\\\\EXCEL.EXE OR *\\\\POWERPNT.exe OR *\\\\MSPUB.exe OR *\\\\VISIO.exe OR *\\\\OUTLOOK.EXE) AND winlog.event_data.Image.keyword:(*\\\\cmd.exe OR *\\\\powershell.exe OR *\\\\wscript.exe OR *\\\\cscript.exe OR *\\\\sh.exe OR *\\\\bash.exe OR *\\\\scrcons.exe OR *\\\\schtasks.exe OR *\\\\regsvr32.exe OR *\\\\hh.exe OR *\\\\wmic.exe OR *\\\\mshta.exe OR *\\\\rundll32.exe OR *\\\\msiexec.exe OR *\\\\forfiles.exe OR *\\\\scriptrunner.exe OR *\\\\mftrace.exe OR *\\\\AppVLP.exe OR *\\\\svchost.exe))",
                    "analyze_wildcard": true
                  }
                }
              ],
              "filter": {
                "range": {
                  "timestamp": {
                    "gte": "now-30m/m"
                  }
                }
              }
            }
          }
        },
        "indices": [
          "winlogbeat-*"
        ]
      }
    }
  },
  "condition": {
    "compare": {
      "ctx.payload.hits.total": {
        "not_eq": 0
      }
    }
  },
  "actions": {
    "send_email": {
      "throttle_period": "15m",
      "email": {
        "profile": "standard",
        "from": "root@localhost",
        "to": "root@localhost",
        "subject": "Sigma Rule 'Microsoft Office Product Spawning Windows Shell'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n      CommandLine = {{_source.CommandLine}}\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\n{{/ctx.payload.hits.hits}}",
        "attachments": {
          "data.json": {
            "data": {
              "format": "json"
            }
          }
        }
      }
    }
  }
}
EOF

```


### graylog
    
```
(ParentImage.keyword:(*\\WINWORD.EXE *\\EXCEL.EXE *\\POWERPNT.exe *\\MSPUB.exe *\\VISIO.exe *\\OUTLOOK.EXE) AND Image.keyword:(*\\cmd.exe *\\powershell.exe *\\wscript.exe *\\cscript.exe *\\sh.exe *\\bash.exe *\\scrcons.exe *\\schtasks.exe *\\regsvr32.exe *\\hh.exe *\\wmic.exe *\\mshta.exe *\\rundll32.exe *\\msiexec.exe *\\forfiles.exe *\\scriptrunner.exe *\\mftrace.exe *\\AppVLP.exe *\\svchost.exe))
```


### splunk
    
```
((ParentImage="*\\WINWORD.EXE" OR ParentImage="*\\EXCEL.EXE" OR ParentImage="*\\POWERPNT.exe" OR ParentImage="*\\MSPUB.exe" OR ParentImage="*\\VISIO.exe" OR ParentImage="*\\OUTLOOK.EXE") (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\wscript.exe" OR Image="*\\cscript.exe" OR Image="*\\sh.exe" OR Image="*\\bash.exe" OR Image="*\\scrcons.exe" OR Image="*\\schtasks.exe" OR Image="*\\regsvr32.exe" OR Image="*\\hh.exe" OR Image="*\\wmic.exe" OR Image="*\\mshta.exe" OR Image="*\\rundll32.exe" OR Image="*\\msiexec.exe" OR Image="*\\forfiles.exe" OR Image="*\\scriptrunner.exe" OR Image="*\\mftrace.exe" OR Image="*\\AppVLP.exe" OR Image="*\\svchost.exe")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(event_id="1" ParentImage IN ["*\\WINWORD.EXE", "*\\EXCEL.EXE", "*\\POWERPNT.exe", "*\\MSPUB.exe", "*\\VISIO.exe", "*\\OUTLOOK.EXE"] Image IN ["*\\cmd.exe", "*\\powershell.exe", "*\\wscript.exe", "*\\cscript.exe", "*\\sh.exe", "*\\bash.exe", "*\\scrcons.exe", "*\\schtasks.exe", "*\\regsvr32.exe", "*\\hh.exe", "*\\wmic.exe", "*\\mshta.exe", "*\\rundll32.exe", "*\\msiexec.exe", "*\\forfiles.exe", "*\\scriptrunner.exe", "*\\mftrace.exe", "*\\AppVLP.exe", "*\\svchost.exe"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\WINWORD\.EXE|.*.*\EXCEL\.EXE|.*.*\POWERPNT\.exe|.*.*\MSPUB\.exe|.*.*\VISIO\.exe|.*.*\OUTLOOK\.EXE))(?=.*(?:.*.*\cmd\.exe|.*.*\powershell\.exe|.*.*\wscript\.exe|.*.*\cscript\.exe|.*.*\sh\.exe|.*.*\bash\.exe|.*.*\scrcons\.exe|.*.*\schtasks\.exe|.*.*\regsvr32\.exe|.*.*\hh\.exe|.*.*\wmic\.exe|.*.*\mshta\.exe|.*.*\rundll32\.exe|.*.*\msiexec\.exe|.*.*\forfiles\.exe|.*.*\scriptrunner\.exe|.*.*\mftrace\.exe|.*.*\AppVLP\.exe|.*.*\svchost\.exe)))'
```



