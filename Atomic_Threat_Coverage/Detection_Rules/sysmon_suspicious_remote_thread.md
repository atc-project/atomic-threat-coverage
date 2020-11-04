| Title                    | Suspicious Remote Thread Created       |
|:-------------------------|:------------------|
| **Description**          | Offensive tradecraft is switching away from using APIs like "CreateRemoteThread", however, this is still largely observed in the wild. This rule aims to detect suspicious processes (those we would not expect to behave in this way like word.exe or outlook.exe) creating remote threads on other processes. It is a generalistic rule, but it should have a low FP ratio due to the selected range of processes. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1055: Process Injection](https://attack.mitre.org/techniques/T1055)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0012_8_windows_sysmon_CreateRemoteThread](../Data_Needed/DN_0012_8_windows_sysmon_CreateRemoteThread.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1055: Process Injection](../Triggers/T1055.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[Personal research, statistical analysis](Personal research, statistical analysis)</li><li>[https://lolbas-project.github.io](https://lolbas-project.github.io)</li></ul>  |
| **Author**               | Perez Diego (@darkquassar), oscd.community |


## Detection Rules

### Sigma rule

```
title: Suspicious Remote Thread Created
id: 66d31e5f-52d6-40a4-9615-002d3789a119
description: Offensive tradecraft is switching away from using APIs like "CreateRemoteThread", however, this is still largely observed in the wild. This rule aims
    to detect suspicious processes (those we would not expect to behave in this way like word.exe or outlook.exe) creating remote threads on other processes. It is
    a generalistic rule, but it should have a low FP ratio due to the selected range of processes.
notes:
    - MonitoringHost.exe is a process that loads .NET CLR by default and thus a favorite for process injection for .NET in-memory offensive tools.
status: experimental
date: 2019/10/27
modified: 2019/11/13
author: Perez Diego (@darkquassar), oscd.community
references:
    - Personal research, statistical analysis
    - https://lolbas-project.github.io
logsource:
    product: windows
    service: sysmon
tags:
    - attack.privilege_escalation
    - attack.t1055
detection:
    selection: 
        EventID: 8
        SourceImage|endswith:
            - '\bash.exe'
            - '\cvtres.exe'
            - '\defrag.exe'
            - '\dnx.exe'
            - '\esentutl.exe'
            - '\excel.exe'
            - '\expand.exe'
            - '\explorer.exe'
            - '\find.exe'
            - '\findstr.exe'
            - '\forfiles.exe'
            - '\git.exe'
            - '\gpupdate.exe'
            - '\hh.exe'
            - '\iexplore.exe'
            - '\installutil.exe'
            - '\lync.exe'
            - '\makecab.exe'
            - '\mDNSResponder.exe'
            - '\monitoringhost.exe'
            - '\msbuild.exe'
            - '\mshta.exe'
            - '\msiexec.exe'
            - '\mspaint.exe'
            - '\outlook.exe'
            - '\ping.exe'
            - '\powerpnt.exe'
            - '\powershell.exe'
            - '\provtool.exe'
            - '\python.exe'
            - '\regsvr32.exe'
            - '\robocopy.exe'
            - '\runonce.exe'
            - '\sapcimc.exe'
            - '\schtasks.exe'
            - '\smartscreen.exe'
            - '\spoolsv.exe'
            # - '\taskhost.exe'  # disabled due to false positives
            - '\tstheme.exe'
            - '\userinit.exe'
            - '\vssadmin.exe'
            - '\vssvc.exe'
            - '\w3wp.exe*'       
            - '\winlogon.exe'
            - '\winscp.exe'
            - '\wmic.exe'
            - '\word.exe'
            - '\wscript.exe'
    filter:
        SourceImage|contains: 'Visual Studio'
    condition: selection AND NOT filter
fields:
    - ComputerName
    - User
    - SourceImage
    - TargetImage
level: high
falsepositives:
    - Unknown

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "8" -and ($_.message -match "SourceImage.*.*\\bash.exe" -or $_.message -match "SourceImage.*.*\\cvtres.exe" -or $_.message -match "SourceImage.*.*\\defrag.exe" -or $_.message -match "SourceImage.*.*\\dnx.exe" -or $_.message -match "SourceImage.*.*\\esentutl.exe" -or $_.message -match "SourceImage.*.*\\excel.exe" -or $_.message -match "SourceImage.*.*\\expand.exe" -or $_.message -match "SourceImage.*.*\\explorer.exe" -or $_.message -match "SourceImage.*.*\\find.exe" -or $_.message -match "SourceImage.*.*\\findstr.exe" -or $_.message -match "SourceImage.*.*\\forfiles.exe" -or $_.message -match "SourceImage.*.*\\git.exe" -or $_.message -match "SourceImage.*.*\\gpupdate.exe" -or $_.message -match "SourceImage.*.*\\hh.exe" -or $_.message -match "SourceImage.*.*\\iexplore.exe" -or $_.message -match "SourceImage.*.*\\installutil.exe" -or $_.message -match "SourceImage.*.*\\lync.exe" -or $_.message -match "SourceImage.*.*\\makecab.exe" -or $_.message -match "SourceImage.*.*\\mDNSResponder.exe" -or $_.message -match "SourceImage.*.*\\monitoringhost.exe" -or $_.message -match "SourceImage.*.*\\msbuild.exe" -or $_.message -match "SourceImage.*.*\\mshta.exe" -or $_.message -match "SourceImage.*.*\\msiexec.exe" -or $_.message -match "SourceImage.*.*\\mspaint.exe" -or $_.message -match "SourceImage.*.*\\outlook.exe" -or $_.message -match "SourceImage.*.*\\ping.exe" -or $_.message -match "SourceImage.*.*\\powerpnt.exe" -or $_.message -match "SourceImage.*.*\\powershell.exe" -or $_.message -match "SourceImage.*.*\\provtool.exe" -or $_.message -match "SourceImage.*.*\\python.exe" -or $_.message -match "SourceImage.*.*\\regsvr32.exe" -or $_.message -match "SourceImage.*.*\\robocopy.exe" -or $_.message -match "SourceImage.*.*\\runonce.exe" -or $_.message -match "SourceImage.*.*\\sapcimc.exe" -or $_.message -match "SourceImage.*.*\\schtasks.exe" -or $_.message -match "SourceImage.*.*\\smartscreen.exe" -or $_.message -match "SourceImage.*.*\\spoolsv.exe" -or $_.message -match "SourceImage.*.*\\tstheme.exe" -or $_.message -match "SourceImage.*.*\\userinit.exe" -or $_.message -match "SourceImage.*.*\\vssadmin.exe" -or $_.message -match "SourceImage.*.*\\vssvc.exe" -or $_.message -match "SourceImage.*.*\\w3wp.exe.*" -or $_.message -match "SourceImage.*.*\\winlogon.exe" -or $_.message -match "SourceImage.*.*\\winscp.exe" -or $_.message -match "SourceImage.*.*\\wmic.exe" -or $_.message -match "SourceImage.*.*\\word.exe" -or $_.message -match "SourceImage.*.*\\wscript.exe")) -and  -not ($_.message -match "SourceImage.*.*Visual Studio.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND (winlog.event_id:"8" AND winlog.event_data.SourceImage.keyword:(*\\bash.exe OR *\\cvtres.exe OR *\\defrag.exe OR *\\dnx.exe OR *\\esentutl.exe OR *\\excel.exe OR *\\expand.exe OR *\\explorer.exe OR *\\find.exe OR *\\findstr.exe OR *\\forfiles.exe OR *\\git.exe OR *\\gpupdate.exe OR *\\hh.exe OR *\\iexplore.exe OR *\\installutil.exe OR *\\lync.exe OR *\\makecab.exe OR *\\mDNSResponder.exe OR *\\monitoringhost.exe OR *\\msbuild.exe OR *\\mshta.exe OR *\\msiexec.exe OR *\\mspaint.exe OR *\\outlook.exe OR *\\ping.exe OR *\\powerpnt.exe OR *\\powershell.exe OR *\\provtool.exe OR *\\python.exe OR *\\regsvr32.exe OR *\\robocopy.exe OR *\\runonce.exe OR *\\sapcimc.exe OR *\\schtasks.exe OR *\\smartscreen.exe OR *\\spoolsv.exe OR *\\tstheme.exe OR *\\userinit.exe OR *\\vssadmin.exe OR *\\vssvc.exe OR *\\w3wp.exe* OR *\\winlogon.exe OR *\\winscp.exe OR *\\wmic.exe OR *\\word.exe OR *\\wscript.exe)) AND (NOT (winlog.event_data.SourceImage.keyword:*Visual\ Studio*)))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/66d31e5f-52d6-40a4-9615-002d3789a119 <<EOF
{
  "metadata": {
    "title": "Suspicious Remote Thread Created",
    "description": "Offensive tradecraft is switching away from using APIs like \"CreateRemoteThread\", however, this is still largely observed in the wild. This rule aims to detect suspicious processes (those we would not expect to behave in this way like word.exe or outlook.exe) creating remote threads on other processes. It is a generalistic rule, but it should have a low FP ratio due to the selected range of processes.",
    "tags": [
      "attack.privilege_escalation",
      "attack.t1055"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND (winlog.event_id:\"8\" AND winlog.event_data.SourceImage.keyword:(*\\\\bash.exe OR *\\\\cvtres.exe OR *\\\\defrag.exe OR *\\\\dnx.exe OR *\\\\esentutl.exe OR *\\\\excel.exe OR *\\\\expand.exe OR *\\\\explorer.exe OR *\\\\find.exe OR *\\\\findstr.exe OR *\\\\forfiles.exe OR *\\\\git.exe OR *\\\\gpupdate.exe OR *\\\\hh.exe OR *\\\\iexplore.exe OR *\\\\installutil.exe OR *\\\\lync.exe OR *\\\\makecab.exe OR *\\\\mDNSResponder.exe OR *\\\\monitoringhost.exe OR *\\\\msbuild.exe OR *\\\\mshta.exe OR *\\\\msiexec.exe OR *\\\\mspaint.exe OR *\\\\outlook.exe OR *\\\\ping.exe OR *\\\\powerpnt.exe OR *\\\\powershell.exe OR *\\\\provtool.exe OR *\\\\python.exe OR *\\\\regsvr32.exe OR *\\\\robocopy.exe OR *\\\\runonce.exe OR *\\\\sapcimc.exe OR *\\\\schtasks.exe OR *\\\\smartscreen.exe OR *\\\\spoolsv.exe OR *\\\\tstheme.exe OR *\\\\userinit.exe OR *\\\\vssadmin.exe OR *\\\\vssvc.exe OR *\\\\w3wp.exe* OR *\\\\winlogon.exe OR *\\\\winscp.exe OR *\\\\wmic.exe OR *\\\\word.exe OR *\\\\wscript.exe)) AND (NOT (winlog.event_data.SourceImage.keyword:*Visual\\ Studio*)))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND (winlog.event_id:\"8\" AND winlog.event_data.SourceImage.keyword:(*\\\\bash.exe OR *\\\\cvtres.exe OR *\\\\defrag.exe OR *\\\\dnx.exe OR *\\\\esentutl.exe OR *\\\\excel.exe OR *\\\\expand.exe OR *\\\\explorer.exe OR *\\\\find.exe OR *\\\\findstr.exe OR *\\\\forfiles.exe OR *\\\\git.exe OR *\\\\gpupdate.exe OR *\\\\hh.exe OR *\\\\iexplore.exe OR *\\\\installutil.exe OR *\\\\lync.exe OR *\\\\makecab.exe OR *\\\\mDNSResponder.exe OR *\\\\monitoringhost.exe OR *\\\\msbuild.exe OR *\\\\mshta.exe OR *\\\\msiexec.exe OR *\\\\mspaint.exe OR *\\\\outlook.exe OR *\\\\ping.exe OR *\\\\powerpnt.exe OR *\\\\powershell.exe OR *\\\\provtool.exe OR *\\\\python.exe OR *\\\\regsvr32.exe OR *\\\\robocopy.exe OR *\\\\runonce.exe OR *\\\\sapcimc.exe OR *\\\\schtasks.exe OR *\\\\smartscreen.exe OR *\\\\spoolsv.exe OR *\\\\tstheme.exe OR *\\\\userinit.exe OR *\\\\vssadmin.exe OR *\\\\vssvc.exe OR *\\\\w3wp.exe* OR *\\\\winlogon.exe OR *\\\\winscp.exe OR *\\\\wmic.exe OR *\\\\word.exe OR *\\\\wscript.exe)) AND (NOT (winlog.event_data.SourceImage.keyword:*Visual\\ Studio*)))",
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
      "email": {
        "to": "root@localhost",
        "subject": "Sigma Rule 'Suspicious Remote Thread Created'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\nComputerName = {{_source.ComputerName}}\n        User = {{_source.User}}\n SourceImage = {{_source.SourceImage}}\n TargetImage = {{_source.TargetImage}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
((EventID:"8" AND SourceImage.keyword:(*\\bash.exe *\\cvtres.exe *\\defrag.exe *\\dnx.exe *\\esentutl.exe *\\excel.exe *\\expand.exe *\\explorer.exe *\\find.exe *\\findstr.exe *\\forfiles.exe *\\git.exe *\\gpupdate.exe *\\hh.exe *\\iexplore.exe *\\installutil.exe *\\lync.exe *\\makecab.exe *\\mDNSResponder.exe *\\monitoringhost.exe *\\msbuild.exe *\\mshta.exe *\\msiexec.exe *\\mspaint.exe *\\outlook.exe *\\ping.exe *\\powerpnt.exe *\\powershell.exe *\\provtool.exe *\\python.exe *\\regsvr32.exe *\\robocopy.exe *\\runonce.exe *\\sapcimc.exe *\\schtasks.exe *\\smartscreen.exe *\\spoolsv.exe *\\tstheme.exe *\\userinit.exe *\\vssadmin.exe *\\vssvc.exe *\\w3wp.exe* *\\winlogon.exe *\\winscp.exe *\\wmic.exe *\\word.exe *\\wscript.exe)) AND (NOT (SourceImage.keyword:*Visual Studio*)))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode="8" (SourceImage="*\\bash.exe" OR SourceImage="*\\cvtres.exe" OR SourceImage="*\\defrag.exe" OR SourceImage="*\\dnx.exe" OR SourceImage="*\\esentutl.exe" OR SourceImage="*\\excel.exe" OR SourceImage="*\\expand.exe" OR SourceImage="*\\explorer.exe" OR SourceImage="*\\find.exe" OR SourceImage="*\\findstr.exe" OR SourceImage="*\\forfiles.exe" OR SourceImage="*\\git.exe" OR SourceImage="*\\gpupdate.exe" OR SourceImage="*\\hh.exe" OR SourceImage="*\\iexplore.exe" OR SourceImage="*\\installutil.exe" OR SourceImage="*\\lync.exe" OR SourceImage="*\\makecab.exe" OR SourceImage="*\\mDNSResponder.exe" OR SourceImage="*\\monitoringhost.exe" OR SourceImage="*\\msbuild.exe" OR SourceImage="*\\mshta.exe" OR SourceImage="*\\msiexec.exe" OR SourceImage="*\\mspaint.exe" OR SourceImage="*\\outlook.exe" OR SourceImage="*\\ping.exe" OR SourceImage="*\\powerpnt.exe" OR SourceImage="*\\powershell.exe" OR SourceImage="*\\provtool.exe" OR SourceImage="*\\python.exe" OR SourceImage="*\\regsvr32.exe" OR SourceImage="*\\robocopy.exe" OR SourceImage="*\\runonce.exe" OR SourceImage="*\\sapcimc.exe" OR SourceImage="*\\schtasks.exe" OR SourceImage="*\\smartscreen.exe" OR SourceImage="*\\spoolsv.exe" OR SourceImage="*\\tstheme.exe" OR SourceImage="*\\userinit.exe" OR SourceImage="*\\vssadmin.exe" OR SourceImage="*\\vssvc.exe" OR SourceImage="*\\w3wp.exe*" OR SourceImage="*\\winlogon.exe" OR SourceImage="*\\winscp.exe" OR SourceImage="*\\wmic.exe" OR SourceImage="*\\word.exe" OR SourceImage="*\\wscript.exe")) NOT (SourceImage="*Visual Studio*")) | table ComputerName,User,SourceImage,TargetImage
```


### logpoint
    
```
((event_id="8" SourceImage IN ["*\\bash.exe", "*\\cvtres.exe", "*\\defrag.exe", "*\\dnx.exe", "*\\esentutl.exe", "*\\excel.exe", "*\\expand.exe", "*\\explorer.exe", "*\\find.exe", "*\\findstr.exe", "*\\forfiles.exe", "*\\git.exe", "*\\gpupdate.exe", "*\\hh.exe", "*\\iexplore.exe", "*\\installutil.exe", "*\\lync.exe", "*\\makecab.exe", "*\\mDNSResponder.exe", "*\\monitoringhost.exe", "*\\msbuild.exe", "*\\mshta.exe", "*\\msiexec.exe", "*\\mspaint.exe", "*\\outlook.exe", "*\\ping.exe", "*\\powerpnt.exe", "*\\powershell.exe", "*\\provtool.exe", "*\\python.exe", "*\\regsvr32.exe", "*\\robocopy.exe", "*\\runonce.exe", "*\\sapcimc.exe", "*\\schtasks.exe", "*\\smartscreen.exe", "*\\spoolsv.exe", "*\\tstheme.exe", "*\\userinit.exe", "*\\vssadmin.exe", "*\\vssvc.exe", "*\\w3wp.exe*", "*\\winlogon.exe", "*\\winscp.exe", "*\\wmic.exe", "*\\word.exe", "*\\wscript.exe"])  -(SourceImage="*Visual Studio*"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*8)(?=.*(?:.*.*\bash\.exe|.*.*\cvtres\.exe|.*.*\defrag\.exe|.*.*\dnx\.exe|.*.*\esentutl\.exe|.*.*\excel\.exe|.*.*\expand\.exe|.*.*\explorer\.exe|.*.*\find\.exe|.*.*\findstr\.exe|.*.*\forfiles\.exe|.*.*\git\.exe|.*.*\gpupdate\.exe|.*.*\hh\.exe|.*.*\iexplore\.exe|.*.*\installutil\.exe|.*.*\lync\.exe|.*.*\makecab\.exe|.*.*\mDNSResponder\.exe|.*.*\monitoringhost\.exe|.*.*\msbuild\.exe|.*.*\mshta\.exe|.*.*\msiexec\.exe|.*.*\mspaint\.exe|.*.*\outlook\.exe|.*.*\ping\.exe|.*.*\powerpnt\.exe|.*.*\powershell\.exe|.*.*\provtool\.exe|.*.*\python\.exe|.*.*\regsvr32\.exe|.*.*\robocopy\.exe|.*.*\runonce\.exe|.*.*\sapcimc\.exe|.*.*\schtasks\.exe|.*.*\smartscreen\.exe|.*.*\spoolsv\.exe|.*.*\tstheme\.exe|.*.*\userinit\.exe|.*.*\vssadmin\.exe|.*.*\vssvc\.exe|.*.*\w3wp\.exe.*|.*.*\winlogon\.exe|.*.*\winscp\.exe|.*.*\wmic\.exe|.*.*\word\.exe|.*.*\wscript\.exe))))(?=.*(?!.*(?:.*(?=.*.*Visual Studio.*)))))'
```



