| Title                    | Shadow Copies Deletion Using Operating Systems Utilities       |
|:-------------------------|:------------------|
| **Description**          | Shadow Copies deletion using operating systems utilities |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0040: Impact](https://attack.mitre.org/tactics/TA0040)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1070: Indicator Removal on Host](https://attack.mitre.org/techniques/T1070)</li><li>[T1490: Inhibit System Recovery](https://attack.mitre.org/techniques/T1490)</li><li>[T1551: None](https://attack.mitre.org/techniques/T1551)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1490: Inhibit System Recovery](../Triggers/T1490.md)</li><li>[T1551: None](../Triggers/T1551.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Legitimate Administrator deletes Shadow Copies using operating systems utilities for legitimate reason</li></ul>  |
| **Development Status**   | stable |
| **References**           | <ul><li>[https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment](https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment)</li><li>[https://blog.talosintelligence.com/2017/05/wannacry.html](https://blog.talosintelligence.com/2017/05/wannacry.html)</li><li>[https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/new-teslacrypt-ransomware-arrives-via-spam/](https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/new-teslacrypt-ransomware-arrives-via-spam/)</li><li>[https://www.bleepingcomputer.com/news/security/why-everyone-should-disable-vssadmin-exe-now/](https://www.bleepingcomputer.com/news/security/why-everyone-should-disable-vssadmin-exe-now/)</li><li>[https://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa?environmentId=100](https://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa?environmentId=100)</li></ul>  |
| **Author**               | Florian Roth, Michael Haag, Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community |


## Detection Rules

### Sigma rule

```
title: Shadow Copies Deletion Using Operating Systems Utilities
id: c947b146-0abc-4c87-9c64-b17e9d7274a2
status: stable
description: Shadow Copies deletion using operating systems utilities
author: Florian Roth, Michael Haag, Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community
date: 2019/10/22
references:
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
    - https://blog.talosintelligence.com/2017/05/wannacry.html
    - https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/new-teslacrypt-ransomware-arrives-via-spam/
    - https://www.bleepingcomputer.com/news/security/why-everyone-should-disable-vssadmin-exe-now/
    - https://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa?environmentId=100
tags:
    - attack.defense_evasion
    - attack.impact
    - attack.t1070
    - attack.t1490
    - attack.t1551
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\powershell.exe'
            - '\wmic.exe'
            - '\vssadmin.exe'
        CommandLine|contains|all:
            - shadow  # will mach "delete shadows" and "shadowcopy delete"
            - delete
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Legitimate Administrator deletes Shadow Copies using operating systems utilities for legitimate reason
level: critical

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\\powershell.exe" -or $_.message -match "Image.*.*\\wmic.exe" -or $_.message -match "Image.*.*\\vssadmin.exe") -and $_.message -match "CommandLine.*.*shadow.*" -and $_.message -match "CommandLine.*.*delete.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:(*\\powershell.exe OR *\\wmic.exe OR *\\vssadmin.exe) AND winlog.event_data.CommandLine.keyword:*shadow* AND winlog.event_data.CommandLine.keyword:*delete*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/c947b146-0abc-4c87-9c64-b17e9d7274a2 <<EOF
{
  "metadata": {
    "title": "Shadow Copies Deletion Using Operating Systems Utilities",
    "description": "Shadow Copies deletion using operating systems utilities",
    "tags": [
      "attack.defense_evasion",
      "attack.impact",
      "attack.t1070",
      "attack.t1490",
      "attack.t1551"
    ],
    "query": "(winlog.event_data.Image.keyword:(*\\\\powershell.exe OR *\\\\wmic.exe OR *\\\\vssadmin.exe) AND winlog.event_data.CommandLine.keyword:*shadow* AND winlog.event_data.CommandLine.keyword:*delete*)"
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
                    "query": "(winlog.event_data.Image.keyword:(*\\\\powershell.exe OR *\\\\wmic.exe OR *\\\\vssadmin.exe) AND winlog.event_data.CommandLine.keyword:*shadow* AND winlog.event_data.CommandLine.keyword:*delete*)",
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
        "subject": "Sigma Rule 'Shadow Copies Deletion Using Operating Systems Utilities'",
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
(Image.keyword:(*\\powershell.exe *\\wmic.exe *\\vssadmin.exe) AND CommandLine.keyword:*shadow* AND CommandLine.keyword:*delete*)
```


### splunk
    
```
((Image="*\\powershell.exe" OR Image="*\\wmic.exe" OR Image="*\\vssadmin.exe") CommandLine="*shadow*" CommandLine="*delete*") | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(event_id="1" Image IN ["*\\powershell.exe", "*\\wmic.exe", "*\\vssadmin.exe"] CommandLine="*shadow*" CommandLine="*delete*")
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\powershell\.exe|.*.*\wmic\.exe|.*.*\vssadmin\.exe))(?=.*.*shadow.*)(?=.*.*delete.*))'
```



