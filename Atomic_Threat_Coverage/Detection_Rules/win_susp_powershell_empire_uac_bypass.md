| Title                    | Empire PowerShell UAC Bypass       |
|:-------------------------|:------------------|
| **Description**          | Detects some Empire PowerShell UAC bypass methods |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1088: Bypass User Account Control](https://attack.mitre.org/techniques/T1088)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-EventVwrBypass.ps1#L64](https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-EventVwrBypass.ps1#L64)</li><li>[https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-FodHelperBypass.ps1#L64](https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-FodHelperBypass.ps1#L64)</li></ul>  |
| **Author**               | Ecco |
| Other Tags           | <ul><li>car.2019-04-001</li><li>attack.t1548.002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Empire PowerShell UAC Bypass
id: 3268b746-88d8-4cd3-bffc-30077d02c787
status: experimental
description: Detects some Empire PowerShell UAC bypass methods
references:
    - https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-EventVwrBypass.ps1#L64
    - https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-FodHelperBypass.ps1#L64
author: Ecco
date: 2019/08/30
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '* -NoP -NonI -w Hidden -c $x=$((gp HKCU:Software\\Microsoft\\Windows Update).Update)*'
            - '* -NoP -NonI -c $x=$((gp HKCU:Software\\Microsoft\\Windows Update).Update);*'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1088
    - car.2019-04-001
    - attack.t1548.002
falsepositives:
    - unknown
level: critical

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.* -NoP -NonI -w Hidden -c $x=$((gp HKCU:Software\\Microsoft\\Windows Update).Update).*" -or $_.message -match "CommandLine.*.* -NoP -NonI -c $x=$((gp HKCU:Software\\Microsoft\\Windows Update).Update);.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(*\ \-NoP\ \-NonI\ \-w\ Hidden\ \-c\ $x\=$\(\(gp\ HKCU\:Software\\Microsoft\\Windows\ Update\).Update\)* OR *\ \-NoP\ \-NonI\ \-c\ $x\=$\(\(gp\ HKCU\:Software\\Microsoft\\Windows\ Update\).Update\);*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/3268b746-88d8-4cd3-bffc-30077d02c787 <<EOF
{
  "metadata": {
    "title": "Empire PowerShell UAC Bypass",
    "description": "Detects some Empire PowerShell UAC bypass methods",
    "tags": [
      "attack.defense_evasion",
      "attack.privilege_escalation",
      "attack.t1088",
      "car.2019-04-001",
      "attack.t1548.002"
    ],
    "query": "winlog.event_data.CommandLine.keyword:(*\\ \\-NoP\\ \\-NonI\\ \\-w\\ Hidden\\ \\-c\\ $x\\=$\\(\\(gp\\ HKCU\\:Software\\\\Microsoft\\\\Windows\\ Update\\).Update\\)* OR *\\ \\-NoP\\ \\-NonI\\ \\-c\\ $x\\=$\\(\\(gp\\ HKCU\\:Software\\\\Microsoft\\\\Windows\\ Update\\).Update\\);*)"
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
                    "query": "winlog.event_data.CommandLine.keyword:(*\\ \\-NoP\\ \\-NonI\\ \\-w\\ Hidden\\ \\-c\\ $x\\=$\\(\\(gp\\ HKCU\\:Software\\\\Microsoft\\\\Windows\\ Update\\).Update\\)* OR *\\ \\-NoP\\ \\-NonI\\ \\-c\\ $x\\=$\\(\\(gp\\ HKCU\\:Software\\\\Microsoft\\\\Windows\\ Update\\).Update\\);*)",
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
        "subject": "Sigma Rule 'Empire PowerShell UAC Bypass'",
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
CommandLine.keyword:(* \-NoP \-NonI \-w Hidden \-c $x=$\(\(gp HKCU\:Software\\Microsoft\\Windows Update\).Update\)* * \-NoP \-NonI \-c $x=$\(\(gp HKCU\:Software\\Microsoft\\Windows Update\).Update\);*)
```


### splunk
    
```
(CommandLine="* -NoP -NonI -w Hidden -c $x=$((gp HKCU:Software\\Microsoft\\Windows Update).Update)*" OR CommandLine="* -NoP -NonI -c $x=$((gp HKCU:Software\\Microsoft\\Windows Update).Update);*") | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(event_id="1" CommandLine IN ["* -NoP -NonI -w Hidden -c $x=$((gp HKCU:Software\\Microsoft\\Windows Update).Update)*", "* -NoP -NonI -c $x=$((gp HKCU:Software\\Microsoft\\Windows Update).Update);*"])
```


### grep
    
```
grep -P '^(?:.*.* -NoP -NonI -w Hidden -c \$x=\$\(\(gp HKCU:Software\\Microsoft\\Windows Update\)\.Update\).*|.*.* -NoP -NonI -c \$x=\$\(\(gp HKCU:Software\\Microsoft\\Windows Update\)\.Update\);.*)'
```



