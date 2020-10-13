| Title                    | Default PowerSploit and Empire Schtasks Persistence       |
|:-------------------------|:------------------|
| **Description**          | Detects the creation of a schtask via PowerSploit or Empire Default Configuration. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1053: Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)</li><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li><li>[T1053.005: Scheduled Task](https://attack.mitre.org/techniques/T1053/005)</li><li>[T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1053.005: Scheduled Task](../Triggers/T1053.005.md)</li><li>[T1059.001: PowerShell](../Triggers/T1059.001.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>False positives are possible, depends on organisation and processes</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/0xdeadbeefJERKY/PowerSploit/blob/8690399ef70d2cad10213575ac67e8fa90ddf7c3/Persistence/Persistence.psm1](https://github.com/0xdeadbeefJERKY/PowerSploit/blob/8690399ef70d2cad10213575ac67e8fa90ddf7c3/Persistence/Persistence.psm1)</li><li>[https://github.com/EmpireProject/Empire/blob/master/lib/modules/powershell/persistence/userland/schtasks.py](https://github.com/EmpireProject/Empire/blob/master/lib/modules/powershell/persistence/userland/schtasks.py)</li><li>[https://github.com/EmpireProject/Empire/blob/master/lib/modules/powershell/persistence/elevated/schtasks.py](https://github.com/EmpireProject/Empire/blob/master/lib/modules/powershell/persistence/elevated/schtasks.py)</li></ul>  |
| **Author**               | Markus Neis, @Karneades |
| Other Tags           | <ul><li>attack.s0111</li><li>attack.g0022</li><li>attack.g0060</li><li>car.2013-08-001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Default PowerSploit and Empire Schtasks Persistence
id: 56c217c3-2de2-479b-990f-5c109ba8458f
status: experimental
description: Detects the creation of a schtask via PowerSploit or Empire Default Configuration.
references:
    - https://github.com/0xdeadbeefJERKY/PowerSploit/blob/8690399ef70d2cad10213575ac67e8fa90ddf7c3/Persistence/Persistence.psm1
    - https://github.com/EmpireProject/Empire/blob/master/lib/modules/powershell/persistence/userland/schtasks.py
    - https://github.com/EmpireProject/Empire/blob/master/lib/modules/powershell/persistence/elevated/schtasks.py
author: Markus Neis, @Karneades
date: 2018/03/06
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage:
            - '*\powershell.exe'
        CommandLine:
            - '*schtasks*/Create*/SC *ONLOGON*/TN *Updater*/TR *powershell*'
            - '*schtasks*/Create*/SC *DAILY*/TN *Updater*/TR *powershell*'
            - '*schtasks*/Create*/SC *ONIDLE*/TN *Updater*/TR *powershell*'
            - '*schtasks*/Create*/SC *Updater*/TN *Updater*/TR *powershell*'
    condition: selection
tags:
    - attack.execution
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1053 # an old one
    - attack.t1086 # an old one
    - attack.s0111
    - attack.g0022
    - attack.g0060
    - car.2013-08-001
    - attack.t1053.005
    - attack.t1059.001
falsepositives:
    - False positives are possible, depends on organisation and processes
level: high

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "ParentImage.*.*\\powershell.exe") -and ($_.message -match "CommandLine.*.*schtasks.*/Create.*/SC .*ONLOGON.*/TN .*Updater.*/TR .*powershell.*" -or $_.message -match "CommandLine.*.*schtasks.*/Create.*/SC .*DAILY.*/TN .*Updater.*/TR .*powershell.*" -or $_.message -match "CommandLine.*.*schtasks.*/Create.*/SC .*ONIDLE.*/TN .*Updater.*/TR .*powershell.*" -or $_.message -match "CommandLine.*.*schtasks.*/Create.*/SC .*Updater.*/TN .*Updater.*/TR .*powershell.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.ParentImage.keyword:(*\\powershell.exe) AND winlog.event_data.CommandLine.keyword:(*schtasks*\/Create*\/SC\ *ONLOGON*\/TN\ *Updater*\/TR\ *powershell* OR *schtasks*\/Create*\/SC\ *DAILY*\/TN\ *Updater*\/TR\ *powershell* OR *schtasks*\/Create*\/SC\ *ONIDLE*\/TN\ *Updater*\/TR\ *powershell* OR *schtasks*\/Create*\/SC\ *Updater*\/TN\ *Updater*\/TR\ *powershell*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/56c217c3-2de2-479b-990f-5c109ba8458f <<EOF
{
  "metadata": {
    "title": "Default PowerSploit and Empire Schtasks Persistence",
    "description": "Detects the creation of a schtask via PowerSploit or Empire Default Configuration.",
    "tags": [
      "attack.execution",
      "attack.persistence",
      "attack.privilege_escalation",
      "attack.t1053",
      "attack.t1086",
      "attack.s0111",
      "attack.g0022",
      "attack.g0060",
      "car.2013-08-001",
      "attack.t1053.005",
      "attack.t1059.001"
    ],
    "query": "(winlog.event_data.ParentImage.keyword:(*\\\\powershell.exe) AND winlog.event_data.CommandLine.keyword:(*schtasks*\\/Create*\\/SC\\ *ONLOGON*\\/TN\\ *Updater*\\/TR\\ *powershell* OR *schtasks*\\/Create*\\/SC\\ *DAILY*\\/TN\\ *Updater*\\/TR\\ *powershell* OR *schtasks*\\/Create*\\/SC\\ *ONIDLE*\\/TN\\ *Updater*\\/TR\\ *powershell* OR *schtasks*\\/Create*\\/SC\\ *Updater*\\/TN\\ *Updater*\\/TR\\ *powershell*))"
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
                    "query": "(winlog.event_data.ParentImage.keyword:(*\\\\powershell.exe) AND winlog.event_data.CommandLine.keyword:(*schtasks*\\/Create*\\/SC\\ *ONLOGON*\\/TN\\ *Updater*\\/TR\\ *powershell* OR *schtasks*\\/Create*\\/SC\\ *DAILY*\\/TN\\ *Updater*\\/TR\\ *powershell* OR *schtasks*\\/Create*\\/SC\\ *ONIDLE*\\/TN\\ *Updater*\\/TR\\ *powershell* OR *schtasks*\\/Create*\\/SC\\ *Updater*\\/TN\\ *Updater*\\/TR\\ *powershell*))",
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
        "subject": "Sigma Rule 'Default PowerSploit and Empire Schtasks Persistence'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}{{_source}}\n================================================================================\n{{/ctx.payload.hits.hits}}",
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
(ParentImage.keyword:(*\\powershell.exe) AND CommandLine.keyword:(*schtasks*\/Create*\/SC *ONLOGON*\/TN *Updater*\/TR *powershell* *schtasks*\/Create*\/SC *DAILY*\/TN *Updater*\/TR *powershell* *schtasks*\/Create*\/SC *ONIDLE*\/TN *Updater*\/TR *powershell* *schtasks*\/Create*\/SC *Updater*\/TN *Updater*\/TR *powershell*))
```


### splunk
    
```
((ParentImage="*\\powershell.exe") (CommandLine="*schtasks*/Create*/SC *ONLOGON*/TN *Updater*/TR *powershell*" OR CommandLine="*schtasks*/Create*/SC *DAILY*/TN *Updater*/TR *powershell*" OR CommandLine="*schtasks*/Create*/SC *ONIDLE*/TN *Updater*/TR *powershell*" OR CommandLine="*schtasks*/Create*/SC *Updater*/TN *Updater*/TR *powershell*"))
```


### logpoint
    
```
(ParentImage IN ["*\\powershell.exe"] CommandLine IN ["*schtasks*/Create*/SC *ONLOGON*/TN *Updater*/TR *powershell*", "*schtasks*/Create*/SC *DAILY*/TN *Updater*/TR *powershell*", "*schtasks*/Create*/SC *ONIDLE*/TN *Updater*/TR *powershell*", "*schtasks*/Create*/SC *Updater*/TN *Updater*/TR *powershell*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\powershell\.exe))(?=.*(?:.*.*schtasks.*/Create.*/SC .*ONLOGON.*/TN .*Updater.*/TR .*powershell.*|.*.*schtasks.*/Create.*/SC .*DAILY.*/TN .*Updater.*/TR .*powershell.*|.*.*schtasks.*/Create.*/SC .*ONIDLE.*/TN .*Updater.*/TR .*powershell.*|.*.*schtasks.*/Create.*/SC .*Updater.*/TN .*Updater.*/TR .*powershell.*)))'
```



