| Title                    | Suspicious Driver Loaded By User       |
|:-------------------------|:------------------|
| **Description**          | Detects the loading of drivers via 'SeLoadDriverPrivilege' required to load or unload a device driver. With this privilege, the user can dynamically load and unload device drivers or other code in to kernel mode. This user right does not apply to Plug and Play device drivers. If you exclude privileged users/admins and processes, which are allowed to do so, you are maybe left with bad programs trying to load malicious kernel drivers. This will detect Ghost-In-The-Logs (https://github.com/bats3c/Ghost-In-The-Logs) and the usage of Sysinternals and various other tools. So you have to work with a whitelist to find the bad stuff. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1089: Disabling Security Tools](https://attack.mitre.org/techniques/T1089)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1089: Disabling Security Tools](../Triggers/T1089.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>{'Other legimate tools loading drivers. There are some': 'Sysinternals, CPU-Z, AVs etc. - but not much. You have to baseline this according to your used products and allowed tools. Also try to exclude users, which are allowed to load drivers.'}</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://blog.dylan.codes/evading-sysmon-and-windows-event-logging/](https://blog.dylan.codes/evading-sysmon-and-windows-event-logging/)</li><li>[https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4673](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4673)</li></ul>  |
| **Author**               | xknow (@xknow_infosec), xorxes (@xor_xes) |


## Detection Rules

### Sigma rule

```
title: Suspicious Driver Loaded By User
id: f63508a0-c809-4435-b3be-ed819394d612
description: Detects the loading of drivers via 'SeLoadDriverPrivilege' required to load or unload a device driver. With this privilege, the user can dynamically load and unload device drivers or other code in to kernel mode. This user right does not apply to Plug and Play device drivers. If you exclude privileged users/admins and processes, which are allowed to do so, you are maybe left with bad programs trying to load malicious kernel drivers. This will detect Ghost-In-The-Logs (https://github.com/bats3c/Ghost-In-The-Logs) and the usage of Sysinternals and various other tools. So you have to work with a whitelist to find the bad stuff.
status: experimental
references:
    - https://blog.dylan.codes/evading-sysmon-and-windows-event-logging/
    - https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4673
tags:
    - attack.t1089
    - attack.defense_evasion
date: 2019/04/08
author: xknow (@xknow_infosec), xorxes (@xor_xes)
logsource:
    product: windows
    service: security
detection:
    selection_1:
        EventID: 4673
        PrivilegeList: 'SeLoadDriverPrivilege'
        Service: '-'
    selection_2:
        ProcessName|contains:
            - '*\Windows\System32\Dism.exe'
            - '*\Windows\System32\rundll32.exe'
            - '*\Windows\System32\fltMC.exe'
            - '*\Windows\HelpPane.exe'
            - '*\Windows\System32\mmc.exe'
            - '*\Windows\System32\svchost.exe'
            - '*\Windows\System32\wimserv.exe'
            - '*\procexp64.exe'
            - '*\procexp.exe'
            - '*\procmon64.exe'
            - '*\procmon.exe'
    condition: selection_1 and not selection_2
falsepositives:
    - Other legimate tools loading drivers. There are some: Sysinternals, CPU-Z, AVs etc. - but not much. You have to baseline this according to your used products and allowed tools. Also try to exclude users, which are allowed to load drivers.
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Security | where {(($_.ID -eq "4673" -and $_.message -match "PrivilegeList.*SeLoadDriverPrivilege" -and $_.message -match "Service.*-") -and  -not (($_.message -match "ProcessName.*.*\\Windows\\System32\\Dism.exe.*" -or $_.message -match "ProcessName.*.*\\Windows\\System32\\rundll32.exe.*" -or $_.message -match "ProcessName.*.*\\Windows\\System32\\fltMC.exe.*" -or $_.message -match "ProcessName.*.*\\Windows\\HelpPane.exe.*" -or $_.message -match "ProcessName.*.*\\Windows\\System32\\mmc.exe.*" -or $_.message -match "ProcessName.*.*\\Windows\\System32\\svchost.exe.*" -or $_.message -match "ProcessName.*.*\\Windows\\System32\\wimserv.exe.*" -or $_.message -match "ProcessName.*.*\\procexp64.exe.*" -or $_.message -match "ProcessName.*.*\\procexp.exe.*" -or $_.message -match "ProcessName.*.*\\procmon64.exe.*" -or $_.message -match "ProcessName.*.*\\procmon.exe.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND (winlog.event_id:"4673" AND PrivilegeList:"SeLoadDriverPrivilege" AND Service:"\-") AND (NOT (winlog.event_data.ProcessName.keyword:(*\\Windows\\System32\\Dism.exe* OR *\\Windows\\System32\\rundll32.exe* OR *\\Windows\\System32\\fltMC.exe* OR *\\Windows\\HelpPane.exe* OR *\\Windows\\System32\\mmc.exe* OR *\\Windows\\System32\\svchost.exe* OR *\\Windows\\System32\\wimserv.exe* OR *\\procexp64.exe* OR *\\procexp.exe* OR *\\procmon64.exe* OR *\\procmon.exe*))))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/f63508a0-c809-4435-b3be-ed819394d612 <<EOF
{
  "metadata": {
    "title": "Suspicious Driver Loaded By User",
    "description": "Detects the loading of drivers via 'SeLoadDriverPrivilege' required to load or unload a device driver. With this privilege, the user can dynamically load and unload device drivers or other code in to kernel mode. This user right does not apply to Plug and Play device drivers. If you exclude privileged users/admins and processes, which are allowed to do so, you are maybe left with bad programs trying to load malicious kernel drivers. This will detect Ghost-In-The-Logs (https://github.com/bats3c/Ghost-In-The-Logs) and the usage of Sysinternals and various other tools. So you have to work with a whitelist to find the bad stuff.",
    "tags": [
      "attack.t1089",
      "attack.defense_evasion"
    ],
    "query": "(winlog.channel:\"Security\" AND (winlog.event_id:\"4673\" AND PrivilegeList:\"SeLoadDriverPrivilege\" AND Service:\"\\-\") AND (NOT (winlog.event_data.ProcessName.keyword:(*\\\\Windows\\\\System32\\\\Dism.exe* OR *\\\\Windows\\\\System32\\\\rundll32.exe* OR *\\\\Windows\\\\System32\\\\fltMC.exe* OR *\\\\Windows\\\\HelpPane.exe* OR *\\\\Windows\\\\System32\\\\mmc.exe* OR *\\\\Windows\\\\System32\\\\svchost.exe* OR *\\\\Windows\\\\System32\\\\wimserv.exe* OR *\\\\procexp64.exe* OR *\\\\procexp.exe* OR *\\\\procmon64.exe* OR *\\\\procmon.exe*))))"
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
                    "query": "(winlog.channel:\"Security\" AND (winlog.event_id:\"4673\" AND PrivilegeList:\"SeLoadDriverPrivilege\" AND Service:\"\\-\") AND (NOT (winlog.event_data.ProcessName.keyword:(*\\\\Windows\\\\System32\\\\Dism.exe* OR *\\\\Windows\\\\System32\\\\rundll32.exe* OR *\\\\Windows\\\\System32\\\\fltMC.exe* OR *\\\\Windows\\\\HelpPane.exe* OR *\\\\Windows\\\\System32\\\\mmc.exe* OR *\\\\Windows\\\\System32\\\\svchost.exe* OR *\\\\Windows\\\\System32\\\\wimserv.exe* OR *\\\\procexp64.exe* OR *\\\\procexp.exe* OR *\\\\procmon64.exe* OR *\\\\procmon.exe*))))",
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
        "subject": "Sigma Rule 'Suspicious Driver Loaded By User'",
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
((EventID:"4673" AND PrivilegeList:"SeLoadDriverPrivilege" AND Service:"\-") AND (NOT (ProcessName.keyword:(*\\Windows\\System32\\Dism.exe* *\\Windows\\System32\\rundll32.exe* *\\Windows\\System32\\fltMC.exe* *\\Windows\\HelpPane.exe* *\\Windows\\System32\\mmc.exe* *\\Windows\\System32\\svchost.exe* *\\Windows\\System32\\wimserv.exe* *\\procexp64.exe* *\\procexp.exe* *\\procmon64.exe* *\\procmon.exe*))))
```


### splunk
    
```
(source="WinEventLog:Security" (EventCode="4673" PrivilegeList="SeLoadDriverPrivilege" Service="-") NOT ((ProcessName="*\\Windows\\System32\\Dism.exe*" OR ProcessName="*\\Windows\\System32\\rundll32.exe*" OR ProcessName="*\\Windows\\System32\\fltMC.exe*" OR ProcessName="*\\Windows\\HelpPane.exe*" OR ProcessName="*\\Windows\\System32\\mmc.exe*" OR ProcessName="*\\Windows\\System32\\svchost.exe*" OR ProcessName="*\\Windows\\System32\\wimserv.exe*" OR ProcessName="*\\procexp64.exe*" OR ProcessName="*\\procexp.exe*" OR ProcessName="*\\procmon64.exe*" OR ProcessName="*\\procmon.exe*")))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" (event_id="4673" PrivilegeList="SeLoadDriverPrivilege" Service="-")  -(ProcessName IN ["*\\Windows\\System32\\Dism.exe*", "*\\Windows\\System32\\rundll32.exe*", "*\\Windows\\System32\\fltMC.exe*", "*\\Windows\\HelpPane.exe*", "*\\Windows\\System32\\mmc.exe*", "*\\Windows\\System32\\svchost.exe*", "*\\Windows\\System32\\wimserv.exe*", "*\\procexp64.exe*", "*\\procexp.exe*", "*\\procmon64.exe*", "*\\procmon.exe*"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*4673)(?=.*SeLoadDriverPrivilege)(?=.*-)))(?=.*(?!.*(?:.*(?=.*(?:.*.*\Windows\System32\Dism\.exe.*|.*.*\Windows\System32\rundll32\.exe.*|.*.*\Windows\System32\fltMC\.exe.*|.*.*\Windows\HelpPane\.exe.*|.*.*\Windows\System32\mmc\.exe.*|.*.*\Windows\System32\svchost\.exe.*|.*.*\Windows\System32\wimserv\.exe.*|.*.*\procexp64\.exe.*|.*.*\procexp\.exe.*|.*.*\procmon64\.exe.*|.*.*\procmon\.exe.*))))))'
```



