| Title                    | Suspicious Service Installed       |
|:-------------------------|:------------------|
| **Description**          | Detects installation of NalDrv or PROCEXP152 services via registry-keys to non-system32 folders. Both services are used in the tool Ghost-In-The-Logs (https://github.com/bats3c/Ghost-In-The-Logs), which uses KDU (https://github.com/hfiref0x/KDU) |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1089: Disabling Security Tools](https://attack.mitre.org/techniques/T1089)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1089: Disabling Security Tools](../Triggers/T1089.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Other legimate tools using this service names and drivers. Note - clever attackers may easily bypass this detection by just renaming the services. Therefore just Medium-level and don't rely on it.</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://blog.dylan.codes/evading-sysmon-and-windows-event-logging/](https://blog.dylan.codes/evading-sysmon-and-windows-event-logging/)</li></ul>  |
| **Author**               | xknow (@xknow_infosec), xorxes (@xor_xes) |


## Detection Rules

### Sigma rule

```
title: Suspicious Service Installed
id: f2485272-a156-4773-82d7-1d178bc4905b
description: Detects installation of NalDrv or PROCEXP152 services via registry-keys to non-system32 folders. Both services are used in the tool Ghost-In-The-Logs (https://github.com/bats3c/Ghost-In-The-Logs), which uses KDU (https://github.com/hfiref0x/KDU)
status: experimental
date: 2019/04/08
author: xknow (@xknow_infosec), xorxes (@xor_xes)
references:
    - https://blog.dylan.codes/evading-sysmon-and-windows-event-logging/
tags:
    - attack.t1089
    - attack.defense_evasion
logsource:
    product: windows
    service: sysmon
detection:
    selection_1:
        EventID: 13
        TargetObject:
            - 'HKLM\System\CurrentControlSet\Services\NalDrv\ImagePath'
            - 'HKLM\System\CurrentControlSet\Services\PROCEXP152\ImagePath'
    selection_2:
        Image|contains:
            - '*\procexp64.exe'
            - '*\procexp.exe'
            - '*\procmon64.exe'
            - '*\procmon.exe'
    selection_3:
        Details|contains:
            - '*\WINDOWS\system32\Drivers\PROCEXP152.SYS'
    condition: selection_1 and not selection_2 and not selection_3
falsepositives:
    - Other legimate tools using this service names and drivers. Note - clever attackers may easily bypass this detection by just renaming the services. Therefore just Medium-level and don't rely on it.
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "13" -and ($_.message -match "HKLM\\System\\CurrentControlSet\\Services\\NalDrv\\ImagePath" -or $_.message -match "HKLM\\System\\CurrentControlSet\\Services\\PROCEXP152\\ImagePath")) -and  -not (($_.message -match "Image.*.*\\procexp64.exe.*" -or $_.message -match "Image.*.*\\procexp.exe.*" -or $_.message -match "Image.*.*\\procmon64.exe.*" -or $_.message -match "Image.*.*\\procmon.exe.*"))) -and  -not (($_.message -match "Details.*.*\\WINDOWS\\system32\\Drivers\\PROCEXP152.SYS.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND ((winlog.event_id:"13" AND winlog.event_data.TargetObject:("HKLM\\System\\CurrentControlSet\\Services\\NalDrv\\ImagePath" OR "HKLM\\System\\CurrentControlSet\\Services\\PROCEXP152\\ImagePath")) AND (NOT (winlog.event_data.Image.keyword:(*\\procexp64.exe* OR *\\procexp.exe* OR *\\procmon64.exe* OR *\\procmon.exe*)))) AND (NOT (winlog.event_data.Details.keyword:(*\\WINDOWS\\system32\\Drivers\\PROCEXP152.SYS*))))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/f2485272-a156-4773-82d7-1d178bc4905b <<EOF
{
  "metadata": {
    "title": "Suspicious Service Installed",
    "description": "Detects installation of NalDrv or PROCEXP152 services via registry-keys to non-system32 folders. Both services are used in the tool Ghost-In-The-Logs (https://github.com/bats3c/Ghost-In-The-Logs), which uses KDU (https://github.com/hfiref0x/KDU)",
    "tags": [
      "attack.t1089",
      "attack.defense_evasion"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND ((winlog.event_id:\"13\" AND winlog.event_data.TargetObject:(\"HKLM\\\\System\\\\CurrentControlSet\\\\Services\\\\NalDrv\\\\ImagePath\" OR \"HKLM\\\\System\\\\CurrentControlSet\\\\Services\\\\PROCEXP152\\\\ImagePath\")) AND (NOT (winlog.event_data.Image.keyword:(*\\\\procexp64.exe* OR *\\\\procexp.exe* OR *\\\\procmon64.exe* OR *\\\\procmon.exe*)))) AND (NOT (winlog.event_data.Details.keyword:(*\\\\WINDOWS\\\\system32\\\\Drivers\\\\PROCEXP152.SYS*))))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND ((winlog.event_id:\"13\" AND winlog.event_data.TargetObject:(\"HKLM\\\\System\\\\CurrentControlSet\\\\Services\\\\NalDrv\\\\ImagePath\" OR \"HKLM\\\\System\\\\CurrentControlSet\\\\Services\\\\PROCEXP152\\\\ImagePath\")) AND (NOT (winlog.event_data.Image.keyword:(*\\\\procexp64.exe* OR *\\\\procexp.exe* OR *\\\\procmon64.exe* OR *\\\\procmon.exe*)))) AND (NOT (winlog.event_data.Details.keyword:(*\\\\WINDOWS\\\\system32\\\\Drivers\\\\PROCEXP152.SYS*))))",
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
        "subject": "Sigma Rule 'Suspicious Service Installed'",
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
(((EventID:"13" AND TargetObject:("HKLM\\System\\CurrentControlSet\\Services\\NalDrv\\ImagePath" "HKLM\\System\\CurrentControlSet\\Services\\PROCEXP152\\ImagePath")) AND (NOT (Image.keyword:(*\\procexp64.exe* *\\procexp.exe* *\\procmon64.exe* *\\procmon.exe*)))) AND (NOT (Details.keyword:(*\\WINDOWS\\system32\\Drivers\\PROCEXP152.SYS*))))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" ((EventCode="13" (TargetObject="HKLM\\System\\CurrentControlSet\\Services\\NalDrv\\ImagePath" OR TargetObject="HKLM\\System\\CurrentControlSet\\Services\\PROCEXP152\\ImagePath")) NOT ((Image="*\\procexp64.exe*" OR Image="*\\procexp.exe*" OR Image="*\\procmon64.exe*" OR Image="*\\procmon.exe*"))) NOT ((Details="*\\WINDOWS\\system32\\Drivers\\PROCEXP152.SYS*")))
```


### logpoint
    
```
(((event_id="13" TargetObject IN ["HKLM\\System\\CurrentControlSet\\Services\\NalDrv\\ImagePath", "HKLM\\System\\CurrentControlSet\\Services\\PROCEXP152\\ImagePath"])  -(Image IN ["*\\procexp64.exe*", "*\\procexp.exe*", "*\\procmon64.exe*", "*\\procmon.exe*"]))  -(Details IN ["*\\WINDOWS\\system32\\Drivers\\PROCEXP152.SYS*"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*(?:.*(?=.*13)(?=.*(?:.*HKLM\System\CurrentControlSet\Services\NalDrv\ImagePath|.*HKLM\System\CurrentControlSet\Services\PROCEXP152\ImagePath))))(?=.*(?!.*(?:.*(?=.*(?:.*.*\procexp64\.exe.*|.*.*\procexp\.exe.*|.*.*\procmon64\.exe.*|.*.*\procmon\.exe.*)))))))(?=.*(?!.*(?:.*(?=.*(?:.*.*\WINDOWS\system32\Drivers\PROCEXP152\.SYS.*))))))'
```



