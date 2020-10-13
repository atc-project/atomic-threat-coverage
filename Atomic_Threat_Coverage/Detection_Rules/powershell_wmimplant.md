| Title                    | WMImplant Hack Tool       |
|:-------------------------|:------------------|
| **Description**          | Detects parameters used by WMImplant |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1047: Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047)</li><li>[T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001)</li><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0036_4104_windows_powershell_script_block](../Data_Needed/DN_0036_4104_windows_powershell_script_block.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1047: Windows Management Instrumentation](../Triggers/T1047.md)</li><li>[T1059.001: PowerShell](../Triggers/T1059.001.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Administrative scripts that use the same keywords.</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/FortyNorthSecurity/WMImplant](https://github.com/FortyNorthSecurity/WMImplant)</li></ul>  |
| **Author**               | NVISO |


## Detection Rules

### Sigma rule

```
title: WMImplant Hack Tool
id: 8028c2c3-e25a-46e3-827f-bbb5abf181d7
status: experimental
description: Detects parameters used by WMImplant
references:
  - https://github.com/FortyNorthSecurity/WMImplant
tags:
  - attack.execution
  - attack.t1047
  - attack.t1059.001
  - attack.t1086  #an old one
author: NVISO
date: 2020/03/26
logsource:
  product: windows
  service: powershell
  definition: "Script block logging must be enabled"
detection:
  selection:
    ScriptBlockText|contains:
      - "WMImplant"
      - " change_user "
      - " gen_cli "
      - " command_exec "
      - " disable_wdigest "
      - " disable_winrm "
      - " enable_wdigest "
      - " enable_winrm "
      - " registry_mod "
      - " remote_posh "
      - " sched_job "
      - " service_mod "
      - " process_kill "
      # - " process_start "
      - " active_users "
      - " basic_info "
      # - " drive_list "
      # - " installed_programs "
      - " power_off "
      - " vacant_system "
      - " logon_events "
  condition: selection
falsepositives:
  - Administrative scripts that use the same keywords.
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {(($_.message -match "ScriptBlockText.*.*WMImplant.*" -or $_.message -match "ScriptBlockText.*.* change_user .*" -or $_.message -match "ScriptBlockText.*.* gen_cli .*" -or $_.message -match "ScriptBlockText.*.* command_exec .*" -or $_.message -match "ScriptBlockText.*.* disable_wdigest .*" -or $_.message -match "ScriptBlockText.*.* disable_winrm .*" -or $_.message -match "ScriptBlockText.*.* enable_wdigest .*" -or $_.message -match "ScriptBlockText.*.* enable_winrm .*" -or $_.message -match "ScriptBlockText.*.* registry_mod .*" -or $_.message -match "ScriptBlockText.*.* remote_posh .*" -or $_.message -match "ScriptBlockText.*.* sched_job .*" -or $_.message -match "ScriptBlockText.*.* service_mod .*" -or $_.message -match "ScriptBlockText.*.* process_kill .*" -or $_.message -match "ScriptBlockText.*.* active_users .*" -or $_.message -match "ScriptBlockText.*.* basic_info .*" -or $_.message -match "ScriptBlockText.*.* power_off .*" -or $_.message -match "ScriptBlockText.*.* vacant_system .*" -or $_.message -match "ScriptBlockText.*.* logon_events .*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
ScriptBlockText.keyword:(*WMImplant* OR *\ change_user\ * OR *\ gen_cli\ * OR *\ command_exec\ * OR *\ disable_wdigest\ * OR *\ disable_winrm\ * OR *\ enable_wdigest\ * OR *\ enable_winrm\ * OR *\ registry_mod\ * OR *\ remote_posh\ * OR *\ sched_job\ * OR *\ service_mod\ * OR *\ process_kill\ * OR *\ active_users\ * OR *\ basic_info\ * OR *\ power_off\ * OR *\ vacant_system\ * OR *\ logon_events\ *)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/8028c2c3-e25a-46e3-827f-bbb5abf181d7 <<EOF
{
  "metadata": {
    "title": "WMImplant Hack Tool",
    "description": "Detects parameters used by WMImplant",
    "tags": [
      "attack.execution",
      "attack.t1047",
      "attack.t1059.001",
      "attack.t1086"
    ],
    "query": "ScriptBlockText.keyword:(*WMImplant* OR *\\ change_user\\ * OR *\\ gen_cli\\ * OR *\\ command_exec\\ * OR *\\ disable_wdigest\\ * OR *\\ disable_winrm\\ * OR *\\ enable_wdigest\\ * OR *\\ enable_winrm\\ * OR *\\ registry_mod\\ * OR *\\ remote_posh\\ * OR *\\ sched_job\\ * OR *\\ service_mod\\ * OR *\\ process_kill\\ * OR *\\ active_users\\ * OR *\\ basic_info\\ * OR *\\ power_off\\ * OR *\\ vacant_system\\ * OR *\\ logon_events\\ *)"
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
                    "query": "ScriptBlockText.keyword:(*WMImplant* OR *\\ change_user\\ * OR *\\ gen_cli\\ * OR *\\ command_exec\\ * OR *\\ disable_wdigest\\ * OR *\\ disable_winrm\\ * OR *\\ enable_wdigest\\ * OR *\\ enable_winrm\\ * OR *\\ registry_mod\\ * OR *\\ remote_posh\\ * OR *\\ sched_job\\ * OR *\\ service_mod\\ * OR *\\ process_kill\\ * OR *\\ active_users\\ * OR *\\ basic_info\\ * OR *\\ power_off\\ * OR *\\ vacant_system\\ * OR *\\ logon_events\\ *)",
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
        "subject": "Sigma Rule 'WMImplant Hack Tool'",
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
ScriptBlockText.keyword:(*WMImplant* * change_user * * gen_cli * * command_exec * * disable_wdigest * * disable_winrm * * enable_wdigest * * enable_winrm * * registry_mod * * remote_posh * * sched_job * * service_mod * * process_kill * * active_users * * basic_info * * power_off * * vacant_system * * logon_events *)
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-PowerShell/Operational" (ScriptBlockText="*WMImplant*" OR ScriptBlockText="* change_user *" OR ScriptBlockText="* gen_cli *" OR ScriptBlockText="* command_exec *" OR ScriptBlockText="* disable_wdigest *" OR ScriptBlockText="* disable_winrm *" OR ScriptBlockText="* enable_wdigest *" OR ScriptBlockText="* enable_winrm *" OR ScriptBlockText="* registry_mod *" OR ScriptBlockText="* remote_posh *" OR ScriptBlockText="* sched_job *" OR ScriptBlockText="* service_mod *" OR ScriptBlockText="* process_kill *" OR ScriptBlockText="* active_users *" OR ScriptBlockText="* basic_info *" OR ScriptBlockText="* power_off *" OR ScriptBlockText="* vacant_system *" OR ScriptBlockText="* logon_events *"))
```


### logpoint
    
```
ScriptBlockText IN ["*WMImplant*", "* change_user *", "* gen_cli *", "* command_exec *", "* disable_wdigest *", "* disable_winrm *", "* enable_wdigest *", "* enable_winrm *", "* registry_mod *", "* remote_posh *", "* sched_job *", "* service_mod *", "* process_kill *", "* active_users *", "* basic_info *", "* power_off *", "* vacant_system *", "* logon_events *"]
```


### grep
    
```
grep -P '^(?:.*.*WMImplant.*|.*.* change_user .*|.*.* gen_cli .*|.*.* command_exec .*|.*.* disable_wdigest .*|.*.* disable_winrm .*|.*.* enable_wdigest .*|.*.* enable_winrm .*|.*.* registry_mod .*|.*.* remote_posh .*|.*.* sched_job .*|.*.* service_mod .*|.*.* process_kill .*|.*.* active_users .*|.*.* basic_info .*|.*.* power_off .*|.*.* vacant_system .*|.*.* logon_events .*)'
```



