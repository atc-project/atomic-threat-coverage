| Title                    | WMImplant Hack Tool       |
|:-------------------------|:------------------|
| **Description**          | Detects parameters used by WMImplant |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1047: Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0036_4104_windows_powershell_script_block](../Data_Needed/DN_0036_4104_windows_powershell_script_block.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1047: Windows Management Instrumentation](../Triggers/T1047.md)</li></ul>  |
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
author: NVISO
date: 2020/03/26
logsource:
  product: windows
  service: powershell
  description: "Script block logging must be enabled"
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





### es-qs
    
```
ScriptBlockText.keyword:(*WMImplant* OR *\\ change_user\\ * OR *\\ gen_cli\\ * OR *\\ command_exec\\ * OR *\\ disable_wdigest\\ * OR *\\ disable_winrm\\ * OR *\\ enable_wdigest\\ * OR *\\ enable_winrm\\ * OR *\\ registry_mod\\ * OR *\\ remote_posh\\ * OR *\\ sched_job\\ * OR *\\ service_mod\\ * OR *\\ process_kill\\ * OR *\\ active_users\\ * OR *\\ basic_info\\ * OR *\\ power_off\\ * OR *\\ vacant_system\\ * OR *\\ logon_events\\ *)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/8028c2c3-e25a-46e3-827f-bbb5abf181d7 <<EOF\n{\n  "metadata": {\n    "title": "WMImplant Hack Tool",\n    "description": "Detects parameters used by WMImplant",\n    "tags": [\n      "attack.execution",\n      "attack.t1047"\n    ],\n    "query": "ScriptBlockText.keyword:(*WMImplant* OR *\\\\ change_user\\\\ * OR *\\\\ gen_cli\\\\ * OR *\\\\ command_exec\\\\ * OR *\\\\ disable_wdigest\\\\ * OR *\\\\ disable_winrm\\\\ * OR *\\\\ enable_wdigest\\\\ * OR *\\\\ enable_winrm\\\\ * OR *\\\\ registry_mod\\\\ * OR *\\\\ remote_posh\\\\ * OR *\\\\ sched_job\\\\ * OR *\\\\ service_mod\\\\ * OR *\\\\ process_kill\\\\ * OR *\\\\ active_users\\\\ * OR *\\\\ basic_info\\\\ * OR *\\\\ power_off\\\\ * OR *\\\\ vacant_system\\\\ * OR *\\\\ logon_events\\\\ *)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "ScriptBlockText.keyword:(*WMImplant* OR *\\\\ change_user\\\\ * OR *\\\\ gen_cli\\\\ * OR *\\\\ command_exec\\\\ * OR *\\\\ disable_wdigest\\\\ * OR *\\\\ disable_winrm\\\\ * OR *\\\\ enable_wdigest\\\\ * OR *\\\\ enable_winrm\\\\ * OR *\\\\ registry_mod\\\\ * OR *\\\\ remote_posh\\\\ * OR *\\\\ sched_job\\\\ * OR *\\\\ service_mod\\\\ * OR *\\\\ process_kill\\\\ * OR *\\\\ active_users\\\\ * OR *\\\\ basic_info\\\\ * OR *\\\\ power_off\\\\ * OR *\\\\ vacant_system\\\\ * OR *\\\\ logon_events\\\\ *)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'WMImplant Hack Tool\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
ScriptBlockText.keyword:(*WMImplant* * change_user * * gen_cli * * command_exec * * disable_wdigest * * disable_winrm * * enable_wdigest * * enable_winrm * * registry_mod * * remote_posh * * sched_job * * service_mod * * process_kill * * active_users * * basic_info * * power_off * * vacant_system * * logon_events *)
```


### splunk
    
```
(ScriptBlockText="*WMImplant*" OR ScriptBlockText="* change_user *" OR ScriptBlockText="* gen_cli *" OR ScriptBlockText="* command_exec *" OR ScriptBlockText="* disable_wdigest *" OR ScriptBlockText="* disable_winrm *" OR ScriptBlockText="* enable_wdigest *" OR ScriptBlockText="* enable_winrm *" OR ScriptBlockText="* registry_mod *" OR ScriptBlockText="* remote_posh *" OR ScriptBlockText="* sched_job *" OR ScriptBlockText="* service_mod *" OR ScriptBlockText="* process_kill *" OR ScriptBlockText="* active_users *" OR ScriptBlockText="* basic_info *" OR ScriptBlockText="* power_off *" OR ScriptBlockText="* vacant_system *" OR ScriptBlockText="* logon_events *")
```


### logpoint
    
```
ScriptBlockText IN ["*WMImplant*", "* change_user *", "* gen_cli *", "* command_exec *", "* disable_wdigest *", "* disable_winrm *", "* enable_wdigest *", "* enable_winrm *", "* registry_mod *", "* remote_posh *", "* sched_job *", "* service_mod *", "* process_kill *", "* active_users *", "* basic_info *", "* power_off *", "* vacant_system *", "* logon_events *"]
```


### grep
    
```
grep -P '^(?:.*.*WMImplant.*|.*.* change_user .*|.*.* gen_cli .*|.*.* command_exec .*|.*.* disable_wdigest .*|.*.* disable_winrm .*|.*.* enable_wdigest .*|.*.* enable_winrm .*|.*.* registry_mod .*|.*.* remote_posh .*|.*.* sched_job .*|.*.* service_mod .*|.*.* process_kill .*|.*.* active_users .*|.*.* basic_info .*|.*.* power_off .*|.*.* vacant_system .*|.*.* logon_events .*)'
```



