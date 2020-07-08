| Title                    | Suspicious Scripting in a WMI Consumer       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious scripting in WMI Event Consumers |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Administrative scripts</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://in.security/an-intro-into-abusing-and-identifying-wmi-event-subscriptions-for-persistence/](https://in.security/an-intro-into-abusing-and-identifying-wmi-event-subscriptions-for-persistence/)</li><li>[https://github.com/Neo23x0/signature-base/blob/master/yara/gen_susp_lnk_files.yar#L19](https://github.com/Neo23x0/signature-base/blob/master/yara/gen_susp_lnk_files.yar#L19)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.t1059.005</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Suspicious Scripting in a WMI Consumer
id: fe21810c-2a8c-478f-8dd3-5a287fb2a0e0
status: experimental
description: Detects suspicious scripting in WMI Event Consumers
author: Florian Roth
references:
    - https://in.security/an-intro-into-abusing-and-identifying-wmi-event-subscriptions-for-persistence/
    - https://github.com/Neo23x0/signature-base/blob/master/yara/gen_susp_lnk_files.yar#L19
date: 2019/04/15
tags:
    - attack.t1086
    - attack.execution
    - attack.t1059.005
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 20
        Destination:
            - '*new-object system.net.webclient).downloadstring(*'
            - '*new-object system.net.webclient).downloadfile(*'
            - '*new-object net.webclient).downloadstring(*'
            - '*new-object net.webclient).downloadfile(*'
            - '* iex(*'
            - '*WScript.shell*'
            - '* -nop *'
            - '* -noprofile *'
            - '* -decode *'
            - '* -enc *'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Administrative scripts
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "20" -and ($_.message -match "Destination.*.*new-object system.net.webclient).downloadstring(.*" -or $_.message -match "Destination.*.*new-object system.net.webclient).downloadfile(.*" -or $_.message -match "Destination.*.*new-object net.webclient).downloadstring(.*" -or $_.message -match "Destination.*.*new-object net.webclient).downloadfile(.*" -or $_.message -match "Destination.*.* iex(.*" -or $_.message -match "Destination.*.*WScript.shell.*" -or $_.message -match "Destination.*.* -nop .*" -or $_.message -match "Destination.*.* -noprofile .*" -or $_.message -match "Destination.*.* -decode .*" -or $_.message -match "Destination.*.* -enc .*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"20" AND Destination.keyword:(*new\-object\ system.net.webclient\).downloadstring\(* OR *new\-object\ system.net.webclient\).downloadfile\(* OR *new\-object\ net.webclient\).downloadstring\(* OR *new\-object\ net.webclient\).downloadfile\(* OR *\ iex\(* OR *WScript.shell* OR *\ \-nop\ * OR *\ \-noprofile\ * OR *\ \-decode\ * OR *\ \-enc\ *))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/fe21810c-2a8c-478f-8dd3-5a287fb2a0e0 <<EOF
{
  "metadata": {
    "title": "Suspicious Scripting in a WMI Consumer",
    "description": "Detects suspicious scripting in WMI Event Consumers",
    "tags": [
      "attack.t1086",
      "attack.execution",
      "attack.t1059.005"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"20\" AND Destination.keyword:(*new\\-object\\ system.net.webclient\\).downloadstring\\(* OR *new\\-object\\ system.net.webclient\\).downloadfile\\(* OR *new\\-object\\ net.webclient\\).downloadstring\\(* OR *new\\-object\\ net.webclient\\).downloadfile\\(* OR *\\ iex\\(* OR *WScript.shell* OR *\\ \\-nop\\ * OR *\\ \\-noprofile\\ * OR *\\ \\-decode\\ * OR *\\ \\-enc\\ *))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"20\" AND Destination.keyword:(*new\\-object\\ system.net.webclient\\).downloadstring\\(* OR *new\\-object\\ system.net.webclient\\).downloadfile\\(* OR *new\\-object\\ net.webclient\\).downloadstring\\(* OR *new\\-object\\ net.webclient\\).downloadfile\\(* OR *\\ iex\\(* OR *WScript.shell* OR *\\ \\-nop\\ * OR *\\ \\-noprofile\\ * OR *\\ \\-decode\\ * OR *\\ \\-enc\\ *))",
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
        "subject": "Sigma Rule 'Suspicious Scripting in a WMI Consumer'",
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
(EventID:"20" AND Destination.keyword:(*new\-object system.net.webclient\).downloadstring\(* *new\-object system.net.webclient\).downloadfile\(* *new\-object net.webclient\).downloadstring\(* *new\-object net.webclient\).downloadfile\(* * iex\(* *WScript.shell* * \-nop * * \-noprofile * * \-decode * * \-enc *))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="20" (Destination="*new-object system.net.webclient).downloadstring(*" OR Destination="*new-object system.net.webclient).downloadfile(*" OR Destination="*new-object net.webclient).downloadstring(*" OR Destination="*new-object net.webclient).downloadfile(*" OR Destination="* iex(*" OR Destination="*WScript.shell*" OR Destination="* -nop *" OR Destination="* -noprofile *" OR Destination="* -decode *" OR Destination="* -enc *")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(event_id="20" Destination IN ["*new-object system.net.webclient).downloadstring(*", "*new-object system.net.webclient).downloadfile(*", "*new-object net.webclient).downloadstring(*", "*new-object net.webclient).downloadfile(*", "* iex(*", "*WScript.shell*", "* -nop *", "* -noprofile *", "* -decode *", "* -enc *"])
```


### grep
    
```
grep -P '^(?:.*(?=.*20)(?=.*(?:.*.*new-object system\.net\.webclient\)\.downloadstring\(.*|.*.*new-object system\.net\.webclient\)\.downloadfile\(.*|.*.*new-object net\.webclient\)\.downloadstring\(.*|.*.*new-object net\.webclient\)\.downloadfile\(.*|.*.* iex\(.*|.*.*WScript\.shell.*|.*.* -nop .*|.*.* -noprofile .*|.*.* -decode .*|.*.* -enc .*)))'
```



