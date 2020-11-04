| Title                    | Suspicious Rundll32 Activity       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious process related to rundll32 based on arguments |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1085: Rundll32](https://attack.mitre.org/techniques/T1085)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1085: Rundll32](../Triggers/T1085.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[http://www.hexacorn.com/blog/2017/05/01/running-programs-via-proxy-jumping-on-a-edr-bypass-trampoline/](http://www.hexacorn.com/blog/2017/05/01/running-programs-via-proxy-jumping-on-a-edr-bypass-trampoline/)</li><li>[https://twitter.com/Hexacorn/status/885258886428725250](https://twitter.com/Hexacorn/status/885258886428725250)</li><li>[https://gist.github.com/ryhanson/227229866af52e2d963cf941af135a52](https://gist.github.com/ryhanson/227229866af52e2d963cf941af135a52)</li></ul>  |
| **Author**               | juju4 |


## Detection Rules

### Sigma rule

```
title: Suspicious Rundll32 Activity
id: e593cf51-88db-4ee1-b920-37e89012a3c9
description: Detects suspicious process related to rundll32 based on arguments
status: experimental
references:
    - http://www.hexacorn.com/blog/2017/05/01/running-programs-via-proxy-jumping-on-a-edr-bypass-trampoline/
    - https://twitter.com/Hexacorn/status/885258886428725250
    - https://gist.github.com/ryhanson/227229866af52e2d963cf941af135a52
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1085
author: juju4
date: 2019/01/16
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '*\rundll32.exe* url.dll,*OpenURL *'
            - '*\rundll32.exe* url.dll,*OpenURLA *'
            - '*\rundll32.exe* url.dll,*FileProtocolHandler *'
            - '*\rundll32.exe* zipfldr.dll,*RouteTheCall *'
            - '*\rundll32.exe* Shell32.dll,*Control_RunDLL *'
            - '*\rundll32.exe javascript:*'
            - '* url.dll,*OpenURL *'
            - '* url.dll,*OpenURLA *'
            - '* url.dll,*FileProtocolHandler *'
            - '* zipfldr.dll,*RouteTheCall *'
            - '* Shell32.dll,*Control_RunDLL *'
            - '* javascript:*'
            - '*.RegisterXLL*'
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.*\\rundll32.exe.* url.dll,.*OpenURL .*" -or $_.message -match "CommandLine.*.*\\rundll32.exe.* url.dll,.*OpenURLA .*" -or $_.message -match "CommandLine.*.*\\rundll32.exe.* url.dll,.*FileProtocolHandler .*" -or $_.message -match "CommandLine.*.*\\rundll32.exe.* zipfldr.dll,.*RouteTheCall .*" -or $_.message -match "CommandLine.*.*\\rundll32.exe.* Shell32.dll,.*Control_RunDLL .*" -or $_.message -match "CommandLine.*.*\\rundll32.exe javascript:.*" -or $_.message -match "CommandLine.*.* url.dll,.*OpenURL .*" -or $_.message -match "CommandLine.*.* url.dll,.*OpenURLA .*" -or $_.message -match "CommandLine.*.* url.dll,.*FileProtocolHandler .*" -or $_.message -match "CommandLine.*.* zipfldr.dll,.*RouteTheCall .*" -or $_.message -match "CommandLine.*.* Shell32.dll,.*Control_RunDLL .*" -or $_.message -match "CommandLine.*.* javascript:.*" -or $_.message -match "CommandLine.*.*.RegisterXLL.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(*\\rundll32.exe*\ url.dll,*OpenURL\ * OR *\\rundll32.exe*\ url.dll,*OpenURLA\ * OR *\\rundll32.exe*\ url.dll,*FileProtocolHandler\ * OR *\\rundll32.exe*\ zipfldr.dll,*RouteTheCall\ * OR *\\rundll32.exe*\ Shell32.dll,*Control_RunDLL\ * OR *\\rundll32.exe\ javascript\:* OR *\ url.dll,*OpenURL\ * OR *\ url.dll,*OpenURLA\ * OR *\ url.dll,*FileProtocolHandler\ * OR *\ zipfldr.dll,*RouteTheCall\ * OR *\ Shell32.dll,*Control_RunDLL\ * OR *\ javascript\:* OR *.RegisterXLL*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/e593cf51-88db-4ee1-b920-37e89012a3c9 <<EOF
{
  "metadata": {
    "title": "Suspicious Rundll32 Activity",
    "description": "Detects suspicious process related to rundll32 based on arguments",
    "tags": [
      "attack.defense_evasion",
      "attack.execution",
      "attack.t1085"
    ],
    "query": "winlog.event_data.CommandLine.keyword:(*\\\\rundll32.exe*\\ url.dll,*OpenURL\\ * OR *\\\\rundll32.exe*\\ url.dll,*OpenURLA\\ * OR *\\\\rundll32.exe*\\ url.dll,*FileProtocolHandler\\ * OR *\\\\rundll32.exe*\\ zipfldr.dll,*RouteTheCall\\ * OR *\\\\rundll32.exe*\\ Shell32.dll,*Control_RunDLL\\ * OR *\\\\rundll32.exe\\ javascript\\:* OR *\\ url.dll,*OpenURL\\ * OR *\\ url.dll,*OpenURLA\\ * OR *\\ url.dll,*FileProtocolHandler\\ * OR *\\ zipfldr.dll,*RouteTheCall\\ * OR *\\ Shell32.dll,*Control_RunDLL\\ * OR *\\ javascript\\:* OR *.RegisterXLL*)"
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
                    "query": "winlog.event_data.CommandLine.keyword:(*\\\\rundll32.exe*\\ url.dll,*OpenURL\\ * OR *\\\\rundll32.exe*\\ url.dll,*OpenURLA\\ * OR *\\\\rundll32.exe*\\ url.dll,*FileProtocolHandler\\ * OR *\\\\rundll32.exe*\\ zipfldr.dll,*RouteTheCall\\ * OR *\\\\rundll32.exe*\\ Shell32.dll,*Control_RunDLL\\ * OR *\\\\rundll32.exe\\ javascript\\:* OR *\\ url.dll,*OpenURL\\ * OR *\\ url.dll,*OpenURLA\\ * OR *\\ url.dll,*FileProtocolHandler\\ * OR *\\ zipfldr.dll,*RouteTheCall\\ * OR *\\ Shell32.dll,*Control_RunDLL\\ * OR *\\ javascript\\:* OR *.RegisterXLL*)",
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
        "subject": "Sigma Rule 'Suspicious Rundll32 Activity'",
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
CommandLine.keyword:(*\\rundll32.exe* url.dll,*OpenURL * *\\rundll32.exe* url.dll,*OpenURLA * *\\rundll32.exe* url.dll,*FileProtocolHandler * *\\rundll32.exe* zipfldr.dll,*RouteTheCall * *\\rundll32.exe* Shell32.dll,*Control_RunDLL * *\\rundll32.exe javascript\:* * url.dll,*OpenURL * * url.dll,*OpenURLA * * url.dll,*FileProtocolHandler * * zipfldr.dll,*RouteTheCall * * Shell32.dll,*Control_RunDLL * * javascript\:* *.RegisterXLL*)
```


### splunk
    
```
(CommandLine="*\\rundll32.exe* url.dll,*OpenURL *" OR CommandLine="*\\rundll32.exe* url.dll,*OpenURLA *" OR CommandLine="*\\rundll32.exe* url.dll,*FileProtocolHandler *" OR CommandLine="*\\rundll32.exe* zipfldr.dll,*RouteTheCall *" OR CommandLine="*\\rundll32.exe* Shell32.dll,*Control_RunDLL *" OR CommandLine="*\\rundll32.exe javascript:*" OR CommandLine="* url.dll,*OpenURL *" OR CommandLine="* url.dll,*OpenURLA *" OR CommandLine="* url.dll,*FileProtocolHandler *" OR CommandLine="* zipfldr.dll,*RouteTheCall *" OR CommandLine="* Shell32.dll,*Control_RunDLL *" OR CommandLine="* javascript:*" OR CommandLine="*.RegisterXLL*")
```


### logpoint
    
```
CommandLine IN ["*\\rundll32.exe* url.dll,*OpenURL *", "*\\rundll32.exe* url.dll,*OpenURLA *", "*\\rundll32.exe* url.dll,*FileProtocolHandler *", "*\\rundll32.exe* zipfldr.dll,*RouteTheCall *", "*\\rundll32.exe* Shell32.dll,*Control_RunDLL *", "*\\rundll32.exe javascript:*", "* url.dll,*OpenURL *", "* url.dll,*OpenURLA *", "* url.dll,*FileProtocolHandler *", "* zipfldr.dll,*RouteTheCall *", "* Shell32.dll,*Control_RunDLL *", "* javascript:*", "*.RegisterXLL*"]
```


### grep
    
```
grep -P '^(?:.*.*\rundll32\.exe.* url\.dll,.*OpenURL .*|.*.*\rundll32\.exe.* url\.dll,.*OpenURLA .*|.*.*\rundll32\.exe.* url\.dll,.*FileProtocolHandler .*|.*.*\rundll32\.exe.* zipfldr\.dll,.*RouteTheCall .*|.*.*\rundll32\.exe.* Shell32\.dll,.*Control_RunDLL .*|.*.*\rundll32\.exe javascript:.*|.*.* url\.dll,.*OpenURL .*|.*.* url\.dll,.*OpenURLA .*|.*.* url\.dll,.*FileProtocolHandler .*|.*.* zipfldr\.dll,.*RouteTheCall .*|.*.* Shell32\.dll,.*Control_RunDLL .*|.*.* javascript:.*|.*.*\.RegisterXLL.*)'
```



