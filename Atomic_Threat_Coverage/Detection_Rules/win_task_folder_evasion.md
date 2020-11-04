| Title                    | Tasks Folder Evasion       |
|:-------------------------|:------------------|
| **Description**          | The Tasks folder in system32 and syswow64 are globally writable paths. Adversaries can take advantage of this and load or influence any script hosts or ANY .NET Application in Tasks to load and execute a custom assembly into cscript, wscript, regsvr32, mshta, eventvwr |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1064: Scripting](https://attack.mitre.org/techniques/T1064)</li><li>[T1211: Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211)</li><li>[T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1064: Scripting](../Triggers/T1064.md)</li><li>[T1059: Command and Scripting Interpreter](../Triggers/T1059.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/subTee/status/1216465628946563073](https://twitter.com/subTee/status/1216465628946563073)</li><li>[https://gist.github.com/am0nsec/8378da08f848424e4ab0cc5b317fdd26](https://gist.github.com/am0nsec/8378da08f848424e4ab0cc5b317fdd26)</li></ul>  |
| **Author**               | Sreeman |


## Detection Rules

### Sigma rule

```
title: Tasks Folder Evasion
id: cc4e02ba-9c06-48e2-b09e-2500cace9ae0
status: experimental
description: The Tasks folder in system32 and syswow64 are globally writable paths. Adversaries can take advantage of this and load or influence any script hosts or ANY .NET Application in Tasks to load and execute a custom assembly into cscript, wscript, regsvr32, mshta, eventvwr 
references: 
    - https://twitter.com/subTee/status/1216465628946563073
    - https://gist.github.com/am0nsec/8378da08f848424e4ab0cc5b317fdd26
date: 2020/01/13
author: Sreeman
tags:
    - attack.t1064
    - attack.t1211
    - attack.t1059
    - attack.defense_evasion
    - attack.persistence
logsource:
    product: Windows
detection:
    selection1:
        CommandLine|contains:
            - 'echo '
            - 'copy '
            - 'type '
            - 'file createnew'
    selection2:
        CommandLine|contains:
            - ' C:\Windows\System32\Tasks\'
            - ' C:\Windows\SysWow64\Tasks\'
    condition: selection1 and selection2
fields:
    - CommandLine
    - ParentProcess
    - CommandLine
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "CommandLine.*.*echo .*" -or $_.message -match "CommandLine.*.*copy .*" -or $_.message -match "CommandLine.*.*type .*" -or $_.message -match "CommandLine.*.*file createnew.*") -and ($_.message -match "CommandLine.*.* C:\\Windows\\System32\\Tasks\\.*" -or $_.message -match "CommandLine.*.* C:\\Windows\\SysWow64\\Tasks\\.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:(*echo\ * OR *copy\ * OR *type\ * OR *file\ createnew*) AND winlog.event_data.CommandLine.keyword:(*\ C\:\\Windows\\System32\\Tasks\* OR *\ C\:\\Windows\\SysWow64\\Tasks\*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/cc4e02ba-9c06-48e2-b09e-2500cace9ae0 <<EOF
{
  "metadata": {
    "title": "Tasks Folder Evasion",
    "description": "The Tasks folder in system32 and syswow64 are globally writable paths. Adversaries can take advantage of this and load or influence any script hosts or ANY .NET Application in Tasks to load and execute a custom assembly into cscript, wscript, regsvr32, mshta, eventvwr",
    "tags": [
      "attack.t1064",
      "attack.t1211",
      "attack.t1059",
      "attack.defense_evasion",
      "attack.persistence"
    ],
    "query": "(winlog.event_data.CommandLine.keyword:(*echo\\ * OR *copy\\ * OR *type\\ * OR *file\\ createnew*) AND winlog.event_data.CommandLine.keyword:(*\\ C\\:\\\\Windows\\\\System32\\\\Tasks\\* OR *\\ C\\:\\\\Windows\\\\SysWow64\\\\Tasks\\*))"
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
                    "query": "(winlog.event_data.CommandLine.keyword:(*echo\\ * OR *copy\\ * OR *type\\ * OR *file\\ createnew*) AND winlog.event_data.CommandLine.keyword:(*\\ C\\:\\\\Windows\\\\System32\\\\Tasks\\* OR *\\ C\\:\\\\Windows\\\\SysWow64\\\\Tasks\\*))",
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
        "subject": "Sigma Rule 'Tasks Folder Evasion'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n  CommandLine = {{_source.CommandLine}}\nParentProcess = {{_source.ParentProcess}}\n  CommandLine = {{_source.CommandLine}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
(CommandLine.keyword:(*echo * *copy * *type * *file createnew*) AND CommandLine.keyword:(* C\:\\Windows\\System32\\Tasks\* * C\:\\Windows\\SysWow64\\Tasks\*))
```


### splunk
    
```
((CommandLine="*echo *" OR CommandLine="*copy *" OR CommandLine="*type *" OR CommandLine="*file createnew*") (CommandLine="* C:\\Windows\\System32\\Tasks\*" OR CommandLine="* C:\\Windows\\SysWow64\\Tasks\*")) | table CommandLine,ParentProcess,CommandLine
```


### logpoint
    
```
(CommandLine IN ["*echo *", "*copy *", "*type *", "*file createnew*"] CommandLine IN ["* C:\\Windows\\System32\\Tasks\*", "* C:\\Windows\\SysWow64\\Tasks\*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*echo .*|.*.*copy .*|.*.*type .*|.*.*file createnew.*))(?=.*(?:.*.* C:\Windows\System32\Tasks\.*|.*.* C:\Windows\SysWow64\Tasks\.*)))'
```



