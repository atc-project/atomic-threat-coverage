| Title                    | Query Registry       |
|:-------------------------|:------------------|
| **Description**          | Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1012: Query Registry](https://attack.mitre.org/techniques/T1012)</li><li>[T1007: System Service Discovery](https://attack.mitre.org/techniques/T1007)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1012: Query Registry](../Triggers/T1012.md)</li><li>[T1007: System Service Discovery](../Triggers/T1007.md)</li></ul>  |
| **Severity Level**       | low |
| **False Positives**      |  There are no documented False Positives for this Detection Rule yet  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1012/T1012.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1012/T1012.yaml)</li></ul>  |
| **Author**               | Timur Zinniatullin, oscd.community |


## Detection Rules

### Sigma rule

```
title: Query Registry
id: 970007b7-ce32-49d0-a4a4-fbef016950bd
status: experimental
description: Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software.
author: Timur Zinniatullin, oscd.community
date: 2019/10/21
modified: 2019/11/04
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1012/T1012.yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        Image|endswith: '\reg.exe'
        CommandLine|contains: 
            - 'query'
            - 'save'
            - 'export'
    selection_2:
        CommandLine|contains:
            - 'currentVersion\windows'
            - 'currentVersion\runServicesOnce'
            - 'currentVersion\runServices'
            - 'winlogon\'
            - 'currentVersion\shellServiceObjectDelayLoad'
            - 'currentVersion\runOnce'
            - 'currentVersion\runOnceEx'
            - 'currentVersion\run'
            - 'currentVersion\policies\explorer\run'
            - 'currentcontrolset\services'
    condition: selection_1 and selection_2
fields:
    - Image
    - CommandLine
    - User
    - LogonGuid
    - Hashes
    - ParentProcessGuid
    - ParentCommandLine
level: low
tags:
    - attack.discovery
    - attack.t1012
    - attack.t1007

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Image.*.*\\reg.exe" -and ($_.message -match "CommandLine.*.*query.*" -or $_.message -match "CommandLine.*.*save.*" -or $_.message -match "CommandLine.*.*export.*") -and ($_.message -match "CommandLine.*.*currentVersion\\windows.*" -or $_.message -match "CommandLine.*.*currentVersion\\runServicesOnce.*" -or $_.message -match "CommandLine.*.*currentVersion\\runServices.*" -or $_.message -match "CommandLine.*.*winlogon\\.*" -or $_.message -match "CommandLine.*.*currentVersion\\shellServiceObjectDelayLoad.*" -or $_.message -match "CommandLine.*.*currentVersion\\runOnce.*" -or $_.message -match "CommandLine.*.*currentVersion\\runOnceEx.*" -or $_.message -match "CommandLine.*.*currentVersion\\run.*" -or $_.message -match "CommandLine.*.*currentVersion\\policies\\explorer\\run.*" -or $_.message -match "CommandLine.*.*currentcontrolset\\services.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\reg.exe AND winlog.event_data.CommandLine.keyword:(*query* OR *save* OR *export*) AND winlog.event_data.CommandLine.keyword:(*currentVersion\\windows* OR *currentVersion\\runServicesOnce* OR *currentVersion\\runServices* OR *winlogon\\* OR *currentVersion\\shellServiceObjectDelayLoad* OR *currentVersion\\runOnce* OR *currentVersion\\runOnceEx* OR *currentVersion\\run* OR *currentVersion\\policies\\explorer\\run* OR *currentcontrolset\\services*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/970007b7-ce32-49d0-a4a4-fbef016950bd <<EOF
{
  "metadata": {
    "title": "Query Registry",
    "description": "Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software.",
    "tags": [
      "attack.discovery",
      "attack.t1012",
      "attack.t1007"
    ],
    "query": "(winlog.event_data.Image.keyword:*\\\\reg.exe AND winlog.event_data.CommandLine.keyword:(*query* OR *save* OR *export*) AND winlog.event_data.CommandLine.keyword:(*currentVersion\\\\windows* OR *currentVersion\\\\runServicesOnce* OR *currentVersion\\\\runServices* OR *winlogon\\\\* OR *currentVersion\\\\shellServiceObjectDelayLoad* OR *currentVersion\\\\runOnce* OR *currentVersion\\\\runOnceEx* OR *currentVersion\\\\run* OR *currentVersion\\\\policies\\\\explorer\\\\run* OR *currentcontrolset\\\\services*))"
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
                    "query": "(winlog.event_data.Image.keyword:*\\\\reg.exe AND winlog.event_data.CommandLine.keyword:(*query* OR *save* OR *export*) AND winlog.event_data.CommandLine.keyword:(*currentVersion\\\\windows* OR *currentVersion\\\\runServicesOnce* OR *currentVersion\\\\runServices* OR *winlogon\\\\* OR *currentVersion\\\\shellServiceObjectDelayLoad* OR *currentVersion\\\\runOnce* OR *currentVersion\\\\runOnceEx* OR *currentVersion\\\\run* OR *currentVersion\\\\policies\\\\explorer\\\\run* OR *currentcontrolset\\\\services*))",
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
        "subject": "Sigma Rule 'Query Registry'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n            Image = {{_source.Image}}\n      CommandLine = {{_source.CommandLine}}\n             User = {{_source.User}}\n        LogonGuid = {{_source.LogonGuid}}\n           Hashes = {{_source.Hashes}}\nParentProcessGuid = {{_source.ParentProcessGuid}}\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
(Image.keyword:*\\reg.exe AND CommandLine.keyword:(*query* *save* *export*) AND CommandLine.keyword:(*currentVersion\\windows* *currentVersion\\runServicesOnce* *currentVersion\\runServices* *winlogon\\* *currentVersion\\shellServiceObjectDelayLoad* *currentVersion\\runOnce* *currentVersion\\runOnceEx* *currentVersion\\run* *currentVersion\\policies\\explorer\\run* *currentcontrolset\\services*))
```


### splunk
    
```
(Image="*\\reg.exe" (CommandLine="*query*" OR CommandLine="*save*" OR CommandLine="*export*") (CommandLine="*currentVersion\\windows*" OR CommandLine="*currentVersion\\runServicesOnce*" OR CommandLine="*currentVersion\\runServices*" OR CommandLine="*winlogon\\*" OR CommandLine="*currentVersion\\shellServiceObjectDelayLoad*" OR CommandLine="*currentVersion\\runOnce*" OR CommandLine="*currentVersion\\runOnceEx*" OR CommandLine="*currentVersion\\run*" OR CommandLine="*currentVersion\\policies\\explorer\\run*" OR CommandLine="*currentcontrolset\\services*")) | table Image,CommandLine,User,LogonGuid,Hashes,ParentProcessGuid,ParentCommandLine
```


### logpoint
    
```
(Image="*\\reg.exe" CommandLine IN ["*query*", "*save*", "*export*"] CommandLine IN ["*currentVersion\\windows*", "*currentVersion\\runServicesOnce*", "*currentVersion\\runServices*", "*winlogon\\*", "*currentVersion\\shellServiceObjectDelayLoad*", "*currentVersion\\runOnce*", "*currentVersion\\runOnceEx*", "*currentVersion\\run*", "*currentVersion\\policies\\explorer\\run*", "*currentcontrolset\\services*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\reg\.exe)(?=.*(?:.*.*query.*|.*.*save.*|.*.*export.*))(?=.*(?:.*.*currentVersion\windows.*|.*.*currentVersion\runServicesOnce.*|.*.*currentVersion\runServices.*|.*.*winlogon\\.*|.*.*currentVersion\shellServiceObjectDelayLoad.*|.*.*currentVersion\runOnce.*|.*.*currentVersion\runOnceEx.*|.*.*currentVersion\run.*|.*.*currentVersion\policies\explorer\run.*|.*.*currentcontrolset\services.*)))'
```



