| Title                    | File or Folder Permissions Modifications       |
|:-------------------------|:------------------|
| **Description**          | Detects a file or folder permissions modifications |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1222: File and Directory Permissions Modification](https://attack.mitre.org/techniques/T1222)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Users interacting with the files on their own (unlikely unless power users)</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1222/T1222.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1222/T1222.yaml)</li></ul>  |
| **Author**               | Jakob Weinzettl, oscd.community |


## Detection Rules

### Sigma rule

```
title: File or Folder Permissions Modifications
id: 37ae075c-271b-459b-8d7b-55ad5f993dd8
status: experimental
description: Detects a file or folder permissions modifications
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1222/T1222.yaml
author: Jakob Weinzettl, oscd.community
date: 2019/10/23
modified: 2019/11/08
tags:
    - attack.defense_evasion
    - attack.t1222
logsource:
    category: process_creation
    product: windows
detection:
    selection:
      - Image|endswith: 
          - '\takeown.exe'
          - '\cacls.exe'
          - '\icacls.exe'
        CommandLine|contains: '/grant'
      - Image|endswith: '\attrib.exe'
        CommandLine|contains: '-r'
    condition: selection
fields:
    - ComputerName
    - User
    - CommandLine
falsepositives:
    - Users interacting with the files on their own (unlikely unless power users)
level: medium

```





### powershell
    
```
Get-WinEvent | where {((($_.message -match "Image.*.*\\takeown.exe" -or $_.message -match "Image.*.*\\cacls.exe" -or $_.message -match "Image.*.*\\icacls.exe") -and $_.message -match "CommandLine.*.*/grant.*") -or ($_.message -match "Image.*.*\\attrib.exe" -and $_.message -match "CommandLine.*.*-r.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.Image.keyword:(*\\takeown.exe OR *\\cacls.exe OR *\\icacls.exe) AND winlog.event_data.CommandLine.keyword:*\/grant*) OR (winlog.event_data.Image.keyword:*\\attrib.exe AND winlog.event_data.CommandLine.keyword:*\-r*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/37ae075c-271b-459b-8d7b-55ad5f993dd8 <<EOF
{
  "metadata": {
    "title": "File or Folder Permissions Modifications",
    "description": "Detects a file or folder permissions modifications",
    "tags": [
      "attack.defense_evasion",
      "attack.t1222"
    ],
    "query": "((winlog.event_data.Image.keyword:(*\\\\takeown.exe OR *\\\\cacls.exe OR *\\\\icacls.exe) AND winlog.event_data.CommandLine.keyword:*\\/grant*) OR (winlog.event_data.Image.keyword:*\\\\attrib.exe AND winlog.event_data.CommandLine.keyword:*\\-r*))"
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
                    "query": "((winlog.event_data.Image.keyword:(*\\\\takeown.exe OR *\\\\cacls.exe OR *\\\\icacls.exe) AND winlog.event_data.CommandLine.keyword:*\\/grant*) OR (winlog.event_data.Image.keyword:*\\\\attrib.exe AND winlog.event_data.CommandLine.keyword:*\\-r*))",
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
        "subject": "Sigma Rule 'File or Folder Permissions Modifications'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\nComputerName = {{_source.ComputerName}}\n        User = {{_source.User}}\n CommandLine = {{_source.CommandLine}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
((Image.keyword:(*\\takeown.exe *\\cacls.exe *\\icacls.exe) AND CommandLine.keyword:*\/grant*) OR (Image.keyword:*\\attrib.exe AND CommandLine.keyword:*\-r*))
```


### splunk
    
```
(((Image="*\\takeown.exe" OR Image="*\\cacls.exe" OR Image="*\\icacls.exe") CommandLine="*/grant*") OR (Image="*\\attrib.exe" CommandLine="*-r*")) | table ComputerName,User,CommandLine
```


### logpoint
    
```
((Image IN ["*\\takeown.exe", "*\\cacls.exe", "*\\icacls.exe"] CommandLine="*/grant*") OR (Image="*\\attrib.exe" CommandLine="*-r*"))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*(?:.*.*\takeown\.exe|.*.*\cacls\.exe|.*.*\icacls\.exe))(?=.*.*/grant.*))|.*(?:.*(?=.*.*\attrib\.exe)(?=.*.*-r.*))))'
```



