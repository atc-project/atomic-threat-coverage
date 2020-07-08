| Title                    | Shells Spawned by Web Servers       |
|:-------------------------|:------------------|
| **Description**          | Web servers that spawn shell processes could be the result of a successfully placed web shell or an other attack |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1100: Web Shell](https://attack.mitre.org/techniques/T1100)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Particular web applications may spawn a shell process legitimately</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Thomas Patzke |
| Other Tags           | <ul><li>attack.t1505.003</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Shells Spawned by Web Servers
id: 8202070f-edeb-4d31-a010-a26c72ac5600
status: experimental
description: Web servers that spawn shell processes could be the result of a successfully placed web shell or an other attack
author: Thomas Patzke
date: 2019/01/16
modified: 2020/03/25
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage:
            - '*\w3wp.exe'
            - '*\httpd.exe'
            - '*\nginx.exe'
            - '*\php-cgi.exe'
            - '*\tomcat.exe'
        Image:
            - '*\cmd.exe'
            - '*\sh.exe'
            - '*\bash.exe'
            - '*\powershell.exe'
            - '*\bitsadmin.exe'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.privilege_escalation
    - attack.persistence
    - attack.t1100
    - attack.t1505.003
falsepositives:
    - Particular web applications may spawn a shell process legitimately
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "ParentImage.*.*\\w3wp.exe" -or $_.message -match "ParentImage.*.*\\httpd.exe" -or $_.message -match "ParentImage.*.*\\nginx.exe" -or $_.message -match "ParentImage.*.*\\php-cgi.exe" -or $_.message -match "ParentImage.*.*\\tomcat.exe") -and ($_.message -match "Image.*.*\\cmd.exe" -or $_.message -match "Image.*.*\\sh.exe" -or $_.message -match "Image.*.*\\bash.exe" -or $_.message -match "Image.*.*\\powershell.exe" -or $_.message -match "Image.*.*\\bitsadmin.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.ParentImage.keyword:(*\\w3wp.exe OR *\\httpd.exe OR *\\nginx.exe OR *\\php\-cgi.exe OR *\\tomcat.exe) AND winlog.event_data.Image.keyword:(*\\cmd.exe OR *\\sh.exe OR *\\bash.exe OR *\\powershell.exe OR *\\bitsadmin.exe))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/8202070f-edeb-4d31-a010-a26c72ac5600 <<EOF
{
  "metadata": {
    "title": "Shells Spawned by Web Servers",
    "description": "Web servers that spawn shell processes could be the result of a successfully placed web shell or an other attack",
    "tags": [
      "attack.privilege_escalation",
      "attack.persistence",
      "attack.t1100",
      "attack.t1505.003"
    ],
    "query": "(winlog.event_data.ParentImage.keyword:(*\\\\w3wp.exe OR *\\\\httpd.exe OR *\\\\nginx.exe OR *\\\\php\\-cgi.exe OR *\\\\tomcat.exe) AND winlog.event_data.Image.keyword:(*\\\\cmd.exe OR *\\\\sh.exe OR *\\\\bash.exe OR *\\\\powershell.exe OR *\\\\bitsadmin.exe))"
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
                    "query": "(winlog.event_data.ParentImage.keyword:(*\\\\w3wp.exe OR *\\\\httpd.exe OR *\\\\nginx.exe OR *\\\\php\\-cgi.exe OR *\\\\tomcat.exe) AND winlog.event_data.Image.keyword:(*\\\\cmd.exe OR *\\\\sh.exe OR *\\\\bash.exe OR *\\\\powershell.exe OR *\\\\bitsadmin.exe))",
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
        "subject": "Sigma Rule 'Shells Spawned by Web Servers'",
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
(ParentImage.keyword:(*\\w3wp.exe *\\httpd.exe *\\nginx.exe *\\php\-cgi.exe *\\tomcat.exe) AND Image.keyword:(*\\cmd.exe *\\sh.exe *\\bash.exe *\\powershell.exe *\\bitsadmin.exe))
```


### splunk
    
```
((ParentImage="*\\w3wp.exe" OR ParentImage="*\\httpd.exe" OR ParentImage="*\\nginx.exe" OR ParentImage="*\\php-cgi.exe" OR ParentImage="*\\tomcat.exe") (Image="*\\cmd.exe" OR Image="*\\sh.exe" OR Image="*\\bash.exe" OR Image="*\\powershell.exe" OR Image="*\\bitsadmin.exe")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(event_id="1" ParentImage IN ["*\\w3wp.exe", "*\\httpd.exe", "*\\nginx.exe", "*\\php-cgi.exe", "*\\tomcat.exe"] Image IN ["*\\cmd.exe", "*\\sh.exe", "*\\bash.exe", "*\\powershell.exe", "*\\bitsadmin.exe"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\w3wp\.exe|.*.*\httpd\.exe|.*.*\nginx\.exe|.*.*\php-cgi\.exe|.*.*\tomcat\.exe))(?=.*(?:.*.*\cmd\.exe|.*.*\sh\.exe|.*.*\bash\.exe|.*.*\powershell\.exe|.*.*\bitsadmin\.exe)))'
```



