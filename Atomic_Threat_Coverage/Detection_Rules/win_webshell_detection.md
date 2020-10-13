| Title                    | Webshell Detection With Command Line Keywords       |
|:-------------------------|:------------------|
| **Description**          | Detects certain command line parameters often used during reconnaissance activity via web shells |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1505.003: Web Shell](https://attack.mitre.org/techniques/T1505/003)</li><li>[T1100: Web Shell](https://attack.mitre.org/techniques/T1100)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1505.003: Web Shell](../Triggers/T1505.003.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Webshell Detection With Command Line Keywords
id: bed2a484-9348-4143-8a8a-b801c979301c
description: Detects certain command line parameters often used during reconnaissance activity via web shells
author: Florian Roth
reference:
    - https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-ii.html
date: 2017/01/01
modified: 2019/10/26
tags:
    - attack.persistence
    - attack.t1505.003
    - attack.privilege_escalation       # an old one
    - attack.t1100      # an old one
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage:
            - '*\apache*'
            - '*\tomcat*'
            - '*\w3wp.exe'
            - '*\php-cgi.exe'
            - '*\nginx.exe'
            - '*\httpd.exe'
        CommandLine:
            - '*whoami*'
            - '*net user *'
            - '*ping -n *'
            - '*systeminfo'
            - '*&cd&echo*'
            - '*cd /d*'  # https://www.computerhope.com/cdhlp.htm
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - unknown
level: high

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "ParentImage.*.*\\apache.*" -or $_.message -match "ParentImage.*.*\\tomcat.*" -or $_.message -match "ParentImage.*.*\\w3wp.exe" -or $_.message -match "ParentImage.*.*\\php-cgi.exe" -or $_.message -match "ParentImage.*.*\\nginx.exe" -or $_.message -match "ParentImage.*.*\\httpd.exe") -and ($_.message -match "CommandLine.*.*whoami.*" -or $_.message -match "CommandLine.*.*net user .*" -or $_.message -match "CommandLine.*.*ping -n .*" -or $_.message -match "CommandLine.*.*systeminfo" -or $_.message -match "CommandLine.*.*&cd&echo.*" -or $_.message -match "CommandLine.*.*cd /d.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.ParentImage.keyword:(*\\apache* OR *\\tomcat* OR *\\w3wp.exe OR *\\php\-cgi.exe OR *\\nginx.exe OR *\\httpd.exe) AND winlog.event_data.CommandLine.keyword:(*whoami* OR *net\ user\ * OR *ping\ \-n\ * OR *systeminfo OR *&cd&echo* OR *cd\ \/d*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/bed2a484-9348-4143-8a8a-b801c979301c <<EOF
{
  "metadata": {
    "title": "Webshell Detection With Command Line Keywords",
    "description": "Detects certain command line parameters often used during reconnaissance activity via web shells",
    "tags": [
      "attack.persistence",
      "attack.t1505.003",
      "attack.privilege_escalation",
      "attack.t1100"
    ],
    "query": "(winlog.event_data.ParentImage.keyword:(*\\\\apache* OR *\\\\tomcat* OR *\\\\w3wp.exe OR *\\\\php\\-cgi.exe OR *\\\\nginx.exe OR *\\\\httpd.exe) AND winlog.event_data.CommandLine.keyword:(*whoami* OR *net\\ user\\ * OR *ping\\ \\-n\\ * OR *systeminfo OR *&cd&echo* OR *cd\\ \\/d*))"
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
                    "query": "(winlog.event_data.ParentImage.keyword:(*\\\\apache* OR *\\\\tomcat* OR *\\\\w3wp.exe OR *\\\\php\\-cgi.exe OR *\\\\nginx.exe OR *\\\\httpd.exe) AND winlog.event_data.CommandLine.keyword:(*whoami* OR *net\\ user\\ * OR *ping\\ \\-n\\ * OR *systeminfo OR *&cd&echo* OR *cd\\ \\/d*))",
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
        "subject": "Sigma Rule 'Webshell Detection With Command Line Keywords'",
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
(ParentImage.keyword:(*\\apache* *\\tomcat* *\\w3wp.exe *\\php\-cgi.exe *\\nginx.exe *\\httpd.exe) AND CommandLine.keyword:(*whoami* *net user * *ping \-n * *systeminfo *&cd&echo* *cd \/d*))
```


### splunk
    
```
((ParentImage="*\\apache*" OR ParentImage="*\\tomcat*" OR ParentImage="*\\w3wp.exe" OR ParentImage="*\\php-cgi.exe" OR ParentImage="*\\nginx.exe" OR ParentImage="*\\httpd.exe") (CommandLine="*whoami*" OR CommandLine="*net user *" OR CommandLine="*ping -n *" OR CommandLine="*systeminfo" OR CommandLine="*&cd&echo*" OR CommandLine="*cd /d*")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(ParentImage IN ["*\\apache*", "*\\tomcat*", "*\\w3wp.exe", "*\\php-cgi.exe", "*\\nginx.exe", "*\\httpd.exe"] CommandLine IN ["*whoami*", "*net user *", "*ping -n *", "*systeminfo", "*&cd&echo*", "*cd /d*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\apache.*|.*.*\tomcat.*|.*.*\w3wp\.exe|.*.*\php-cgi\.exe|.*.*\nginx\.exe|.*.*\httpd\.exe))(?=.*(?:.*.*whoami.*|.*.*net user .*|.*.*ping -n .*|.*.*systeminfo|.*.*&cd&echo.*|.*.*cd /d.*)))'
```



