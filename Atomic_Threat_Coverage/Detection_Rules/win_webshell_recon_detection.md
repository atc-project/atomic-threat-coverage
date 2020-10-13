| Title                    | Webshell Recon Detection Via CommandLine & Processes       |
|:-------------------------|:------------------|
| **Description**          | Looking for processes spawned by web server components that indicate reconnaissance by popular public domain webshells for whether perl, python or wget are installed. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1505.003: Web Shell](https://attack.mitre.org/techniques/T1505/003)</li><li>[T1100: Web Shell](https://attack.mitre.org/techniques/T1100)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1505.003: Web Shell](../Triggers/T1505.003.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Cian Heasley |


## Detection Rules

### Sigma rule

```
title: Webshell Recon Detection Via CommandLine & Processes
id: f64e5c19-879c-4bae-b471-6d84c8339677
status: experimental
description: Looking for processes spawned by web server components that indicate reconnaissance by popular public domain webshells for whether perl, python or wget are installed.
author: Cian Heasley
reference:
    - https://ragged-lab.blogspot.com/2020/07/webshells-automating-reconnaissance.html
date: 2020/07/22
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
        ParentImage|contains:
            - '*\apache*'
            - '*\tomcat*'
            - '*\w3wp.exe'
            - '*\php-cgi.exe'
            - '*\nginx.exe'
            - '*\httpd.exe'
        Image|endswith:
            - '*\cmd.exe'
        CommandLine|contains:
            - '*perl --help*'
            - '*python --help*'
            - '*wget --help*'
            - '*perl -h*'
    condition: selection
fields:
    - Image
    - CommandLine
    - ParentCommandLine
falsepositives:
    - unknown
level: high

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "ParentImage.*.*\\apache.*" -or $_.message -match "ParentImage.*.*\\tomcat.*" -or $_.message -match "ParentImage.*.*\\w3wp.exe.*" -or $_.message -match "ParentImage.*.*\\php-cgi.exe.*" -or $_.message -match "ParentImage.*.*\\nginx.exe.*" -or $_.message -match "ParentImage.*.*\\httpd.exe.*") -and ($_.message -match "Image.*.*\\cmd.exe") -and ($_.message -match "CommandLine.*.*perl --help.*" -or $_.message -match "CommandLine.*.*python --help.*" -or $_.message -match "CommandLine.*.*wget --help.*" -or $_.message -match "CommandLine.*.*perl -h.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.ParentImage.keyword:(*\\apache* OR *\\tomcat* OR *\\w3wp.exe* OR *\\php\-cgi.exe* OR *\\nginx.exe* OR *\\httpd.exe*) AND winlog.event_data.Image.keyword:(*\\cmd.exe) AND winlog.event_data.CommandLine.keyword:(*perl\ \-\-help* OR *python\ \-\-help* OR *wget\ \-\-help* OR *perl\ \-h*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/f64e5c19-879c-4bae-b471-6d84c8339677 <<EOF
{
  "metadata": {
    "title": "Webshell Recon Detection Via CommandLine & Processes",
    "description": "Looking for processes spawned by web server components that indicate reconnaissance by popular public domain webshells for whether perl, python or wget are installed.",
    "tags": [
      "attack.persistence",
      "attack.t1505.003",
      "attack.privilege_escalation",
      "attack.t1100"
    ],
    "query": "(winlog.event_data.ParentImage.keyword:(*\\\\apache* OR *\\\\tomcat* OR *\\\\w3wp.exe* OR *\\\\php\\-cgi.exe* OR *\\\\nginx.exe* OR *\\\\httpd.exe*) AND winlog.event_data.Image.keyword:(*\\\\cmd.exe) AND winlog.event_data.CommandLine.keyword:(*perl\\ \\-\\-help* OR *python\\ \\-\\-help* OR *wget\\ \\-\\-help* OR *perl\\ \\-h*))"
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
                    "query": "(winlog.event_data.ParentImage.keyword:(*\\\\apache* OR *\\\\tomcat* OR *\\\\w3wp.exe* OR *\\\\php\\-cgi.exe* OR *\\\\nginx.exe* OR *\\\\httpd.exe*) AND winlog.event_data.Image.keyword:(*\\\\cmd.exe) AND winlog.event_data.CommandLine.keyword:(*perl\\ \\-\\-help* OR *python\\ \\-\\-help* OR *wget\\ \\-\\-help* OR *perl\\ \\-h*))",
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
        "subject": "Sigma Rule 'Webshell Recon Detection Via CommandLine & Processes'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n            Image = {{_source.Image}}\n      CommandLine = {{_source.CommandLine}}\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
(ParentImage.keyword:(*\\apache* *\\tomcat* *\\w3wp.exe* *\\php\-cgi.exe* *\\nginx.exe* *\\httpd.exe*) AND Image.keyword:(*\\cmd.exe) AND CommandLine.keyword:(*perl \-\-help* *python \-\-help* *wget \-\-help* *perl \-h*))
```


### splunk
    
```
((ParentImage="*\\apache*" OR ParentImage="*\\tomcat*" OR ParentImage="*\\w3wp.exe*" OR ParentImage="*\\php-cgi.exe*" OR ParentImage="*\\nginx.exe*" OR ParentImage="*\\httpd.exe*") (Image="*\\cmd.exe") (CommandLine="*perl --help*" OR CommandLine="*python --help*" OR CommandLine="*wget --help*" OR CommandLine="*perl -h*")) | table Image,CommandLine,ParentCommandLine
```


### logpoint
    
```
(ParentImage IN ["*\\apache*", "*\\tomcat*", "*\\w3wp.exe*", "*\\php-cgi.exe*", "*\\nginx.exe*", "*\\httpd.exe*"] Image IN ["*\\cmd.exe"] CommandLine IN ["*perl --help*", "*python --help*", "*wget --help*", "*perl -h*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\apache.*|.*.*\tomcat.*|.*.*\w3wp\.exe.*|.*.*\php-cgi\.exe.*|.*.*\nginx\.exe.*|.*.*\httpd\.exe.*))(?=.*(?:.*.*\cmd\.exe))(?=.*(?:.*.*perl --help.*|.*.*python --help.*|.*.*wget --help.*|.*.*perl -h.*)))'
```



