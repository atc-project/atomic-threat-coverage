| Title                    | Suspicious WMI Execution       |
|:-------------------------|:------------------|
| **Description**          | Detects WMI executing suspicious commands |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1047: Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1047: Windows Management Instrumentation](../Triggers/T1047.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Will need to be tuned</li><li>If using Splunk, I recommend | stats count by Computer,CommandLine following for easy hunting by Computer/CommandLine.</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://digital-forensics.sans.org/blog/2010/06/04/wmic-draft/](https://digital-forensics.sans.org/blog/2010/06/04/wmic-draft/)</li><li>[https://www.hybrid-analysis.com/sample/4be06ecd234e2110bd615649fe4a6fa95403979acf889d7e45a78985eb50acf9?environmentId=1](https://www.hybrid-analysis.com/sample/4be06ecd234e2110bd615649fe4a6fa95403979acf889d7e45a78985eb50acf9?environmentId=1)</li><li>[https://blog.malwarebytes.com/threat-analysis/2016/04/rokku-ransomware/](https://blog.malwarebytes.com/threat-analysis/2016/04/rokku-ransomware/)</li></ul>  |
| **Author**               | Michael Haag, Florian Roth, juju4 |
| Other Tags           | <ul><li>car.2016-03-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Suspicious WMI Execution
id: 526be59f-a573-4eea-b5f7-f0973207634d
status: experimental
description: Detects WMI executing suspicious commands
references:
    - https://digital-forensics.sans.org/blog/2010/06/04/wmic-draft/
    - https://www.hybrid-analysis.com/sample/4be06ecd234e2110bd615649fe4a6fa95403979acf889d7e45a78985eb50acf9?environmentId=1
    - https://blog.malwarebytes.com/threat-analysis/2016/04/rokku-ransomware/
author: Michael Haag, Florian Roth, juju4
date: 2019/01/16
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\wmic.exe'
        CommandLine:
            - '*/NODE:*process call create *'
            - '* path AntiVirusProduct get *'
            - '* path FirewallProduct get *'
            - '* shadowcopy delete *'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.execution
    - attack.t1047
    - car.2016-03-002
falsepositives:
    - Will need to be tuned
    - If using Splunk, I recommend | stats count by Computer,CommandLine following for easy hunting by Computer/CommandLine.
level: medium

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "Image.*.*\\wmic.exe") -and ($_.message -match "CommandLine.*.*/NODE:.*process call create .*" -or $_.message -match "CommandLine.*.* path AntiVirusProduct get .*" -or $_.message -match "CommandLine.*.* path FirewallProduct get .*" -or $_.message -match "CommandLine.*.* shadowcopy delete .*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:(*\\wmic.exe) AND winlog.event_data.CommandLine.keyword:(*\/NODE\:*process\ call\ create\ * OR *\ path\ AntiVirusProduct\ get\ * OR *\ path\ FirewallProduct\ get\ * OR *\ shadowcopy\ delete\ *))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/526be59f-a573-4eea-b5f7-f0973207634d <<EOF
{
  "metadata": {
    "title": "Suspicious WMI Execution",
    "description": "Detects WMI executing suspicious commands",
    "tags": [
      "attack.execution",
      "attack.t1047",
      "car.2016-03-002"
    ],
    "query": "(winlog.event_data.Image.keyword:(*\\\\wmic.exe) AND winlog.event_data.CommandLine.keyword:(*\\/NODE\\:*process\\ call\\ create\\ * OR *\\ path\\ AntiVirusProduct\\ get\\ * OR *\\ path\\ FirewallProduct\\ get\\ * OR *\\ shadowcopy\\ delete\\ *))"
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
                    "query": "(winlog.event_data.Image.keyword:(*\\\\wmic.exe) AND winlog.event_data.CommandLine.keyword:(*\\/NODE\\:*process\\ call\\ create\\ * OR *\\ path\\ AntiVirusProduct\\ get\\ * OR *\\ path\\ FirewallProduct\\ get\\ * OR *\\ shadowcopy\\ delete\\ *))",
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
        "subject": "Sigma Rule 'Suspicious WMI Execution'",
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
(Image.keyword:(*\\wmic.exe) AND CommandLine.keyword:(*\/NODE\:*process call create * * path AntiVirusProduct get * * path FirewallProduct get * * shadowcopy delete *))
```


### splunk
    
```
((Image="*\\wmic.exe") (CommandLine="*/NODE:*process call create *" OR CommandLine="* path AntiVirusProduct get *" OR CommandLine="* path FirewallProduct get *" OR CommandLine="* shadowcopy delete *")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(Image IN ["*\\wmic.exe"] CommandLine IN ["*/NODE:*process call create *", "* path AntiVirusProduct get *", "* path FirewallProduct get *", "* shadowcopy delete *"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\wmic\.exe))(?=.*(?:.*.*/NODE:.*process call create .*|.*.* path AntiVirusProduct get .*|.*.* path FirewallProduct get .*|.*.* shadowcopy delete .*)))'
```



