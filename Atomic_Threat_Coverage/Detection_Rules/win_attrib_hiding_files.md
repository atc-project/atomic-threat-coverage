| Title                    | Hiding Files with Attrib.exe       |
|:-------------------------|:------------------|
| **Description**          | Detects usage of attrib.exe to hide files from users. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1158: Hidden Files and Directories](https://attack.mitre.org/techniques/T1158)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | low |
| **False Positives**      | <ul><li>igfxCUIService.exe hiding *.cui files via .bat script (attrib.exe a child of cmd.exe and igfxCUIService.exe is the parent of the cmd.exe)</li><li>msiexec.exe hiding desktop.ini</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Sami Ruohonen |
| Other Tags           | <ul><li>attack.t1564.001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Hiding Files with Attrib.exe
id: 4281cb20-2994-4580-aa63-c8b86d019934
status: experimental
description: Detects usage of attrib.exe to hide files from users.
author: Sami Ruohonen
date: 2019/01/16
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\attrib.exe'
        CommandLine: '* +h *'
    ini:
        CommandLine: '*\desktop.ini *'
    intel:
        ParentImage: '*\cmd.exe'
        CommandLine: +R +H +S +A \\*.cui
        ParentCommandLine: C:\WINDOWS\system32\\*.bat
    condition: selection and not (ini or intel)
fields:
    - CommandLine
    - ParentCommandLine
    - User
tags:
    - attack.defense_evasion
    - attack.persistence
    - attack.t1158
    - attack.t1564.001
falsepositives:
    - igfxCUIService.exe hiding *.cui files via .bat script (attrib.exe a child of cmd.exe and igfxCUIService.exe is the parent of the cmd.exe)
    - msiexec.exe hiding desktop.ini
level: low

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\\attrib.exe" -and $_.message -match "CommandLine.*.* \+h .*") -and  -not ((($_.ID -eq "1") -and ($_.message -match "CommandLine.*.*\\desktop.ini .*" -or ($_.message -match "ParentImage.*.*\\cmd.exe" -and $_.message -match "CommandLine.*\+R \+H \+S \+A \\.*.cui" -and $_.message -match "ParentCommandLine.*C:\\WINDOWS\\system32\\.*.bat"))))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.Image.keyword:*\\attrib.exe AND winlog.event_data.CommandLine.keyword:*\ \+h\ *) AND (NOT ((winlog.event_data.CommandLine.keyword:*\\desktop.ini\ * OR (winlog.event_data.ParentImage.keyword:*\\cmd.exe AND winlog.event_data.CommandLine.keyword:\+R\ \+H\ \+S\ \+A\ \\*.cui AND winlog.event_data.ParentCommandLine.keyword:C\:\\WINDOWS\\system32\\*.bat)))))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/4281cb20-2994-4580-aa63-c8b86d019934 <<EOF
{
  "metadata": {
    "title": "Hiding Files with Attrib.exe",
    "description": "Detects usage of attrib.exe to hide files from users.",
    "tags": [
      "attack.defense_evasion",
      "attack.persistence",
      "attack.t1158",
      "attack.t1564.001"
    ],
    "query": "((winlog.event_data.Image.keyword:*\\\\attrib.exe AND winlog.event_data.CommandLine.keyword:*\\ \\+h\\ *) AND (NOT ((winlog.event_data.CommandLine.keyword:*\\\\desktop.ini\\ * OR (winlog.event_data.ParentImage.keyword:*\\\\cmd.exe AND winlog.event_data.CommandLine.keyword:\\+R\\ \\+H\\ \\+S\\ \\+A\\ \\\\*.cui AND winlog.event_data.ParentCommandLine.keyword:C\\:\\\\WINDOWS\\\\system32\\\\*.bat)))))"
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
                    "query": "((winlog.event_data.Image.keyword:*\\\\attrib.exe AND winlog.event_data.CommandLine.keyword:*\\ \\+h\\ *) AND (NOT ((winlog.event_data.CommandLine.keyword:*\\\\desktop.ini\\ * OR (winlog.event_data.ParentImage.keyword:*\\\\cmd.exe AND winlog.event_data.CommandLine.keyword:\\+R\\ \\+H\\ \\+S\\ \\+A\\ \\\\*.cui AND winlog.event_data.ParentCommandLine.keyword:C\\:\\\\WINDOWS\\\\system32\\\\*.bat)))))",
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
        "subject": "Sigma Rule 'Hiding Files with Attrib.exe'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n      CommandLine = {{_source.CommandLine}}\nParentCommandLine = {{_source.ParentCommandLine}}\n             User = {{_source.User}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
((Image.keyword:*\\attrib.exe AND CommandLine.keyword:* \+h *) AND (NOT ((CommandLine.keyword:*\\desktop.ini * OR (ParentImage.keyword:*\\cmd.exe AND CommandLine.keyword:\+R \+H \+S \+A \\*.cui AND ParentCommandLine.keyword:C\:\\WINDOWS\\system32\\*.bat)))))
```


### splunk
    
```
((Image="*\\attrib.exe" CommandLine="* +h *") NOT ((CommandLine="*\\desktop.ini *" OR (ParentImage="*\\cmd.exe" CommandLine="+R +H +S +A \\*.cui" ParentCommandLine="C:\\WINDOWS\\system32\\*.bat")))) | table CommandLine,ParentCommandLine,User
```


### logpoint
    
```
(event_id="1" (Image="*\\attrib.exe" CommandLine="* +h *")  -((event_id="1" (CommandLine="*\\desktop.ini *" OR (ParentImage="*\\cmd.exe" CommandLine="+R +H +S +A \\*.cui" ParentCommandLine="C:\\WINDOWS\\system32\\*.bat")))))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*.*\attrib\.exe)(?=.*.* \+h .*)))(?=.*(?!.*(?:.*(?:.*(?:.*.*\desktop\.ini .*|.*(?:.*(?=.*.*\cmd\.exe)(?=.*\+R \+H \+S \+A \\.*\.cui)(?=.*C:\WINDOWS\system32\\.*\.bat))))))))'
```



