| Title                    | Squirrel Lolbin       |
|:-------------------------|:------------------|
| **Description**          | Detects Possible Squirrel Packages Manager as Lolbin |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>1Clipboard</li><li>Beaker Browser</li><li>Caret</li><li>Collectie</li><li>Discord</li><li>Figma</li><li>Flow</li><li>Ghost</li><li>GitHub Desktop</li><li>GitKraken</li><li>Hyper</li><li>Insomnia</li><li>JIBO</li><li>Kap</li><li>Kitematic</li><li>Now Desktop</li><li>Postman</li><li>PostmanCanary</li><li>Rambox</li><li>Simplenote</li><li>Skype</li><li>Slack</li><li>SourceTree</li><li>Stride</li><li>Svgsus</li><li>WebTorrent</li><li>WhatsApp</li><li>WordPress.com</li><li>atom</li><li>gitkraken</li><li>slack</li><li>teams</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[http://www.hexacorn.com/blog/2019/03/30/sqirrel-packages-manager-as-a-lolbin-a-k-a-many-electron-apps-are-lolbins-by-default/](http://www.hexacorn.com/blog/2019/03/30/sqirrel-packages-manager-as-a-lolbin-a-k-a-many-electron-apps-are-lolbins-by-default/)</li><li>[http://www.hexacorn.com/blog/2018/08/16/squirrel-as-a-lolbin/](http://www.hexacorn.com/blog/2018/08/16/squirrel-as-a-lolbin/)</li></ul>  |
| **Author**               | Karneades / Markus Neis |


## Detection Rules

### Sigma rule

```
title: Squirrel Lolbin
id: fa4b21c9-0057-4493-b289-2556416ae4d7
status: experimental
description: Detects Possible Squirrel Packages Manager as Lolbin
references:
    - http://www.hexacorn.com/blog/2019/03/30/sqirrel-packages-manager-as-a-lolbin-a-k-a-many-electron-apps-are-lolbins-by-default/
    - http://www.hexacorn.com/blog/2018/08/16/squirrel-as-a-lolbin/
tags:
    - attack.execution
author: Karneades / Markus Neis
date: 2019/11/12
falsepositives:
    - 1Clipboard
    - Beaker Browser
    - Caret
    - Collectie
    - Discord
    - Figma
    - Flow
    - Ghost
    - GitHub Desktop
    - GitKraken
    - Hyper
    - Insomnia
    - JIBO
    - Kap
    - Kitematic
    - Now Desktop
    - Postman
    - PostmanCanary
    - Rambox
    - Simplenote
    - Skype
    - Slack
    - SourceTree
    - Stride
    - Svgsus
    - WebTorrent
    - WhatsApp
    - WordPress.com
    - atom
    - gitkraken
    - slack
    - teams
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\update.exe'                           # Check if folder Name matches executed binary  \\(?P<first>[^\\]*)\\Update.*Start.{2}(?P<second>\1)\.exe (example: https://regex101.com/r/SGSQGz/2)
        CommandLine:
            - '*--processStart*.exe*'
            - '*--processStartAndWait*.exe*'
            - '*--createShortcut*.exe*'
    condition: selection

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "Image.*.*\\update.exe") -and ($_.message -match "CommandLine.*.*--processStart.*.exe.*" -or $_.message -match "CommandLine.*.*--processStartAndWait.*.exe.*" -or $_.message -match "CommandLine.*.*--createShortcut.*.exe.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:(*\\update.exe) AND winlog.event_data.CommandLine.keyword:(*\-\-processStart*.exe* OR *\-\-processStartAndWait*.exe* OR *\-\-createShortcut*.exe*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/fa4b21c9-0057-4493-b289-2556416ae4d7 <<EOF
{
  "metadata": {
    "title": "Squirrel Lolbin",
    "description": "Detects Possible Squirrel Packages Manager as Lolbin",
    "tags": [
      "attack.execution"
    ],
    "query": "(winlog.event_data.Image.keyword:(*\\\\update.exe) AND winlog.event_data.CommandLine.keyword:(*\\-\\-processStart*.exe* OR *\\-\\-processStartAndWait*.exe* OR *\\-\\-createShortcut*.exe*))"
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
                    "query": "(winlog.event_data.Image.keyword:(*\\\\update.exe) AND winlog.event_data.CommandLine.keyword:(*\\-\\-processStart*.exe* OR *\\-\\-processStartAndWait*.exe* OR *\\-\\-createShortcut*.exe*))",
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
        "subject": "Sigma Rule 'Squirrel Lolbin'",
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
(Image.keyword:(*\\update.exe) AND CommandLine.keyword:(*\-\-processStart*.exe* *\-\-processStartAndWait*.exe* *\-\-createShortcut*.exe*))
```


### splunk
    
```
((Image="*\\update.exe") (CommandLine="*--processStart*.exe*" OR CommandLine="*--processStartAndWait*.exe*" OR CommandLine="*--createShortcut*.exe*"))
```


### logpoint
    
```
(Image IN ["*\\update.exe"] CommandLine IN ["*--processStart*.exe*", "*--processStartAndWait*.exe*", "*--createShortcut*.exe*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\update\.exe))(?=.*(?:.*.*--processStart.*\.exe.*|.*.*--processStartAndWait.*\.exe.*|.*.*--createShortcut.*\.exe.*)))'
```



