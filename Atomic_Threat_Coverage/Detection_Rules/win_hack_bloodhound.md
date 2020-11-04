| Title                    | Bloodhound and Sharphound Hack Tool       |
|:-------------------------|:------------------|
| **Description**          | Detects command line parameters used by Bloodhound and Sharphound hack tools |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1087: Account Discovery](https://attack.mitre.org/techniques/T1087)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1087: Account Discovery](../Triggers/T1087.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Other programs that use these command line option and accepts an 'All' parameter</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)</li><li>[https://github.com/BloodHoundAD/SharpHound](https://github.com/BloodHoundAD/SharpHound)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Bloodhound and Sharphound Hack Tool
id: f376c8a7-a2d0-4ddc-aa0c-16c17236d962
description: Detects command line parameters used by Bloodhound and Sharphound hack tools
author: Florian Roth
references:
    - https://github.com/BloodHoundAD/BloodHound
    - https://github.com/BloodHoundAD/SharpHound
date: 2019/12/20
modified: 2019/12/21
tags:
    - attack.discovery
    - attack.t1087
logsource:
    category: process_creation
    product: windows
detection:
    selection1: 
        Image|contains: 
            - '\Bloodhound.exe'
            - '\SharpHound.exe'
    selection2:
        CommandLine|contains: 
            - ' -CollectionMethod All '
            - '.exe -c All -d '
            - 'Invoke-Bloodhound'
            - 'Get-BloodHoundData'
    selection3:
        CommandLine|contains|all: 
            - ' -JsonFolder '
            - ' -ZipFileName '
    selection4:
        CommandLine|contains|all: 
            - ' DCOnly '
            - ' --NoSaveCache '
    condition: 1 of them
falsepositives:
    - Other programs that use these command line option and accepts an 'All' parameter
level: high


```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "Image.*.*\\Bloodhound.exe.*" -or $_.message -match "Image.*.*\\SharpHound.exe.*") -or ($_.message -match "CommandLine.*.* -CollectionMethod All .*" -or $_.message -match "CommandLine.*.*.exe -c All -d .*" -or $_.message -match "CommandLine.*.*Invoke-Bloodhound.*" -or $_.message -match "CommandLine.*.*Get-BloodHoundData.*") -or ($_.message -match "CommandLine.*.* -JsonFolder .*" -and $_.message -match "CommandLine.*.* -ZipFileName .*") -or ($_.message -match "CommandLine.*.* DCOnly .*" -and $_.message -match "CommandLine.*.* --NoSaveCache .*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:(*\\Bloodhound.exe* OR *\\SharpHound.exe*) OR winlog.event_data.CommandLine.keyword:(*\ \-CollectionMethod\ All\ * OR *.exe\ \-c\ All\ \-d\ * OR *Invoke\-Bloodhound* OR *Get\-BloodHoundData*) OR (winlog.event_data.CommandLine.keyword:*\ \-JsonFolder\ * AND winlog.event_data.CommandLine.keyword:*\ \-ZipFileName\ *) OR (winlog.event_data.CommandLine.keyword:*\ DCOnly\ * AND winlog.event_data.CommandLine.keyword:*\ \-\-NoSaveCache\ *))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/f376c8a7-a2d0-4ddc-aa0c-16c17236d962 <<EOF
{
  "metadata": {
    "title": "Bloodhound and Sharphound Hack Tool",
    "description": "Detects command line parameters used by Bloodhound and Sharphound hack tools",
    "tags": [
      "attack.discovery",
      "attack.t1087"
    ],
    "query": "(winlog.event_data.Image.keyword:(*\\\\Bloodhound.exe* OR *\\\\SharpHound.exe*) OR winlog.event_data.CommandLine.keyword:(*\\ \\-CollectionMethod\\ All\\ * OR *.exe\\ \\-c\\ All\\ \\-d\\ * OR *Invoke\\-Bloodhound* OR *Get\\-BloodHoundData*) OR (winlog.event_data.CommandLine.keyword:*\\ \\-JsonFolder\\ * AND winlog.event_data.CommandLine.keyword:*\\ \\-ZipFileName\\ *) OR (winlog.event_data.CommandLine.keyword:*\\ DCOnly\\ * AND winlog.event_data.CommandLine.keyword:*\\ \\-\\-NoSaveCache\\ *))"
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
                    "query": "(winlog.event_data.Image.keyword:(*\\\\Bloodhound.exe* OR *\\\\SharpHound.exe*) OR winlog.event_data.CommandLine.keyword:(*\\ \\-CollectionMethod\\ All\\ * OR *.exe\\ \\-c\\ All\\ \\-d\\ * OR *Invoke\\-Bloodhound* OR *Get\\-BloodHoundData*) OR (winlog.event_data.CommandLine.keyword:*\\ \\-JsonFolder\\ * AND winlog.event_data.CommandLine.keyword:*\\ \\-ZipFileName\\ *) OR (winlog.event_data.CommandLine.keyword:*\\ DCOnly\\ * AND winlog.event_data.CommandLine.keyword:*\\ \\-\\-NoSaveCache\\ *))",
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
        "subject": "Sigma Rule 'Bloodhound and Sharphound Hack Tool'",
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
(Image.keyword:(*\\Bloodhound.exe* *\\SharpHound.exe*) OR CommandLine.keyword:(* \-CollectionMethod All * *.exe \-c All \-d * *Invoke\-Bloodhound* *Get\-BloodHoundData*) OR (CommandLine.keyword:* \-JsonFolder * AND CommandLine.keyword:* \-ZipFileName *) OR (CommandLine.keyword:* DCOnly * AND CommandLine.keyword:* \-\-NoSaveCache *))
```


### splunk
    
```
((Image="*\\Bloodhound.exe*" OR Image="*\\SharpHound.exe*") OR (CommandLine="* -CollectionMethod All *" OR CommandLine="*.exe -c All -d *" OR CommandLine="*Invoke-Bloodhound*" OR CommandLine="*Get-BloodHoundData*") OR (CommandLine="* -JsonFolder *" CommandLine="* -ZipFileName *") OR (CommandLine="* DCOnly *" CommandLine="* --NoSaveCache *"))
```


### logpoint
    
```
(Image IN ["*\\Bloodhound.exe*", "*\\SharpHound.exe*"] OR CommandLine IN ["* -CollectionMethod All *", "*.exe -c All -d *", "*Invoke-Bloodhound*", "*Get-BloodHoundData*"] OR (CommandLine="* -JsonFolder *" CommandLine="* -ZipFileName *") OR (CommandLine="* DCOnly *" CommandLine="* --NoSaveCache *"))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*.*\Bloodhound\.exe.*|.*.*\SharpHound\.exe.*)|.*(?:.*.* -CollectionMethod All .*|.*.*\.exe -c All -d .*|.*.*Invoke-Bloodhound.*|.*.*Get-BloodHoundData.*)|.*(?:.*(?=.*.* -JsonFolder .*)(?=.*.* -ZipFileName .*))|.*(?:.*(?=.*.* DCOnly .*)(?=.*.* --NoSaveCache .*))))'
```



