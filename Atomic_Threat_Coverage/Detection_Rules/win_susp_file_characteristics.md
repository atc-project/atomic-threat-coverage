| Title                    | Suspicious File Characteristics Due to Missing Fields       |
|:-------------------------|:------------------|
| **Description**          | Detects Executables in the Downloads folder without FileVersion,Description,Product,Company likely created with py2exe |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1059.006: Python](https://attack.mitre.org/techniques/T1059/006)</li><li>[T1064: Scripting](https://attack.mitre.org/techniques/T1064)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://securelist.com/muddywater/88059/](https://securelist.com/muddywater/88059/)</li><li>[https://www.virustotal.com/#/file/276a765a10f98cda1a38d3a31e7483585ca3722ecad19d784441293acf1b7beb/detection](https://www.virustotal.com/#/file/276a765a10f98cda1a38d3a31e7483585ca3722ecad19d784441293acf1b7beb/detection)</li></ul>  |
| **Author**               | Markus Neis, Sander Wiebing |


## Detection Rules

### Sigma rule

```
title: Suspicious File Characteristics Due to Missing Fields
id: 9637e8a5-7131-4f7f-bdc7-2b05d8670c43
description: Detects Executables in the Downloads folder without FileVersion,Description,Product,Company likely created with py2exe
status: experimental
references:
    - https://securelist.com/muddywater/88059/
    - https://www.virustotal.com/#/file/276a765a10f98cda1a38d3a31e7483585ca3722ecad19d784441293acf1b7beb/detection
author: Markus Neis, Sander Wiebing
date: 2018/11/22
modified: 2020/05/26
tags:
    - attack.execution
    - attack.t1059.006
    - attack.defense_evasion        # an old one
    - attack.t1064      # an old one
logsource:
    product: windows
    category: process_creation
detection:
    selection1:
        Description: '\?'
        FileVersion: '\?'
    selection2:
        Description: '\?'
        Product: '\?'
    selection3:
        Description: '\?'
        Company: '\?'
    folder:
        Image: '*\Downloads\\*'
    condition: (selection1 or selection2 or selection3) and folder
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: medium

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Description.*\?" -and ($_.message -match "FileVersion.*\?" -or $_.message -match "Product.*\?" -or $_.message -match "Company.*\?") -and $_.message -match "Image.*.*\\Downloads\\.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Description:"\?" AND (FileVersion:"\?" OR Product:"\?" OR Company:"\?") AND winlog.event_data.Image.keyword:*\\Downloads\\*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/9637e8a5-7131-4f7f-bdc7-2b05d8670c43 <<EOF
{
  "metadata": {
    "title": "Suspicious File Characteristics Due to Missing Fields",
    "description": "Detects Executables in the Downloads folder without FileVersion,Description,Product,Company likely created with py2exe",
    "tags": [
      "attack.execution",
      "attack.t1059.006",
      "attack.defense_evasion",
      "attack.t1064"
    ],
    "query": "(winlog.event_data.Description:\"\\?\" AND (FileVersion:\"\\?\" OR Product:\"\\?\" OR Company:\"\\?\") AND winlog.event_data.Image.keyword:*\\\\Downloads\\\\*)"
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
                    "query": "(winlog.event_data.Description:\"\\?\" AND (FileVersion:\"\\?\" OR Product:\"\\?\" OR Company:\"\\?\") AND winlog.event_data.Image.keyword:*\\\\Downloads\\\\*)",
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
        "subject": "Sigma Rule 'Suspicious File Characteristics Due to Missing Fields'",
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
(Description:"\?" AND (FileVersion:"\?" OR Product:"\?" OR Company:"\?") AND Image.keyword:*\\Downloads\\*)
```


### splunk
    
```
(Description="\?" (FileVersion="\?" OR Product="\?" OR Company="\?") Image="*\\Downloads\\*") | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(Description="\?" (FileVersion="\?" OR Product="\?" OR Company="\?") Image="*\\Downloads\\*")
```


### grep
    
```
grep -P '^(?:.*(?=.*\?)(?=.*(?:.*(?:.*\?|.*\?|.*\?)))(?=.*.*\Downloads\\.*))'
```



