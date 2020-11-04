| Title                    | Suspicious File Characteristics Due to Missing Fields       |
|:-------------------------|:------------------|
| **Description**          | Detects Executables without FileVersion,Description,Product,Company likely created with py2exe |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1064: Scripting](https://attack.mitre.org/techniques/T1064)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0011_7_windows_sysmon_image_loaded](../Data_Needed/DN_0011_7_windows_sysmon_image_loaded.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1064: Scripting](../Triggers/T1064.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://securelist.com/muddywater/88059/](https://securelist.com/muddywater/88059/)</li><li>[https://www.virustotal.com/#/file/276a765a10f98cda1a38d3a31e7483585ca3722ecad19d784441293acf1b7beb/detection](https://www.virustotal.com/#/file/276a765a10f98cda1a38d3a31e7483585ca3722ecad19d784441293acf1b7beb/detection)</li></ul>  |
| **Author**               | Markus Neis |


## Detection Rules

### Sigma rule

```
title: Suspicious File Characteristics Due to Missing Fields
id: 9637e8a5-7131-4f7f-bdc7-2b05d8670c43
description: Detects Executables without FileVersion,Description,Product,Company likely created with py2exe
status: experimental
references:
    - https://securelist.com/muddywater/88059/
    - https://www.virustotal.com/#/file/276a765a10f98cda1a38d3a31e7483585ca3722ecad19d784441293acf1b7beb/detection
author: Markus Neis
date: 2018/11/22
modified: 2019/11/09
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1064
logsource:
    product: windows
    service: sysmon
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
    condition: 1 of them
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.message -match "Description.*\?" -and ($_.message -match "FileVersion.*\?" -or $_.message -match "Product.*\?" -or $_.message -match "Company.*\?")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_data.Description:"\?" AND (FileVersion:"\?" OR Product:"\?" OR Company:"\?"))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/9637e8a5-7131-4f7f-bdc7-2b05d8670c43 <<EOF
{
  "metadata": {
    "title": "Suspicious File Characteristics Due to Missing Fields",
    "description": "Detects Executables without FileVersion,Description,Product,Company likely created with py2exe",
    "tags": [
      "attack.defense_evasion",
      "attack.execution",
      "attack.t1064"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_data.Description:\"\\?\" AND (FileVersion:\"\\?\" OR Product:\"\\?\" OR Company:\"\\?\"))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_data.Description:\"\\?\" AND (FileVersion:\"\\?\" OR Product:\"\\?\" OR Company:\"\\?\"))",
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
(Description:"\?" AND (FileVersion:"\?" OR Product:"\?" OR Company:"\?"))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" Description="\?" (FileVersion="\?" OR Product="\?" OR Company="\?")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(Description="\?" (FileVersion="\?" OR Product="\?" OR Company="\?"))
```


### grep
    
```
grep -P '^(?:.*(?=.*\?)(?=.*(?:.*(?:.*\?|.*\?|.*\?))))'
```



