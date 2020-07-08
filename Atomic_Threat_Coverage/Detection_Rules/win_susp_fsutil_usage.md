| Title                    | Fsutil Suspicious Invocation       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious parameters of fsutil (deleting USN journal, configuring it with small size..). Might be used by ransomwares during the attack (seen by NotPetya and others) |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1070: Indicator Removal on Host](https://attack.mitre.org/techniques/T1070)</li><li>[T1551: None](https://attack.mitre.org/techniques/T1551)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1551: None](../Triggers/T1551.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Admin activity</li><li>Scripts and administrative tools used in the monitored environment</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)</li><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070/T1070.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070/T1070.yaml)</li><li>[https://eqllib.readthedocs.io/en/latest/analytics/c91f422a-5214-4b17-8664-c5fcf115c0a2.html](https://eqllib.readthedocs.io/en/latest/analytics/c91f422a-5214-4b17-8664-c5fcf115c0a2.html)</li></ul>  |
| **Author**               | Ecco, E.M. Anhaus, oscd.community |


## Detection Rules

### Sigma rule

```
title: Fsutil Suspicious Invocation
id: add64136-62e5-48ea-807e-88638d02df1e
description: Detects suspicious parameters of fsutil (deleting USN journal, configuring it with small size..). Might be used by ransomwares during the attack (seen by NotPetya and others)
author: Ecco, E.M. Anhaus, oscd.community
date: 2019/09/26
modified: 2019/11/11
level: high
references:
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070/T1070.yaml
    - https://eqllib.readthedocs.io/en/latest/analytics/c91f422a-5214-4b17-8664-c5fcf115c0a2.html
tags:
    - attack.defense_evasion
    - attack.t1070
    - attack.t1551
logsource:
    category: process_creation
    product: windows
detection:
    binary_1:
        Image|endswith: '\fsutil.exe'
    binary_2:
        OriginalFileName: 'fsutil.exe'
    selection:
        CommandLine|contains:
            - 'deletejournal'  # usn deletejournal ==> generally ransomware or attacker
            - 'createjournal'  # usn createjournal ==> can modify config to set it to a tiny size
    condition: (1 of binary_*) and selection
falsepositives:
    - Admin activity
    - Scripts and administrative tools used in the monitored environment

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.ID -eq "1") -and ($_.message -match "Image.*.*\\fsutil.exe" -or $_.message -match "OriginalFileName.*fsutil.exe") -and ($_.message -match "CommandLine.*.*deletejournal.*" -or $_.message -match "CommandLine.*.*createjournal.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.Image.keyword:*\\fsutil.exe OR OriginalFileName:"fsutil.exe") AND winlog.event_data.CommandLine.keyword:(*deletejournal* OR *createjournal*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/add64136-62e5-48ea-807e-88638d02df1e <<EOF
{
  "metadata": {
    "title": "Fsutil Suspicious Invocation",
    "description": "Detects suspicious parameters of fsutil (deleting USN journal, configuring it with small size..). Might be used by ransomwares during the attack (seen by NotPetya and others)",
    "tags": [
      "attack.defense_evasion",
      "attack.t1070",
      "attack.t1551"
    ],
    "query": "((winlog.event_data.Image.keyword:*\\\\fsutil.exe OR OriginalFileName:\"fsutil.exe\") AND winlog.event_data.CommandLine.keyword:(*deletejournal* OR *createjournal*))"
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
                    "query": "((winlog.event_data.Image.keyword:*\\\\fsutil.exe OR OriginalFileName:\"fsutil.exe\") AND winlog.event_data.CommandLine.keyword:(*deletejournal* OR *createjournal*))",
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
        "subject": "Sigma Rule 'Fsutil Suspicious Invocation'",
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
((Image.keyword:*\\fsutil.exe OR OriginalFileName:"fsutil.exe") AND CommandLine.keyword:(*deletejournal* *createjournal*))
```


### splunk
    
```
((Image="*\\fsutil.exe" OR OriginalFileName="fsutil.exe") (CommandLine="*deletejournal*" OR CommandLine="*createjournal*"))
```


### logpoint
    
```
(event_id="1" (Image="*\\fsutil.exe" OR OriginalFileName="fsutil.exe") CommandLine IN ["*deletejournal*", "*createjournal*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?:.*.*\fsutil\.exe|.*fsutil\.exe)))(?=.*(?:.*.*deletejournal.*|.*.*createjournal.*)))'
```



