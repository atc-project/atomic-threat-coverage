| Title                    | DNSCat2 Powershell Implementation Detection Via Process Creation       |
|:-------------------------|:------------------|
| **Description**          | The PowerShell implementation of DNSCat2 calls nslookup to craft queries. Counting nslookup processes spawned by PowerShell will show hundreds or thousands of instances if PS DNSCat2 is active locally. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0011: Command and Control](https://attack.mitre.org/tactics/TA0011)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1071: Application Layer Protocol](https://attack.mitre.org/techniques/T1071)</li><li>[T1071.004: DNS](https://attack.mitre.org/techniques/T1071/004)</li><li>[T1001.003: Protocol Impersonation](https://attack.mitre.org/techniques/T1001/003)</li><li>[T1041: Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1071.004: DNS](../Triggers/T1071.004.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Other powershell scripts that call nslookup.exe</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Cian Heasley |


## Detection Rules

### Sigma rule

```
title: DNSCat2 Powershell Implementation Detection Via Process Creation
id: b11d75d6-d7c1-11ea-87d0-0242ac130003
status: experimental
description: The PowerShell implementation of DNSCat2 calls nslookup to craft queries. Counting nslookup processes spawned by PowerShell will show hundreds or thousands of instances if PS DNSCat2 is active locally.
author: Cian Heasley
reference:
    - https://github.com/lukebaggett/dnscat2-powershell
    - https://blu3-team.blogspot.com/2019/08/powershell-dns-c2-notes.html
    - https://ragged-lab.blogspot.com/2020/06/it-is-always-dns-powershell-edition.html
date: 2020/08/08
tags:
    - attack.command_and_control
    - attack.t1071
    - attack.t1071.004
    - attack.t1001.003
    - attack.t1041
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '*\powershell.exe'
        Image|endswith: '*\nslookup.exe'
        CommandLine|endswith: '*\nslookup.exe'
    condition: selection | count(Image) by ParentImage > 100
fields:
    - Image
    - CommandLine
    - ParentImage
falsepositives:
    - Other powershell scripts that call nslookup.exe
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "ParentImage.*.*\\powershell.exe" -and $_.message -match "Image.*.*\\nslookup.exe" -and $_.message -match "CommandLine.*.*\\nslookup.exe") }  | select ParentImage, Image | group ParentImage | foreach { [PSCustomObject]@{'ParentImage'=$_.name;'Count'=($_.group.Image | sort -u).count} }  | sort count -desc | where { $_.count -gt 100 }
```


### es-qs
    
```
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/process_creation/win_dnscat2_powershell_implementation.yml): Aggregations not implemented for this backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/b11d75d6-d7c1-11ea-87d0-0242ac130003 <<EOF
{
  "metadata": {
    "title": "DNSCat2 Powershell Implementation Detection Via Process Creation",
    "description": "The PowerShell implementation of DNSCat2 calls nslookup to craft queries. Counting nslookup processes spawned by PowerShell will show hundreds or thousands of instances if PS DNSCat2 is active locally.",
    "tags": [
      "attack.command_and_control",
      "attack.t1071",
      "attack.t1071.004",
      "attack.t1001.003",
      "attack.t1041"
    ],
    "query": "(winlog.event_data.ParentImage.keyword:*\\\\powershell.exe AND winlog.event_data.Image.keyword:*\\\\nslookup.exe AND winlog.event_data.CommandLine.keyword:*\\\\nslookup.exe)"
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
                    "query": "(winlog.event_data.ParentImage.keyword:*\\\\powershell.exe AND winlog.event_data.Image.keyword:*\\\\nslookup.exe AND winlog.event_data.CommandLine.keyword:*\\\\nslookup.exe)",
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
          },
          "aggs": {
            "by": {
              "terms": {
                "field": "winlog.event_data.ParentImage",
                "size": 10,
                "order": {
                  "_count": "desc"
                },
                "min_doc_count": 101
              },
              "aggs": {
                "agg": {
                  "terms": {
                    "field": "winlog.event_data.Image",
                    "size": 10,
                    "order": {
                      "_count": "desc"
                    },
                    "min_doc_count": 101
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
      "ctx.payload.aggregations.by.buckets.0.agg.buckets.0.doc_count": {
        "gt": 100
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
        "subject": "Sigma Rule 'DNSCat2 Powershell Implementation Detection Via Process Creation'",
        "body": "Hits:\n{{#aggregations.agg.buckets}}\n {{key}} {{doc_count}}\n\n{{#by.buckets}}\n-- {{key}} {{doc_count}}\n{{/by.buckets}}\n\n{{/aggregations.agg.buckets}}\n",
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
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/process_creation/win_dnscat2_powershell_implementation.yml): Aggregations not implemented for this backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### splunk
    
```
(ParentImage="*\\powershell.exe" Image="*\\nslookup.exe" CommandLine="*\\nslookup.exe") | eventstats dc(Image) as val by ParentImage | search val > 100 | table Image,CommandLine,ParentImage
```


### logpoint
    
```
(ParentImage="*\\powershell.exe" Image="*\\nslookup.exe" CommandLine="*\\nslookup.exe") | chart count(Image) as val by ParentImage | search val > 100
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\powershell\.exe)(?=.*.*\nslookup\.exe)(?=.*.*\nslookup\.exe))'
```



