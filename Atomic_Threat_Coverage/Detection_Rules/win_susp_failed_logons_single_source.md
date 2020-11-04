| Title                    | Failed Logins with Different Accounts from Single Source System       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious failed logins with different user accounts from a single source system |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0041_529_logon_failure](../Data_Needed/DN_0041_529_logon_failure.md)</li><li>[DN_0057_4625_account_failed_to_logon](../Data_Needed/DN_0057_4625_account_failed_to_logon.md)</li><li>[DN_0079_4776_computer_attempted_to_validate_the_credentials_for_an_account](../Data_Needed/DN_0079_4776_computer_attempted_to_validate_the_credentials_for_an_account.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Terminal servers</li><li>Jump servers</li><li>Other multiuser systems like Citrix server farms</li><li>Workstations with frequently changing users</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Failed Logins with Different Accounts from Single Source System
id: e98374a6-e2d9-4076-9b5c-11bdb2569995
description: Detects suspicious failed logins with different user accounts from a single source system
author: Florian Roth
date: 2017/01/10
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1078
logsource:
    product: windows
    service: security
detection:
    selection1:
        EventID:
            - 529
            - 4625
        UserName: '*'
        WorkstationName: '*'
    selection2:
        EventID: 4776
        UserName: '*'
        Workstation: '*'
    timeframe: 24h
    condition:
        - selection1 | count(UserName) by WorkstationName > 3
        - selection2 | count(UserName) by Workstation > 3
falsepositives:
    - Terminal servers
    - Jump servers
    - Other multiuser systems like Citrix server farms
    - Workstations with frequently changing users
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Security | where {(($_.ID -eq "529" -or $_.ID -eq "4625") -and $_.message -match "UserName.*.*" -and $_.message -match "WorkstationName.*.*") }  | select WorkstationName, UserName | group WorkstationName | foreach { [PSCustomObject]@{'WorkstationName'=$_.name;'Count'=($_.group.UserName | sort -u).count} }  | sort count -desc | where { $_.count -gt 3 }
```


### es-qs
    
```
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/builtin/win_susp_failed_logons_single_source.yml): Aggregations not implemented for this backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/e98374a6-e2d9-4076-9b5c-11bdb2569995 <<EOF
{
  "metadata": {
    "title": "Failed Logins with Different Accounts from Single Source System",
    "description": "Detects suspicious failed logins with different user accounts from a single source system",
    "tags": [
      "attack.persistence",
      "attack.privilege_escalation",
      "attack.t1078"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:(\"529\" OR \"4625\") AND UserName.keyword:* AND winlog.event_data.WorkstationName.keyword:*)"
  },
  "trigger": {
    "schedule": {
      "interval": "24h"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:(\"529\" OR \"4625\") AND UserName.keyword:* AND winlog.event_data.WorkstationName.keyword:*)",
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
                "field": "winlog.event_data.WorkstationName",
                "size": 10,
                "order": {
                  "_count": "desc"
                },
                "min_doc_count": 4
              },
              "aggs": {
                "agg": {
                  "terms": {
                    "field": "UserName",
                    "size": 10,
                    "order": {
                      "_count": "desc"
                    },
                    "min_doc_count": 4
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
        "gt": 3
      }
    }
  },
  "actions": {
    "send_email": {
      "email": {
        "to": "root@localhost",
        "subject": "Sigma Rule 'Failed Logins with Different Accounts from Single Source System'",
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
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/e98374a6-e2d9-4076-9b5c-11bdb2569995-2 <<EOF
{
  "metadata": {
    "title": "Failed Logins with Different Accounts from Single Source System",
    "description": "Detects suspicious failed logins with different user accounts from a single source system",
    "tags": [
      "attack.persistence",
      "attack.privilege_escalation",
      "attack.t1078"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4776\" AND UserName.keyword:* AND Workstation.keyword:*)"
  },
  "trigger": {
    "schedule": {
      "interval": "24h"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4776\" AND UserName.keyword:* AND Workstation.keyword:*)",
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
                "field": "Workstation",
                "size": 10,
                "order": {
                  "_count": "desc"
                },
                "min_doc_count": 4
              },
              "aggs": {
                "agg": {
                  "terms": {
                    "field": "UserName",
                    "size": 10,
                    "order": {
                      "_count": "desc"
                    },
                    "min_doc_count": 4
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
        "gt": 3
      }
    }
  },
  "actions": {
    "send_email": {
      "email": {
        "to": "root@localhost",
        "subject": "Sigma Rule 'Failed Logins with Different Accounts from Single Source System'",
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
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/builtin/win_susp_failed_logons_single_source.yml): Aggregations not implemented for this backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### splunk
    
```
(source="WinEventLog:Security" (EventCode="529" OR EventCode="4625") UserName="*" WorkstationName="*") | eventstats dc(UserName) as val by WorkstationName | search val > 3
```


### logpoint
    
```
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/builtin/win_susp_failed_logons_single_source.yml): Field mappings in aggregations must be single valued
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*529|.*4625))(?=.*.*)(?=.*.*))'
```



