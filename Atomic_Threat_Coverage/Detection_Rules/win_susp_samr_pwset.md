| Title                    | Possible Remote Password Change Through SAMR       |
|:-------------------------|:------------------|
| **Description**          | Detects a possible remote NTLM hash change through SAMR API SamiChangePasswordUser() or SamSetInformationUser(). "Audit User Account Management" in "Advanced Audit Policy Configuration" has to be enabled in your local security policy / GPO to see this events. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1212: Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0027_4738_user_account_was_changed](../Data_Needed/DN_0027_4738_user_account_was_changed.md)</li><li>[DN_0032_5145_network_share_object_was_accessed_detailed](../Data_Needed/DN_0032_5145_network_share_object_was_accessed_detailed.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      |  There are no documented False Positives for this Detection Rule yet  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Dimitrios Slamaris |


## Detection Rules

### Sigma rule

```
title: Possible Remote Password Change Through SAMR
id: 7818b381-5eb1-4641-bea5-ef9e4cfb5951
description: Detects a possible remote NTLM hash change through SAMR API SamiChangePasswordUser() or SamSetInformationUser(). "Audit User Account Management" in "Advanced
    Audit Policy Configuration" has to be enabled in your local security policy / GPO to see this events.
author: Dimitrios Slamaris
date: 2017/06/09
tags:
    - attack.credential_access
    - attack.t1212
logsource:
    product: windows
    service: security
detection:
    samrpipe:
        EventID: 5145
        RelativeTargetName: samr
    passwordchanged:
        EventID: 4738
    passwordchanged_filter:
        PasswordLastSet: null
    timeframe: 15s
    condition: ( passwordchanged and not passwordchanged_filter ) | near samrpipe
level: medium

```





### powershell
    
```
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/builtin/win_susp_samr_pwset.yml): Only COUNT aggregation function is implemented for this backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### es-qs
    
```
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/builtin/win_susp_samr_pwset.yml): Aggregations not implemented for this backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/7818b381-5eb1-4641-bea5-ef9e4cfb5951 <<EOF
{
  "metadata": {
    "title": "Possible Remote Password Change Through SAMR",
    "description": "Detects a possible remote NTLM hash change through SAMR API SamiChangePasswordUser() or SamSetInformationUser(). \"Audit User Account Management\" in \"Advanced Audit Policy Configuration\" has to be enabled in your local security policy / GPO to see this events.",
    "tags": [
      "attack.credential_access",
      "attack.t1212"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4738\" AND (NOT (NOT _exists_:PasswordLastSet)))"
  },
  "trigger": {
    "schedule": {
      "interval": "15s"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4738\" AND (NOT (NOT _exists_:PasswordLastSet)))",
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
        "subject": "Sigma Rule 'Possible Remote Password Change Through SAMR'",
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
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/builtin/win_susp_samr_pwset.yml): Aggregations not implemented for this backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### splunk
    
```
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/builtin/win_susp_samr_pwset.yml): The 'near' aggregation operator is not yet implemented for this backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### logpoint
    
```
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/builtin/win_susp_samr_pwset.yml): The 'near' aggregation operator is not yet implemented for this backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### grep
    
```
grep -P '^(?:.*(?=.*4738)(?=.*(?!.*(?:.*(?=.*(?!PasswordLastSet))))))'
```



