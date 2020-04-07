| Title                    | AD User Enumeration       |
|:-------------------------|:------------------|
| **Description**          | Detects access to a domain user from a non-machine account |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1087: Account Discovery](https://attack.mitre.org/techniques/T1087)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0030_4662_operation_was_performed_on_an_object](../Data_Needed/DN_0030_4662_operation_was_performed_on_an_object.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1087: Account Discovery](../Triggers/T1087.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Administrators configuring new users.</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.specterops.io/assets/resources/an_ace_up_the_sleeve.pdf](https://www.specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)</li><li>[http://www.stuffithoughtiknew.com/2019/02/detecting-bloodhound.html](http://www.stuffithoughtiknew.com/2019/02/detecting-bloodhound.html)</li><li>[https://docs.microsoft.com/en-us/windows/win32/adschema/attributes-all](https://docs.microsoft.com/en-us/windows/win32/adschema/attributes-all)</li></ul>  |
| **Author**               | Maxime Thiebaut (@0xThiebaut) |


## Detection Rules

### Sigma rule

```
title: AD User Enumeration
id: ab6bffca-beff-4baa-af11-6733f296d57a
description: Detects access to a domain user from a non-machine account
status: experimental
date: 2020/03/30
author: Maxime Thiebaut (@0xThiebaut)
references:
    - https://www.specterops.io/assets/resources/an_ace_up_the_sleeve.pdf
    - http://www.stuffithoughtiknew.com/2019/02/detecting-bloodhound.html
    - https://docs.microsoft.com/en-us/windows/win32/adschema/attributes-all # For further investigation of the accessed properties
tags:
    - attack.discovery
    - attack.t1087
logsource:
    product: windows
    service: security
    definition: Requires the "Read all properties" permission on the user object to be audited for the "Everyone" principal
detection:
    selection:
        EventID: 4662
        ObjectType|contains: # Using contains as the data commonly is structured as "%{bf967aba-0de6-11d0-a285-00aa003049e2}"
            - 'bf967aba-0de6-11d0-a285-00aa003049e2' # The user class (https://docs.microsoft.com/en-us/windows/win32/adschema/c-user)
    filter:
        - SubjectUserName|endswith: '$' # Exclude machine accounts
        - SubjectUserName|startswith: 'MSOL_' # https://docs.microsoft.com/en-us/azure/active-directory/hybrid/reference-connect-accounts-permissions#ad-ds-connector-account
    condition: selection and not filter
falsepositives:
    - Administrators configuring new users.
level: medium

```





### es-qs
    
```
((EventID:"4662" AND ObjectType.keyword:(*bf967aba\\-0de6\\-11d0\\-a285\\-00aa003049e2*)) AND (NOT (SubjectUserName.keyword:*$ OR SubjectUserName.keyword:MSOL_*)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/ab6bffca-beff-4baa-af11-6733f296d57a <<EOF\n{\n  "metadata": {\n    "title": "AD User Enumeration",\n    "description": "Detects access to a domain user from a non-machine account",\n    "tags": [\n      "attack.discovery",\n      "attack.t1087"\n    ],\n    "query": "((EventID:\\"4662\\" AND ObjectType.keyword:(*bf967aba\\\\-0de6\\\\-11d0\\\\-a285\\\\-00aa003049e2*)) AND (NOT (SubjectUserName.keyword:*$ OR SubjectUserName.keyword:MSOL_*)))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((EventID:\\"4662\\" AND ObjectType.keyword:(*bf967aba\\\\-0de6\\\\-11d0\\\\-a285\\\\-00aa003049e2*)) AND (NOT (SubjectUserName.keyword:*$ OR SubjectUserName.keyword:MSOL_*)))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'AD User Enumeration\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:"4662" AND ObjectType.keyword:(*bf967aba\\-0de6\\-11d0\\-a285\\-00aa003049e2*)) AND (NOT (SubjectUserName.keyword:*$ OR SubjectUserName.keyword:MSOL_*)))
```


### splunk
    
```
((EventID="4662" (ObjectType="*bf967aba-0de6-11d0-a285-00aa003049e2*")) NOT (SubjectUserName="*$" OR SubjectUserName="MSOL_*"))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" (event_id="4662" ObjectType IN ["*bf967aba-0de6-11d0-a285-00aa003049e2*"])  -(SubjectUserName="*$" OR SubjectUserName="MSOL_*"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*4662)(?=.*(?:.*.*bf967aba-0de6-11d0-a285-00aa003049e2.*))))(?=.*(?!.*(?:.*(?:.*(?=.*.*\\$)|.*(?=.*MSOL_.*))))))'
```



