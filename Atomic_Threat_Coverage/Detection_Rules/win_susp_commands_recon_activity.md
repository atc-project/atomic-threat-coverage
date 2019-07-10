| Title                | Reconnaissance Activity with Net Command                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a set of commands often used in recon stages by different attack groups                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1087: Account Discovery](https://attack.mitre.org/techniques/T1087)</li><li>[T1082: System Information Discovery](https://attack.mitre.org/techniques/T1082)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1087: Account Discovery](../Triggers/T1087.md)</li><li>[T1082: System Information Discovery](../Triggers/T1082.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/haroonmeer/status/939099379834658817](https://twitter.com/haroonmeer/status/939099379834658817)</li><li>[https://twitter.com/c_APT_ure/status/939475433711722497](https://twitter.com/c_APT_ure/status/939475433711722497)</li><li>[https://www.fireeye.com/blog/threat-research/2016/05/targeted_attacksaga.html](https://www.fireeye.com/blog/threat-research/2016/05/targeted_attacksaga.html)</li></ul>  |
| Author               | Florian Roth, Markus Neis |
| Other Tags           | <ul><li>car.2016-03-001</li><li>car.2016-03-001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Reconnaissance Activity with Net Command
status: experimental
description: Detects a set of commands often used in recon stages by different attack groups
references:
    - https://twitter.com/haroonmeer/status/939099379834658817
    - https://twitter.com/c_APT_ure/status/939475433711722497
    - https://www.fireeye.com/blog/threat-research/2016/05/targeted_attacksaga.html
author: Florian Roth, Markus Neis
date: 2018/08/22
modified: 2018/12/11
tags:
    - attack.discovery
    - attack.t1087
    - attack.t1082
    - car.2016-03-001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - tasklist
            - net time
            - systeminfo
            - whoami
            - nbtstat
            - net start
            - '*\net1 start'
            - qprocess
            - nslookup
            - hostname.exe
            - '*\net1 user /domain'
            - '*\net1 group /domain'
            - '*\net1 group "domain admins" /domain'
            - '*\net1 group "Exchange Trusted Subsystem" /domain'
            - '*\net1 accounts /domain'
            - '*\net1 user net localgroup administrators'
            - netstat -an
    timeframe: 15s
    condition: selection | count() by CommandLine > 4
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium

```





### es-qs
    
```

```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Reconnaissance-Activity-with-Net-Command <<EOF\n{\n  "metadata": {\n    "title": "Reconnaissance Activity with Net Command",\n    "description": "Detects a set of commands often used in recon stages by different attack groups",\n    "tags": [\n      "attack.discovery",\n      "attack.t1087",\n      "attack.t1082",\n      "car.2016-03-001"\n    ],\n    "query": "CommandLine.keyword:(tasklist net\\\\ time systeminfo whoami nbtstat net\\\\ start *\\\\\\\\net1\\\\ start qprocess nslookup hostname.exe *\\\\\\\\net1\\\\ user\\\\ \\\\/domain *\\\\\\\\net1\\\\ group\\\\ \\\\/domain *\\\\\\\\net1\\\\ group\\\\ \\\\\\"domain\\\\ admins\\\\\\"\\\\ \\\\/domain *\\\\\\\\net1\\\\ group\\\\ \\\\\\"Exchange\\\\ Trusted\\\\ Subsystem\\\\\\"\\\\ \\\\/domain *\\\\\\\\net1\\\\ accounts\\\\ \\\\/domain *\\\\\\\\net1\\\\ user\\\\ net\\\\ localgroup\\\\ administrators netstat\\\\ \\\\-an)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "15s"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "CommandLine.keyword:(tasklist net\\\\ time systeminfo whoami nbtstat net\\\\ start *\\\\\\\\net1\\\\ start qprocess nslookup hostname.exe *\\\\\\\\net1\\\\ user\\\\ \\\\/domain *\\\\\\\\net1\\\\ group\\\\ \\\\/domain *\\\\\\\\net1\\\\ group\\\\ \\\\\\"domain\\\\ admins\\\\\\"\\\\ \\\\/domain *\\\\\\\\net1\\\\ group\\\\ \\\\\\"Exchange\\\\ Trusted\\\\ Subsystem\\\\\\"\\\\ \\\\/domain *\\\\\\\\net1\\\\ accounts\\\\ \\\\/domain *\\\\\\\\net1\\\\ user\\\\ net\\\\ localgroup\\\\ administrators netstat\\\\ \\\\-an)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          },\n          "aggs": {\n            "by": {\n              "terms": {\n                "field": "CommandLine.keyword",\n                "size": 10,\n                "order": {\n                  "_count": "desc"\n                },\n                "min_doc_count": 5\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.aggregations.by.buckets.0.doc_count": {\n        "gt": 4\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Reconnaissance Activity with Net Command\'",\n        "body": "Hits:\\n{{#aggregations.by.buckets}}\\n {{key}} {{doc_count}}\\n{{/aggregations.by.buckets}}\\n",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```

```


### splunk
    
```
(CommandLine="tasklist" OR CommandLine="net time" OR CommandLine="systeminfo" OR CommandLine="whoami" OR CommandLine="nbtstat" OR CommandLine="net start" OR CommandLine="*\\\\net1 start" OR CommandLine="qprocess" OR CommandLine="nslookup" OR CommandLine="hostname.exe" OR CommandLine="*\\\\net1 user /domain" OR CommandLine="*\\\\net1 group /domain" OR CommandLine="*\\\\net1 group \\"domain admins\\" /domain" OR CommandLine="*\\\\net1 group \\"Exchange Trusted Subsystem\\" /domain" OR CommandLine="*\\\\net1 accounts /domain" OR CommandLine="*\\\\net1 user net localgroup administrators" OR CommandLine="netstat -an") | eventstats count as val by CommandLine| search val > 4
```


### logpoint
    
```
CommandLine IN ["tasklist", "net time", "systeminfo", "whoami", "nbtstat", "net start", "*\\\\net1 start", "qprocess", "nslookup", "hostname.exe", "*\\\\net1 user /domain", "*\\\\net1 group /domain", "*\\\\net1 group \\"domain admins\\" /domain", "*\\\\net1 group \\"Exchange Trusted Subsystem\\" /domain", "*\\\\net1 accounts /domain", "*\\\\net1 user net localgroup administrators", "netstat -an"] | chart count() as val by CommandLine | search val > 4
```


### grep
    
```
grep -P \'^(?:.*tasklist|.*net time|.*systeminfo|.*whoami|.*nbtstat|.*net start|.*.*\\net1 start|.*qprocess|.*nslookup|.*hostname\\.exe|.*.*\\net1 user /domain|.*.*\\net1 group /domain|.*.*\\net1 group "domain admins" /domain|.*.*\\net1 group "Exchange Trusted Subsystem" /domain|.*.*\\net1 accounts /domain|.*.*\\net1 user net localgroup administrators|.*netstat -an)\'
```



