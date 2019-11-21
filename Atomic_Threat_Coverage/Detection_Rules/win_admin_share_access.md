| Title                | Access to ADMIN$ Share                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects access to $ADMIN share                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1077: Windows Admin Shares](https://attack.mitre.org/techniques/T1077)</li></ul>  |
| Data Needed          | <ul><li>[DN_0033_5140_network_share_object_was_accessed](../Data_Needed/DN_0033_5140_network_share_object_was_accessed.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1077: Windows Admin Shares](../Triggers/T1077.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>Legitimate administrative activity</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Access to ADMIN$ Share
id: 098d7118-55bc-4912-a836-dc6483a8d150
description: Detects access to $ADMIN share
tags:
    - attack.lateral_movement
    - attack.t1077
status: experimental
author: Florian Roth
logsource:
    product: windows
    service: security
    definition: 'The advanced audit policy setting "Object Access > Audit File Share" must be configured for Success/Failure'
detection:
    selection:
        EventID: 5140
        ShareName: Admin$
    filter:
        SubjectUserName: '*$'
    condition: selection and not filter
falsepositives: 
    - Legitimate administrative activity
level: low

```





### splunk
    
```
((EventID="5140" ShareName="Admin$") NOT (SubjectUserName="*$"))
```



