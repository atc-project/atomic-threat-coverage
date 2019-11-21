| Title                | Possible Remote Password Change Through SAMR                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a possible remote NTLM hash change through SAMR API SamiChangePasswordUser() or SamSetInformationUser(). "Audit User Account Management" in "Advanced Audit Policy Configuration" has to be enabled in your local security policy / GPO to see this events.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1212: Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212)</li></ul>  |
| Data Needed          | <ul><li>[DN_0027_4738_user_account_was_changed](../Data_Needed/DN_0027_4738_user_account_was_changed.md)</li><li>[DN_0032_5145_network_share_object_was_accessed_detailed](../Data_Needed/DN_0032_5145_network_share_object_was_accessed_detailed.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1212: Exploitation for Credential Access](../Triggers/T1212.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      |  There are no documented False Positives for this Detection Rule yet  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Dimitrios Slamaris |


## Detection Rules

### Sigma rule

```
title: Possible Remote Password Change Through SAMR
id: 7818b381-5eb1-4641-bea5-ef9e4cfb5951
description: Detects a possible remote NTLM hash change through SAMR API SamiChangePasswordUser() or SamSetInformationUser(). "Audit User Account Management" in "Advanced
    Audit Policy Configuration" has to be enabled in your local security policy / GPO to see this events.
author: Dimitrios Slamaris
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





### splunk
    
```

```



