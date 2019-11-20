| Title                | Suspicious PsExec execution                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | detects execution of psexec or paexec with renamed service name, this rule helps to filter out the noise if psexec is used for legit purposes or if attacker uses a different psexec client other than sysinternal one                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1077: Windows Admin Shares](https://attack.mitre.org/techniques/T1077)</li></ul>  |
| Data Needed          | <ul><li>[DN_0032_5145_network_share_object_was_accessed_detailed](../Data_Needed/DN_0032_5145_network_share_object_was_accessed_detailed.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1077: Windows Admin Shares](../Triggers/T1077.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>nothing observed so far</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://blog.menasec.net/2019/02/threat-hunting-3-detecting-psexec.html](https://blog.menasec.net/2019/02/threat-hunting-3-detecting-psexec.html)</li></ul>  |
| Author               | Samir Bousseaden |


## Detection Rules

### Sigma rule

```
title: Suspicious PsExec execution
id: c462f537-a1e3-41a6-b5fc-b2c2cef9bf82
description: detects execution of psexec or paexec with renamed service name, this rule helps to filter out the noise if psexec is used for legit purposes or if attacker
    uses a different psexec client other than sysinternal one
author: Samir Bousseaden
references:
    - https://blog.menasec.net/2019/02/threat-hunting-3-detecting-psexec.html
tags:
    - attack.lateral_movement
    - attack.t1077
logsource:
    product: windows
    service: security
    description: 'The advanced audit policy setting "Object Access > Audit Detailed File Share" must be configured for Success/Failure'
detection:
    selection1:
        EventID: 5145
        ShareName: \\*\IPC$
        RelativeTargetName:
         - '*-stdin'
         - '*-stdout'
         - '*-stderr'
    selection2:
        EventID: 5145
        ShareName: \\*\IPC$
        RelativeTargetName: 'PSEXESVC*'
    condition: selection1 and not selection2
falsepositives: 
    - nothing observed so far
level: high

```





### splunk
    
```
((EventID="5145" ShareName="\\\\*\\\\IPC$" (RelativeTargetName="*-stdin" OR RelativeTargetName="*-stdout" OR RelativeTargetName="*-stderr")) NOT (EventID="5145" ShareName="\\\\*\\\\IPC$" RelativeTargetName="PSEXESVC*"))
```






### Saved Search for Splunk

```
b'# Generated with Sigma2SplunkAlert\n[Suspicious PsExec execution]\naction.email = 1\naction.email.subject.alert = Splunk Alert: $name$\naction.email.to = test@test.de\naction.email.message.alert = Splunk Alert $name$ triggered \\\nList of interesting fields:   \\\ntitle: Suspicious PsExec execution status:  \\\ndescription: detects execution of psexec or paexec with renamed service name, this rule helps to filter out the noise if psexec is used for legit purposes or if attacker uses a different psexec client other than sysinternal one \\\nreferences: [\'https://blog.menasec.net/2019/02/threat-hunting-3-detecting-psexec.html\'] \\\ntags: [\'attack.lateral_movement\', \'attack.t1077\'] \\\nauthor: Samir Bousseaden \\\ndate:  \\\nfalsepositives: [\'nothing observed so far\'] \\\nlevel: high\naction.email.useNSSubject = 1\nalert.severity = 1\nalert.suppress = 0\nalert.track = 1\nalert.expires = 24h\ncounttype = number of events\ncron_schedule = */10 * * * *\nallow_skew = 50%\nschedule_window = auto\ndescription = detects execution of psexec or paexec with renamed service name, this rule helps to filter out the noise if psexec is used for legit purposes or if attacker uses a different psexec client other than sysinternal one\ndispatch.earliest_time = -10m\ndispatch.latest_time = now\nenableSched = 1\nquantity = 0\nrelation = greater than\nrequest.ui_dispatch_app = sigma_hunting_app\nrequest.ui_dispatch_view = search\nsearch = ((EventID="5145" ShareName="\\\\*\\\\IPC$" (RelativeTargetName="*-stdin" OR RelativeTargetName="*-stdout" OR RelativeTargetName="*-stderr")) NOT (EventID="5145" ShareName="\\\\*\\\\IPC$" RelativeTargetName="PSEXESVC*")) | stats values(*) AS * by _time | search NOT [| inputlookup Suspicious_PsExec_execution_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.lateral_movement,sigma_tag=attack.t1077,level=high"\n\n\n'
```
