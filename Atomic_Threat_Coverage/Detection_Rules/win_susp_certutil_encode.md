| Title                | Certutil Encode                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious a certutil command that used to encode files, which is sometimes used for data exfiltration                                                                                                                                           |
| ATT&amp;CK Tactic    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | medium |
| False Positives      | <ul><li>unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/certutil](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)</li><li>[https://unit42.paloaltonetworks.com/new-babyshark-malware-targets-u-s-national-security-think-tanks/](https://unit42.paloaltonetworks.com/new-babyshark-malware-targets-u-s-national-security-think-tanks/)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Certutil Encode
id: e62a9f0c-ca1e-46b2-85d5-a6da77f86d1a
status: experimental
description: Detects suspicious a certutil command that used to encode files, which is sometimes used for data exfiltration
references:
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/certutil
    - https://unit42.paloaltonetworks.com/new-babyshark-malware-targets-u-s-national-security-think-tanks/
author: Florian Roth
date: 2019/02/24
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - certutil -f -encode *
            - certutil.exe -f -encode *
            - certutil -encode -f *
            - certutil.exe -encode -f *
    condition: selection
falsepositives:
    - unknown
level: medium

```





### splunk
    
```
(CommandLine="certutil -f -encode *" OR CommandLine="certutil.exe -f -encode *" OR CommandLine="certutil -encode -f *" OR CommandLine="certutil.exe -encode -f *")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Certutil Encode]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Certutil Encode status: experimental \
description: Detects suspicious a certutil command that used to encode files, which is sometimes used for data exfiltration \
references: ['https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/certutil', 'https://unit42.paloaltonetworks.com/new-babyshark-malware-targets-u-s-national-security-think-tanks/'] \
tags:  \
author: Florian Roth \
date:  \
falsepositives: ['unknown'] \
level: medium
action.email.useNSSubject = 1
alert.severity = 1
alert.suppress = 0
alert.track = 1
alert.expires = 24h
counttype = number of events
cron_schedule = */10 * * * *
allow_skew = 50%
schedule_window = auto
description = Detects suspicious a certutil command that used to encode files, which is sometimes used for data exfiltration
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (CommandLine="certutil -f -encode *" OR CommandLine="certutil.exe -f -encode *" OR CommandLine="certutil -encode -f *" OR CommandLine="certutil.exe -encode -f *") | stats values(*) AS * by _time | search NOT [| inputlookup Certutil_Encode_whitelist.csv]
```
