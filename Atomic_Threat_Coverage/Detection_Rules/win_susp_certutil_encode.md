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



