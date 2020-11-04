| Title              | DN_0057_4625_account_failed_to_logon       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | An account failed to log on |
| **Logging Policy** | <ul><li>[LP0004_windows_audit_logon](../Logging_Policies/LP0004_windows_audit_logon.md)</li></ul> |
| **References**     | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/event-4625.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/event-4625.md)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | Security     |
| **Provider**       | Microsoft-Windows-Security-Auditing    |
| **Fields**         | <ul><li>EventID</li><li>AccountName</li><li>Hostname</li><li>Computer</li><li>SubjectUserSid</li><li>SubjectUserName</li><li>SubjectDomainName</li><li>SubjectLogonId</li><li>TargetUserSid</li><li>TargetUserName</li><li>TargetDomainName</li><li>Status</li><li>FailureReason</li><li>SubStatus</li><li>LogonType</li><li>LogonProcessName</li><li>AuthenticationPackageName</li><li>WorkstationName</li><li>TransmittedServices</li><li>LmPackageName</li><li>KeyLength</li><li>ProcessId</li><li>ProcessName</li><li>IpAddress</li><li>IpPort</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
    <EventID>4625</EventID> 
    <Version>0</Version> 
    <Level>0</Level> 
    <Task>12546</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8010000000000000</Keywords> 
    <TimeCreated SystemTime="2015-09-08T22:54:54.962511700Z" /> 
    <EventRecordID>229977</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="516" ThreadID="3240" /> 
    <Channel>Security</Channel> 
    <Computer>DC01.contoso.local</Computer> 
    <Security /> 
  </System>
  - <EventData>
    <Data Name="SubjectUserSid">S-1-5-18</Data> 
    <Data Name="SubjectUserName">DC01$</Data> 
    <Data Name="SubjectDomainName">CONTOSO</Data> 
    <Data Name="SubjectLogonId">0x3e7</Data> 
    <Data Name="TargetUserSid">S-1-0-0</Data> 
    <Data Name="TargetUserName">Auditor</Data> 
    <Data Name="TargetDomainName">CONTOSO</Data> 
    <Data Name="Status">0xc0000234</Data> 
    <Data Name="FailureReason">%%2307</Data> 
    <Data Name="SubStatus">0x0</Data> 
    <Data Name="LogonType">2</Data> 
    <Data Name="LogonProcessName">User32</Data> 
    <Data Name="AuthenticationPackageName">Negotiate</Data> 
    <Data Name="WorkstationName">DC01</Data> 
    <Data Name="TransmittedServices">-</Data> 
    <Data Name="LmPackageName">-</Data> 
    <Data Name="KeyLength">0</Data> 
    <Data Name="ProcessId">0x1bc</Data> 
    <Data Name="ProcessName">C:\\Windows\\System32\\winlogon.exe</Data> 
    <Data Name="IpAddress">127.0.0.1</Data> 
    <Data Name="IpPort">0</Data> 
  </EventData>
</Event>

```




