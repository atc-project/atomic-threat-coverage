| Title              | DN_0050_1102_audit_log_was_cleared       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | Event 1102 is created whenever the Security log is cleared,  REGARDLESS of the status of the Audit System Events audit policy |
| **Logging Policy** | <ul><li> Not existing </li></ul> |
| **References**     | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/event-1102.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/event-1102.md)</li><li>[https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=1102](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=1102)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | Security     |
| **Provider**       | Microsoft-Windows-Eventlog    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>SubjectUserSid</li><li>SubjectUserName</li><li>SubjectDomainName</li><li>SubjectLogonId</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Eventlog" Guid="{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}" /> 
    <EventID>1102</EventID> 
    <Version>0</Version> 
    <Level>4</Level> 
    <Task>104</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x4020000000000000</Keywords> 
    <TimeCreated SystemTime="2015-10-16T00:39:58.656871200Z" /> 
    <EventRecordID>1087729</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="820" ThreadID="2644" /> 
    <Channel>Security</Channel> 
    <Computer>DC01.contoso.local</Computer> 
    <Security /> 
  </System>
  - <UserData>
    - <LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">
      <SubjectUserSid>S-1-5-21-3457937927-2839227994-823803824-1104</SubjectUserSid> 
      <SubjectUserName>dadmin</SubjectUserName> 
      <SubjectDomainName>CONTOSO</SubjectDomainName> 
      <SubjectLogonId>0x55cd1d</SubjectLogonId> 
    </LogFileCleared>
  </UserData>
</Event>

```




