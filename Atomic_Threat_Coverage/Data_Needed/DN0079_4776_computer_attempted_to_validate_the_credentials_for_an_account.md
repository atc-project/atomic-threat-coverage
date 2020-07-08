| Title              | DN0079_4776_computer_attempted_to_validate_the_credentials_for_an_account       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | This event generates every time that a credential validation occurs  using NTLM authentication. This event occurs only on the computer  that is authoritative for the provided credentials. For domain  accounts, the domain controller is authoritative. For local accounts,  the local computer is authoritative |
| **Logging Policy** | <ul><li>[LP0107_windows_audit_credential_validation](../Logging_Policies/LP0107_windows_audit_credential_validation.md)</li></ul> |
| **References**     | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/event-4776.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/event-4776.md)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | Security     |
| **Provider**       | Microsoft-Windows-Security-Auditing    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>PackageName</li><li>TargetUserName</li><li>Workstation</li><li>Status</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
    <EventID>4776</EventID> 
    <Version>0</Version> 
    <Level>0</Level> 
    <Task>14336</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8010000000000000</Keywords> 
    <TimeCreated SystemTime="2015-07-25T04:38:11.003163100Z" /> 
    <EventRecordID>165437</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="500" ThreadID="532" /> 
    <Channel>Security</Channel> 
    <Computer>DC01.contoso.local</Computer> 
    <Security /> 
  </System>
  - <EventData>
    <Data Name="PackageName">MICROSOFT\_AUTHENTICATION\_PACKAGE\_V1\_0</Data> 
    <Data Name="TargetUserName">dadmin</Data> 
    <Data Name="Workstation">WIN81</Data> 
    <Data Name="Status">0xc0000234</Data> 
  </EventData>
</Event>

```




