| Title              | DN0077_4769_kerberos_service_ticket_was_requested       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | This event generates every time Key Distribution Center gets a Kerberos Ticket Granting  Service (TGS) ticket request. This event generates only on domain controllers. If TGS  issue fails then you will see Failure event with Failure Code field not equal to "0x0" |
| **Logging Policy** | <ul><li>[LP0106_windows_audit_kerberos_service_ticket_operations](../Logging_Policies/LP0106_windows_audit_kerberos_service_ticket_operations.md)</li></ul> |
| **References**     | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/event-4769.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/event-4769.md)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | Security     |
| **Provider**       | Microsoft-Windows-Security-Auditing    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>TargetUserName</li><li>TargetDomainName</li><li>ServiceName</li><li>ServiceSid</li><li>TicketOptions</li><li>TicketEncryptionType</li><li>IpAddress</li><li>IpPort</li><li>Status</li><li>LogonGuid</li><li>TransmittedServices</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" />
    <EventID>4769</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>14337</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2015-08-07T18:13:46.043256100Z" />
    <EventRecordID>166746</EventRecordID>
    <Correlation />
    <Execution ProcessID="520" ThreadID="1496" />
    <Channel>Security</Channel>
    <Computer>DC01.contoso.local</Computer>
  <Security />
  </System>
  - <EventData>
    <Data Name="TargetUserName">dadmin@CONTOSO.LOCAL</Data>
    <Data Name="TargetDomainName">CONTOSO.LOCAL</Data>
    <Data Name="ServiceName">WIN2008R2$</Data>
    <Data Name="ServiceSid">S-1-5-21-3457937927-2839227994-823803824-2102</Data>
    <Data Name="TicketOptions">0x40810000</Data>
    <Data Name="TicketEncryptionType">0x12</Data>
    <Data Name="IpAddress">::ffff:10.0.0.12</Data>
    <Data Name="IpPort">49272</Data>
    <Data Name="Status">0x0</Data>
    <Data Name="LogonGuid">{F85C455E-C66E-205C-6B39-F6C60A7FE453}</Data>
    <Data Name="TransmittedServices">-</Data>
  </EventData>
</Event>

```




