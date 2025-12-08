use crate::sensors::SensorConfig;

use std::ptr::null_mut;
use std::net::Ipv4Addr;
use std::ffi::{OsStr, c_void};
use std::fs::File;
use std::io::Read;


use sha2::{Sha256, Digest};

use serde::{Deserialize, Serialize};

#[cfg(target_os = "windows")]
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

#[cfg(target_os = "windows")]
use std::{mem::size_of, os::windows::ffi::OsStrExt};

#[cfg(target_os = "windows")]
use windows::core::PCWSTR;

#[cfg(target_os = "windows")]
use windows::Win32::{
    Foundation::{CloseHandle, HWND, HANDLE, HMODULE, FILETIME},
    System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
        PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    },
    System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, OpenProcessToken, GetProcessTimes},
    System::ProcessStatus::{K32GetModuleFileNameExW, K32EnumProcessModules},
    
    System::SystemInformation::{
        GetSystemTimeAsFileTime,
        GetSystemInfo,
        SYSTEM_INFO,
    },

    NetworkManagement::IpHelper::{
        GetExtendedTcpTable,
        MIB_TCPTABLE_OWNER_PID,
        TCP_TABLE_CLASS,
    },

    Security::WinTrust::{
        WinVerifyTrust,
        WINTRUST_ACTION_GENERIC_VERIFY_V2,
        WINTRUST_DATA,
        WINTRUST_DATA_0,
        WINTRUST_FILE_INFO,
        WTD_CHOICE_FILE,
        WTD_UI_NONE,
        WTD_REVOKE_NONE,
    },
    Security::Cryptography::{
        CryptQueryObject,
        CertEnumCertificatesInStore,
        CertCloseStore,
        CertGetNameStringW,
        HCERTSTORE,
        CERT_QUERY_OBJECT_FILE,
        CERT_QUERY_CONTENT_FLAG_ALL,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
    },
    Security::{
        TOKEN_QUERY,
        GetTokenInformation,
        TOKEN_MANDATORY_LABEL,
        GetSidSubAuthorityCount,
        GetSidSubAuthority,
        TokenIntegrityLevel,
    }
};

#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub proto: String,
    pub local: String,
    pub remote: String,
    pub state: String,
}

#[derive(Debug, Serialize, Default, Deserialize)]
pub struct DerivedFlags {
    pub path_is_temp_or_appdata: bool,
    pub parent_is_office_or_browser: bool,
    pub has_outbound_network: bool,
    pub is_signed_and_trusted: bool,
    pub elevated_integrity: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub exe_path: String,
    pub command_line: Option<String>,
    pub user: Option<String>,
    pub domain: Option<String>,
    pub integrity_level: Option<String>,
    pub is_signed: Option<bool>,
    pub signer_name: Option<String>,
    pub sha256: Option<String>,
    pub cpu_percent: Option<f32>,
    pub working_set_mb: Option<u64>,
    pub thread_count: u32,
    pub modules: Vec<String>,
    pub connections: Vec<ConnectionInfo>,
    pub derived_flags: DerivedFlags,
}




#[cfg(target_os = "windows")]
#[repr(C)]
struct UNICODE_STRING {
    Length: u16,
    MaximumLength: u16,
    Buffer: *mut u16,
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct RTL_USER_PROCESS_PARAMETERS {
    Reserved1: [u8; 16],
    Reserved2: [*mut c_void; 10],
    ImagePathName: UNICODE_STRING,
    CommandLine: UNICODE_STRING,
}



//PEB WALKING
#[cfg(target_os = "windows")]
#[repr(C)]
struct PEB {
    Reserved1: [u8; 2],
    BeingDebugged: u8,
    Reserved2: [u8; 1],
    Reserved3: [*mut c_void; 2],
    Ldr: *mut c_void,
    ProcessParameters: *mut RTL_USER_PROCESS_PARAMETERS,
    // we don’t care about the rest
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct PROCESS_BASIC_INFORMATION {
    Reserved1: *mut c_void,
    PebBaseAddress: *mut PEB,
    Reserved2: [*mut c_void; 2],
    UniqueProcessId: usize,
    Reserved3: *mut c_void,
}

#[cfg(target_os = "windows")]
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryInformationProcess(
        ProcessHandle: HANDLE,
        ProcessInformationClass: u32,   // 0 = ProcessBasicInformation
        ProcessInformation: *mut c_void,
        ProcessInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> i32; // NTSTATUS
}

#[cfg(target_os = "windows")]
const PROCESS_BASIC_INFORMATION_CLASS: u32 = 0;




#[cfg(target_os= "windows")]
pub fn collect_process_info() -> Vec<ProcessInfo>
{

    let mut count = 0;

    let mut results: Vec<ProcessInfo> = Vec::new();

    unsafe 
    {
        //snapshot of all processes

        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        {
            Ok(handle) => {
                //println!("Snapshot handle: {:?}", handle);
                handle
            }
            Err(e) =>
            {

                eprintln!("CreateToolhelp32Snapshot (taking snapshot of processes) failed: {e:?}");
                std::process::exit(1); 

            }
        };


        //process struct
        let mut entry = PROCESSENTRY32W::default();

        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        //get first process

        match Process32FirstW(snapshot, &mut entry)
        {
            Ok(_process) => {

            }

            Err(_e)=> {
                eprint!("Process32FirstW failed");
                let _ = CloseHandle(snapshot);
            }
            
        }

        loop   
        {
            count += 1;

            let pid = entry.th32ProcessID;
            let ppid = entry.th32ParentProcessID;
            let thread_count = entry.cntThreads;

            // Extract exe name from szExeFile (UTF-16, null-terminated)
            let exe_name = {
                let raw = &entry.szExeFile;
                let len = raw.iter().position(|c| *c == 0).unwrap_or(raw.len());
                String::from_utf16_lossy(&raw[..len])
            };


            //Gather ALL THE DATA
            let exe_path = get_process_path(pid).unwrap_or_else( || exe_name.clone());
            let is_signed = Some(get_is_signed(pid));
            let signer_name = get_signer_name(pid);
            let connections = get_connections(pid);
            let integrity_level = get_integrity_level(pid);
            let modules = get_modules(pid);
            let sha256 = get_sha256(pid);
            let cpu_percent = get_cpu_percentage(pid);
            let command_line = get_command_line(pid);

            results.push(ProcessInfo {
                pid,
                ppid,
                exe_path,
                command_line,          
                user: None,                  // TODO
                domain: None,                // TODO
                integrity_level,      
                is_signed,             
                signer_name,           
                sha256,              
                cpu_percent,           
                working_set_mb: None,        // TODO
                thread_count,
                modules,         
                connections,     
                derived_flags: DerivedFlags::default(),
            });

            match Process32NextW(snapshot, &mut entry)
            {
                Ok(_process) => {
                    //println!("{:?}", _process);
                }
    
                Err(_e)=> {
                    break
                }
                
            }

        }

        let _ = CloseHandle(snapshot);

    }

    //println!("Number of processes running on this computer: {}", count);

    results
}

#[cfg(target_os = "windows")]
fn get_command_line(pid: u32) -> Option<String> {
    unsafe {
        // Open the process so we can query its PEB and read memory
        let access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
        let h_process = match OpenProcess(access, false, pid) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("OpenProcess({pid}) for command line failed: {e:?}");
                return None;
            }
        };

        // Ask ntdll for basic process info -> gives us PEB address
        let mut pbi: PROCESS_BASIC_INFORMATION = std::mem::zeroed();
        let mut return_len: u32 = 0;

        let status = NtQueryInformationProcess(
            h_process,
            PROCESS_BASIC_INFORMATION_CLASS,                  // 0
            &mut pbi as *mut _ as *mut c_void,
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_len,
        );

        if status != 0 {
            // Non-zero NTSTATUS = failure
            eprintln!("NtQueryInformationProcess({pid}) failed with NTSTATUS=0x{status:08x}");
            let _ = CloseHandle(h_process);
            return None;
        }

        if pbi.PebBaseAddress.is_null() {
            let _ = CloseHandle(h_process);
            return None;
        }

        // --- Read the PEB from the remote process ---
        let mut peb: PEB = std::mem::zeroed();
        let mut bytes_read: usize = 0;

        let res = ReadProcessMemory(
            h_process,
            pbi.PebBaseAddress as *const c_void,
            &mut peb as *mut _ as *mut c_void,
            std::mem::size_of::<PEB>(),
            Some(&mut bytes_read as *mut usize),
        );

        if let Err(e) = res {
            eprintln!("ReadProcessMemory({pid}, PEB) failed: {e:?}");
            let _ = CloseHandle(h_process);
            return None;
        }

        if bytes_read < std::mem::size_of::<PEB>() {
            eprintln!("ReadProcessMemory({pid}, PEB) short read");
            let _ = CloseHandle(h_process);
            return None;
        }

        if peb.ProcessParameters.is_null() {
            let _ = CloseHandle(h_process);
            return None;
        }

        // --- Read RTL_USER_PROCESS_PARAMETERS ---
        let mut params: RTL_USER_PROCESS_PARAMETERS = std::mem::zeroed();
        let mut bytes_read2: usize = 0;

        let res = ReadProcessMemory(
            h_process,
            peb.ProcessParameters as *const c_void,
            &mut params as *mut _ as *mut c_void,
            std::mem::size_of::<RTL_USER_PROCESS_PARAMETERS>(),
            Some(&mut bytes_read2 as *mut usize),
        );

        if let Err(e) = res {
            eprintln!("ReadProcessMemory({pid}, ProcessParameters) failed: {e:?}");
            let _ = CloseHandle(h_process);
            return None;
        }

        if bytes_read2 < std::mem::size_of::<RTL_USER_PROCESS_PARAMETERS>() {
            eprintln!("ReadProcessMemory({pid}, ProcessParameters) short read");
            let _ = CloseHandle(h_process);
            return None;
        }

        let cmd = params.CommandLine;

        if cmd.Length == 0 || cmd.Buffer.is_null() {
            let _ = CloseHandle(h_process);
            return None;
        }

        // CommandLine.Length is in bytes, not chars
        let char_count = (cmd.Length / 2) as usize;
        let mut buf: Vec<u16> = vec![0u16; char_count];
        let mut bytes_read3: usize = 0;

        let res = ReadProcessMemory(
            h_process,
            cmd.Buffer as *const c_void,
            buf.as_mut_ptr() as *mut c_void,
            cmd.Length as usize,
            Some(&mut bytes_read3 as *mut usize),
        );

        let _ = CloseHandle(h_process);

        if let Err(e) = res {
            eprintln!("ReadProcessMemory({pid}, CommandLine.Buffer) failed: {e:?}");
            return None;
        }

        if bytes_read3 < cmd.Length as usize {
            eprintln!("ReadProcessMemory({pid}, CommandLine.Buffer) short read");
            return None;
        }

        // Convert UTF-16 -> Rust String
        Some(String::from_utf16_lossy(&buf))
    }
}


#[cfg(target_os = "windows")]
fn get_cpu_percentage(pid: u32) -> Option<f32> {
    unsafe {
        // open the process so we can query times
        let access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
        let h_process = match OpenProcess(access, false, pid) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("OpenProcess({pid}) for CPU% failed: {e:?}");
                return None;
            }
        };

        // get process creation/exit/kernel/user times
        let mut ft_creation = FILETIME::default();
        let mut ft_exit     = FILETIME::default();
        let mut ft_kernel   = FILETIME::default();
        let mut ft_user     = FILETIME::default();

        if let Err(e) = GetProcessTimes(
            h_process,
            &mut ft_creation,
            &mut ft_exit,
            &mut ft_kernel,
            &mut ft_user,
        ) {
            eprintln!("GetProcessTimes({pid}) failed: {e:?}");
            let _ = CloseHandle(h_process);
            return None;
        }

        // Current time
        let mut ft_now = GetSystemTimeAsFileTime();


        let creation_ticks = filetime_to_u64(ft_creation);
        let now_ticks      = filetime_to_u64(ft_now);

        if now_ticks <= creation_ticks {
            let _ = CloseHandle(h_process);
            return Some(0.0);
        }

        // 100-ns units
        let elapsed_100ns = now_ticks - creation_ticks;

        // Total CPU time this process has consumed (user + kernel)
        let kernel_ticks = filetime_to_u64(ft_kernel);
        let user_ticks   = filetime_to_u64(ft_user);
        let proc_ticks   = kernel_ticks + user_ticks;

        // Number of logical processors
        let mut sys_info = SYSTEM_INFO::default();
        GetSystemInfo(&mut sys_info);
        let num_procs = if sys_info.dwNumberOfProcessors == 0 {
            1.0
        } else {
            sys_info.dwNumberOfProcessors as f64
        };

        // Average CPU usage over process lifetime:
        // CPU% ~= (proc_time / (elapsed_time * num_procs)) * 100
        let cpu = (proc_ticks as f64)
            / ((elapsed_100ns as f64) * num_procs)
            * 100.0;

        let _ = CloseHandle(h_process);

        // Clamp to [0, 100] to avoid weird rounding artifacts
        Some(cpu.clamp(0.0, 100.0) as f32)
    }
}


#[cfg(target_os = "windows")]
fn filetime_to_u64(ft: FILETIME) -> u64 {
    // FILETIME is number of 100-ns intervals since 1601-01-01
    ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64 & 0xFFFF_FFFF)
}


#[cfg(target_os = "windows")]
fn get_sha256(pid: u32) -> Option<String> 
{
    // get the full on disk path for this process

    let path = get_process_path(pid)?;

    // try to open the file. just return None if protected.
    let mut file = File::open(&path).ok()?;

    // stream the file into our SHA-256 hasher
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];

    loop 
    {
        let read = match file.read(&mut buf) {
            Ok(0) => break,          // EOF
            Ok(n) => n,
            Err(_) => return None,   // io error  
        };

        hasher.update(&buf[..read]);
    }

    // Finalize and hex encode
    let digest = hasher.finalize();
    let hex = digest.iter().map(|b| format!("{:02x}", b)).collect();

    Some(hex)

}

///HELPERS FOR ACQUIRING PROCESS DETAILS
#[cfg(target_os = "windows")]
fn get_process_path(pid: u32) -> Option<String> 
{
    unsafe {
        // Combine the access rights we need
        let access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;

        // Try to open the process
        let h_process = match OpenProcess(access, false, pid) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("OpenProcess({pid}) failed: {e:?}");
                return None;
            }
        };

        // UTF-16 buffer for the path
        let mut buffer = [0u16; 1024];

        // Ask Windows for the main module's file name
        let len = K32GetModuleFileNameExW(Some(h_process), None, &mut buffer) as usize;

        if len == 0 {
            let _ = CloseHandle(h_process);
            return None;
        }

        let path = String::from_utf16_lossy(&buffer[..len]);

        let _ = CloseHandle(h_process);
 
        Some(path)
    }
}




#[cfg(target_os = "windows")]
fn get_is_signed(pid: u32) -> bool 
{
    // 1) Resolve the executable path for this PID
    let path = match get_process_path(pid) 
    {
        Some(p) => p,
        None => return false,
    };

    // 2) Convert Rust &str null-terminated UTF-16 for Win32
    let wide: Vec<u16> = OsStr::new(&path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        // 3) Describe the file we want to verify
        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: PCWSTR(wide.as_ptr()),
            hFile: HANDLE(std::ptr::null_mut()),                    // let WinTrust open it
            pgKnownSubject: std::ptr::null_mut(),
        };

        // 4) Configure WinTrust: "verify this file, no UI"
        let mut data = WINTRUST_DATA {
            cbStruct: size_of::<WINTRUST_DATA>() as u32,
            dwUnionChoice: WTD_CHOICE_FILE,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            Anonymous: WINTRUST_DATA_0 { pFile: &mut file_info },
            ..Default::default()
        };

        // 5) Policy GUID: generic code-signing verify v2
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        // 6) Call WinVerifyTrust. 0 == ERROR_SUCCESS == "signed & trusted"
        let status = WinVerifyTrust(
            HWND(std::ptr::null_mut()),
            &mut action,
            &mut data as *mut _ as *mut _,
        );

        status == 0
    }
}


#[cfg(target_os = "windows")]
fn get_signer_name(pid: u32) -> Option<String> 
{
    //exe path
    let path = get_process_path(pid)?;

    // 2) Make a null-terminated UTF-16 string for CryptoAPI
    let wide: Vec<u16> = OsStr::new(&path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        //use CryptoAPI to parse the file and give us a cert store

        use std::ffi::c_void;
        let mut cert_store: HCERTSTORE = HCERTSTORE::default();

        let res = CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            // pvObject: wide string pointer as *const c_void
            wide.as_ptr() as *const c_void,
            CERT_QUERY_CONTENT_FLAG_ALL,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            None,              // pdwMsgAndCertEncodingType
            None,              // pdwContentType
            None,              // pdwFormatType
            Some(&mut cert_store),
            None,              // phMsg
            None,              // ppvContext
        );

        if let Err(e) = res {
            eprintln!("CryptQueryObject({}) failed: {:?}", path, e);
            if !cert_store.is_invalid() {
                let _ = CertCloseStore(Some(cert_store), 0);
            }
            return None;
        }

        if cert_store.is_invalid() {
            return None;
        }

        //take the first certificate from the store
        let cert_context = CertEnumCertificatesInStore(cert_store, None);
        if cert_context.is_null() {
            let _ = CertCloseStore(Some(cert_store), 0);
            return None;
        }

        //ask for the \"simple display\" subject name
        let mut name_buf = [0u16; 256];

        let len = CertGetNameStringW(
            cert_context,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,          // dwFlags
            None,       // pvTypePara
            Some(&mut name_buf),
        );

        if len <= 1 {
            let _ = CertCloseStore(Some(cert_store), 0);
            return None;
        }

        let name = String::from_utf16_lossy(&name_buf[..(len - 1) as usize]);

        let _ = CertCloseStore(Some(cert_store), 0);

        Some(name)
    }
}


#[cfg(target_os = "windows")]
fn tcp_state_to_string(state: u32) -> &'static str 
{
    match state {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RECEIVED",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
}
#[cfg(target_os = "windows")]
fn get_connections(pid: u32) -> Vec<ConnectionInfo> 
{
    let mut results = Vec::new();

    unsafe {

        let mut size: u32 = 0;

        // First call to get required buffer size
        let _ = GetExtendedTcpTable(
            Some(null_mut()),
            &mut size,
            false.into(),                   // don't need sorted
            2,                               // AF_INET = 2
            TCP_TABLE_CLASS(5),              // 5 == TCP_TABLE_OWNER_PID_ALL
            0,
        );

        if size == 0 {
            return results;
        }

        let mut buf: Vec<u8> = vec![0; size as usize];

        let ret = GetExtendedTcpTable(
            Some(buf.as_mut_ptr() as *mut c_void),
            &mut size,
            false.into(),
            2,                               // AF_INET
            TCP_TABLE_CLASS(5),              // OWNER_PID_ALL
            0,
        );

        if ret != 0 {
            // non-zero means some error (we can refine this later)
            return results;
        }

        // Interpret the buffer as MIB_TCPTABLE_OWNER_PID
        let table_ptr = buf.as_mut_ptr() as *mut MIB_TCPTABLE_OWNER_PID;
        let table = &*table_ptr;

        let num = table.dwNumEntries as usize;
        let rows_ptr = table.table.as_ptr(); // first row
        let rows = std::slice::from_raw_parts(rows_ptr, num);

        for row in rows {
            if row.dwOwningPid != pid {
                continue;
            }

            // IPs
            let local_ip = Ipv4Addr::from(u32::from_be(row.dwLocalAddr));
            let remote_ip = Ipv4Addr::from(u32::from_be(row.dwRemoteAddr));

            // Ports (low 16 bits, network order)
            let local_port = u16::from_be(row.dwLocalPort as u16);
            let remote_port = u16::from_be(row.dwRemotePort as u16);

            let state = tcp_state_to_string(row.dwState).to_string();

            results.push(ConnectionInfo {
                proto: "tcp".to_string(),
                local: format!("{}:{}", local_ip, local_port),
                remote: format!("{}:{}", remote_ip, remote_port),
                state,
            });
        }
    }

    results
}


#[cfg(target_os = "windows")]
fn integrity_rid_to_string(rid: u32) -> String 
{
    match rid {
        _security_mandatory_untrusted_rid => "Untrusted",
        _security_mandatory_low_rid => "Low",
        _security_mandatory_medium_rid => "Medium",
        _security_mandatory_high_rid => "High",
        _security_mandatory_system_rid => "System",
        _security_mandatory_protected_process_rid => "ProtectedProcess",
        _ => "Unknown",
    }
    .to_string()
}
#[cfg(target_os = "windows")]
fn get_integrity_level(pid: u32) -> Option<String> 
{
    use std::ptr::null_mut;
    use std::ffi::c_void;

    unsafe {
        // 1) Open the process so we can query its token
        let access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
        let h_process = match OpenProcess(access, false, pid) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("OpenProcess({pid}) for integrity level failed: {e:?}");
                return None;
            }
        };

        // 2) Open the process token
        let mut token_handle = HANDLE(null_mut());
        // Depending on your windows crate version, this may return BOOL or Result<()>
        if let Err(e) = OpenProcessToken(h_process, TOKEN_QUERY, &mut token_handle) {
            eprintln!("OpenProcessToken({pid}) failed: {e:?}");
            let _ = CloseHandle(h_process);
            return None;
        }

        // 3) First call to get required buffer size
        let mut length: u32 = 0;
        let _ = GetTokenInformation(
            token_handle,
            TokenIntegrityLevel,
            None,                  // buffer
            0,
            &mut length,
        );
        
        if length == 0 {
            let _ = CloseHandle(token_handle);
            let _ = CloseHandle(h_process);
            return None;
        }

        // 4) Allocate buffer and get the TOKEN_MANDATORY_LABEL
        let mut buf = vec![0u8; length as usize];

        let res = GetTokenInformation(
            token_handle,
            TokenIntegrityLevel,
            Some(buf.as_mut_ptr() as *mut c_void),
            length,
            &mut length,
        );

        if let Err(e) = res {
            eprintln!("GetTokenInformation(TokenIntegrityLevel) failed: {e:?}");
            let _ = CloseHandle(token_handle);
            let _ = CloseHandle(h_process);
            return None;
        }

        // Interpret the buffer as TOKEN_MANDATORY_LABEL
        let tml = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
        let sid = tml.Label.Sid;

        if sid.0.is_null() {
            let _ = CloseHandle(token_handle);
            let _ = CloseHandle(h_process);
            return None;
        }

        // 5) Pull the last SubAuthority from the SID – that's the integrity RID
        let sub_auth_count_ptr = GetSidSubAuthorityCount(sid);
        if sub_auth_count_ptr.is_null() {
            let _ = CloseHandle(token_handle);
            let _ = CloseHandle(h_process);
            return None;
        }

        let sub_auth_count = *sub_auth_count_ptr as u32;
        if sub_auth_count == 0 {
            let _ = CloseHandle(token_handle);
            let _ = CloseHandle(h_process);
            return None;
        }

        let rid_ptr = GetSidSubAuthority(sid, sub_auth_count - 1);
        if rid_ptr.is_null() {
            let _ = CloseHandle(token_handle);
            let _ = CloseHandle(h_process);
            return None;
        }

        let rid = *rid_ptr;

        let level = integrity_rid_to_string(rid);

        let _ = CloseHandle(token_handle);
        let _ = CloseHandle(h_process);

        Some(level)
    }
}



fn get_modules(pid: u32) -> Vec<String> {
    let mut modules = Vec::new();

    unsafe {
        // Open the target process
        let access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
        let h_process = match OpenProcess(access, false, pid) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("OpenProcess({pid}) for modules failed: {e:?}");
                return modules;
            }
        };

        // Buffer for module handles
        let mut hmods: [HMODULE; 1024] = [HMODULE::default(); 1024];
        let mut needed_bytes: u32 = 0;

        // Size of our buffer in bytes
        let cb = (std::mem::size_of::<HMODULE>() * hmods.len()) as u32;

        let ok = K32EnumProcessModules(
            h_process,
            hmods.as_mut_ptr(),  // *mut HMODULE
            cb,                  // buffer size in bytes
            &mut needed_bytes,   // how many bytes were actually needed
        );

        if !ok.as_bool() {
            eprintln!("K32EnumProcessModules({pid}) failed");
            let _ = CloseHandle(h_process);
            return modules;
        }

        // How many modules did we get?
        if needed_bytes == 0 {
            let _ = CloseHandle(h_process);
            return modules;
        }

        let module_size = std::mem::size_of::<HMODULE>() as u32;
        let mut count = (needed_bytes / module_size) as usize;

        if count > hmods.len() {
            count = hmods.len();
        }

        // For each module, get its full path
        for hmod in &hmods[..count] {
            let mut buf = [0u16; 1024];

            // Use the same 3-arg style you already use in get_process_path
            let len = K32GetModuleFileNameExW(
                Some(h_process),
                Some(*hmod),
                &mut buf,
            ) as usize;

            if len == 0 {
                continue;
            }

            let path = String::from_utf16_lossy(&buf[..len]);
            modules.push(path);
        }

        let _ = CloseHandle(h_process);
    }

    modules
}