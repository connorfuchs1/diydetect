use crate::sensors::SensorConfig;

use std::ptr::null_mut;
use std::net::Ipv4Addr;
use std::ffi::{OsStr, c_void};


use serde::Serialize;


#[cfg(target_os = "windows")]
use std::{mem::size_of, os::windows::ffi::OsStrExt};

#[cfg(target_os = "windows")]
use windows::core::PCWSTR;

#[cfg(target_os = "windows")]
use windows::Win32::{
    Foundation::{CloseHandle, HWND, HANDLE, HMODULE},
    System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
        PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    },
    System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, OpenProcessToken},
    System::ProcessStatus::{K32GetModuleFileNameExW, K32EnumProcessModules},
    
    NetworkManagement::IpHelper::{
        GetExtendedTcpTable,
        MIB_TCPTABLE_OWNER_PID,
        MIB_TCPROW_OWNER_PID,
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
        TOKEN_INFORMATION_CLASS,
        GetSidSubAuthorityCount,
        GetSidSubAuthority,
        TokenIntegrityLevel,

    }


};


#[derive(Debug, Serialize)]
pub struct ConnectionInfo {
    pub proto: String,
    pub local: String,
    pub remote: String,
    pub state: String,
}

#[derive(Debug, Serialize, Default)]
pub struct DerivedFlags {
    pub path_is_temp_or_appdata: bool,
    pub parent_is_office_or_browser: bool,
    pub has_outbound_network: bool,
    pub is_signed_and_trusted: bool,
    pub elevated_integrity: bool,
}

#[derive(Debug, Serialize)]
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



pub fn run_process_sensor(_config: &SensorConfig)
{
    println!("Iterating process list and gathering information...");
    let processes  = collect_process_info();
    println!("Number of processes: {}", processes.len());


    match serde_json::to_string_pretty(&processes) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("Failed to serialize process info to JSON: {e}"),
    }
}




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
                println!("Snapshot handle: {:?}", handle);
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

            println!(
                "PID {:6} | PPID {:6} | Threads {:3} | {}",
                pid, ppid, thread_count, exe_name
            );

            //get path of exe




            let exe_path = get_process_path(pid).unwrap_or_else( || exe_name.clone());
            let is_signed = Some(get_is_signed(pid));
            let signer_name = get_signer_name(pid);
            let connections = get_connections(pid);
            let integrity_level = get_integrity_level(pid);
            let modules = get_modules(pid);

            results.push(ProcessInfo {
                pid,
                ppid,
                exe_path,
                command_line: None,          // TODO
                user: None,                  // TODO
                domain: None,                // TODO
                integrity_level,      
                is_signed,             
                signer_name,           
                sha256: None,                // TODO
                cpu_percent: None,           // TODO
                working_set_mb: None,        // TODO
                thread_count,
                modules,         
                connections,     
                derived_flags: DerivedFlags::default(),
            });

            match Process32NextW(snapshot, &mut entry)
            {
                Ok(_process) => {
                    println!("{:?}", _process);
                }
    
                Err(_e)=> {
                    break
                }
                
            }

        }

        let _ = CloseHandle(snapshot);

    }

    println!("Number of processes running on this computer: {}", count);

    results
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

    // 2) Convert Rust &str -> null-terminated UTF-16 for Win32
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
        SECURITY_MANDATORY_UNTRUSTED_RID => "Untrusted",
        SECURITY_MANDATORY_LOW_RID => "Low",
        SECURITY_MANDATORY_MEDIUM_RID => "Medium",
        SECURITY_MANDATORY_HIGH_RID => "High",
        SECURITY_MANDATORY_SYSTEM_RID => "System",
        SECURITY_MANDATORY_PROTECTED_PROCESS_RID => "ProtectedProcess",
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