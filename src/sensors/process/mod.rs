use crate::sensors::SensorConfig;


use std::ffi::{OsStr};
use serde::Serialize;


#[cfg(target_os = "windows")]
use std::{mem::size_of, os::windows::ffi::OsStrExt};

#[cfg(target_os = "windows")]
use windows::core::PCWSTR;

#[cfg(target_os = "windows")]
use windows::Win32::{
    Foundation::{CloseHandle, HWND, HANDLE},
    System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
        PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    },
    System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
    System::ProcessStatus::K32GetModuleFileNameExW,
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

            results.push(ProcessInfo {
                pid,
                ppid,
                exe_path,
                command_line: None,          // TODO
                user: None,                  // TODO
                domain: None,                // TODO
                integrity_level: None,       // TODO
                is_signed,             
                signer_name: None,           // TODO
                sha256: None,                // TODO
                cpu_percent: None,           // TODO
                working_set_mb: None,        // TODO
                thread_count,
                modules: Vec::new(),         // TODO
                connections: Vec::new(),     // TODO
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
fn get_process_path(pid: u32) -> Option<String> {
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
fn get_is_signed(pid: u32) -> bool {
    // 1) Resolve the executable path for this PID
    let path = match get_process_path(pid) {
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
