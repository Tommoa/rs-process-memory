extern crate winapi;
extern crate process_memory;

use winapi::shared::minwindef; 

#[allow(non_snake_case)] #[no_mangle]
pub extern "stdcall" fn DllMain(_self_handle: minwindef::HINSTANCE, reason: minwindef::DWORD, _lpv_reserved: minwindef::LPVOID) -> minwindef::BOOL {
    use std::fs::File;
    use winapi::um::winnt;
    use process_memory::remote_member::LocalManager;

    match reason {
        winnt::DLL_PROCESS_ATTACH => {
            let mut buffer = File::create("D:\\dll.txt").unwrap();
            LocalManager::new("\\\\.\\pipe\\MEC".to_owned(), &mut buffer).run();
        },
        winnt::DLL_PROCESS_DETACH => {
        },
        winnt::DLL_THREAD_ATTACH => {
            let mut buffer = File::create("D:\\dll.txt").unwrap();
            LocalManager::new("\\\\.\\pipe\\MEC".to_owned(), &mut buffer).run();
        },
        winnt::DLL_THREAD_DETACH => {
        },
        _ => {
        }
    } 

    0
}
