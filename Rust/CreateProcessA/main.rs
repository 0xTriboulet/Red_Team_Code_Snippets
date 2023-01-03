extern crate winapi;

use std::mem;
use std::ptr::null_mut;
use windows::core::{PCSTR, PSTR};
use winapi::shared::basetsd::SIZE_T;
use windows::Win32::System::Memory::{HeapAlloc, GetProcessHeap, HEAP_GENERATE_EXCEPTIONS};
use windows::Win32::System::Threading::{STARTUPINFOEXA,PROCESS_INFORMATION,InitializeProcThreadAttributeList,CreateProcessA, CREATE_NEW_CONSOLE, CREATE_SUSPENDED};

//CreateProcessA Implementation
//by 0xTriboulet
//Jan 2023

/*
BOOL CreateProcessA(
  [in, optional]      LPCSTR                lpApplicationName,
  [in, out, optional] LPSTR                 lpCommandLine,
  [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
  [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
  [in]                BOOL                  bInheritHandles,
  [in]                DWORD                 dwCreationFlags,
  [in, optional]      LPVOID                lpEnvironment,
  [in, optional]      LPCSTR                lpCurrentDirectory,
  [in]                LPSTARTUPINFOA        lpStartupInfo,
  [out]               LPPROCESS_INFORMATION lpProcessInformation
);
*/

fn main() {
  let mut attrsize: SIZE_T = Default::default();
  let mut pi = PROCESS_INFORMATION::default();
  let mut si = STARTUPINFOEXA::default();
  
  unsafe{

    si.lpAttributeList = windows::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST(HeapAlloc(GetProcessHeap().ok(), HEAP_GENERATE_EXCEPTIONS, attrsize));
    si.StartupInfo.cb = mem::size_of::<STARTUPINFOEXA>() as u32;

    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &mut attrsize);
    
    CreateProcessA(
      PCSTR::null(),
      PSTR(String::from("notepad.exe\0").as_mut_ptr()),
      Some(null_mut()),
      Some(null_mut()),
      false,
      CREATE_NEW_CONSOLE,
      Some(null_mut()),
      PCSTR::null(),
      &mut si.StartupInfo,
      &mut pi
    );
  }
}
