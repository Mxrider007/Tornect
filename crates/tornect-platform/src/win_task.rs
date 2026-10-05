//! The Win32 side of [`crate::helper_task`] (§B.8.7.5): the helper task's
//! registration, removal and switch through `schtasks.exe` from the system
//! directory, elevated through the UAC prompt (F1-1's path); a file's or
//! folder's owner and DACL (`GetNamedSecurityInfoW` + `GetAce`); and the on-demand run
//! with its run parameter (`ITaskService` → `ITaskFolder::GetTask` →
//! `IRegisteredTask::Run`, the COM vtables declared here in the order of
//! `taskschd.h`, since `windows-sys` has none). Type-checked only:
//! NEEDS-DEVICE(windows); the run parameter's substitution into `$(Arg0)` is
//! UNVERIFIED on a device.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::path::PathBuf;
use std::process::Command;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{HLOCAL, LocalFree, NO_ERROR, SysAllocString, SysFreeString};
use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
};
use windows_sys::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
};
use windows_sys::core::GUID;

use crate::autostart::AutostartError;
use crate::helper_task::{Ace, HelperTasks, Security};
use crate::win::wide;

/// The helper task through `schtasks.exe` and the Task Scheduler's COM API.
pub(crate) struct Scheduler {
    schtasks: PathBuf,
    name: String,
    sid: String,
}

impl Scheduler {
    /// The task of this user (named by `sid`).
    pub(crate) fn new(sid: &str) -> Result<Self, AutostartError> {
        let system = crate::win::system_directory()
            .map_err(|e| AutostartError::Failed(format!("finding the system directory: {e}")))?;
        Ok(Self {
            schtasks: system.join("schtasks.exe"),
            name: crate::helper_task::task_name(sid),
            sid: sid.to_owned(),
        })
    }

    fn quiet(&self, args: &[&str]) -> Result<std::process::Output, AutostartError> {
        Command::new(&self.schtasks)
            .args(args)
            .output()
            .map_err(|e| AutostartError::Failed(format!("running schtasks.exe: {e}")))
    }

    /// One change through the UAC prompt: the task runs at `HighestAvailable`,
    /// which a filtered token can neither register nor remove.
    fn elevated(&self, args: &[String]) -> Result<(), AutostartError> {
        let line = crate::autostart::windows_command_line(args);
        match crate::win::run_elevated(&self.schtasks, &line) {
            Ok(0) => Ok(()),
            Ok(code) => Err(AutostartError::Failed(format!(
                "the elevated schtasks.exe exited with {code}"
            ))),
            Err(crate::win::ElevateError::Cancelled) => Err(AutostartError::Cancelled),
            Err(crate::win::ElevateError::Failed(e)) => Err(AutostartError::Failed(e)),
        }
    }
}

impl HelperTasks for Scheduler {
    /// Not `query`'s reading, which takes every failure for no task (right for a
    /// registration's read-back): the Task Scheduler's `GetTask`, absent only on its
    /// "not found" (decision M1-67: a presence that cannot be read counts as
    /// registered).
    fn exists(&self) -> Result<bool, AutostartError> {
        let hr = get_task(&self.name)
            .map_err(|e| AutostartError::Failed(format!("asking the Task Scheduler: {e}")))?;
        crate::helper_task::exists_from_get_task(hr)
    }

    fn query(&self) -> Result<Option<String>, AutostartError> {
        let out = self.quiet(&["/Query", "/TN", &self.name, "/XML"])?;
        let text = crate::autostart::decode_console_output(&out.stdout);
        if out.status.success() && text.contains("<Task") {
            Ok(Some(text))
        } else if out.status.success() {
            Err(AutostartError::Failed(
                "schtasks.exe printed no task definition".to_owned(),
            ))
        } else {
            // Not found, or not readable: both read as absent here; a
            // registration then goes through the prompt and its read-back.
            Ok(None)
        }
    }

    fn register(&self, xml: &str) -> Result<(), AutostartError> {
        let dir = crate::win::known_folder(crate::win::KnownFolder::LocalAppData)
            .map_err(|e| AutostartError::Failed(format!("finding local application data: {e}")))?
            .join("Tornect");
        std::fs::create_dir_all(&dir)
            .map_err(|e| AutostartError::Failed(format!("creating {}: {e}", dir.display())))?;
        let file = crate::win::TempFile::write(
            &dir,
            "tornect-admin-helper",
            ".xml",
            &crate::autostart::task_xml_file_bytes(xml),
        )
        .map_err(|e| AutostartError::Failed(format!("writing the task definition: {e}")))?;
        let path = file.path().to_str().ok_or_else(|| {
            AutostartError::Failed("the task definition's path is not Unicode".to_owned())
        })?;
        let args = [
            "/Create".to_owned(),
            "/TN".to_owned(),
            self.name.clone(),
            "/XML".to_owned(),
            path.to_owned(),
            "/F".to_owned(),
        ];
        let done = self.elevated(&args);
        drop(file);
        done
    }

    fn delete(&self) -> Result<(), AutostartError> {
        self.elevated(&[
            "/Delete".to_owned(),
            "/TN".to_owned(),
            self.name.clone(),
            "/F".to_owned(),
        ])
    }

    fn set_enabled(&self, enabled: bool) -> Result<(), AutostartError> {
        self.elevated(&[
            "/Change".to_owned(),
            "/TN".to_owned(),
            self.name.clone(),
            if enabled { "/ENABLE" } else { "/DISABLE" }.to_owned(),
        ])
    }

    fn security(&self, path: &str) -> Result<Security, AutostartError> {
        security(path).map_err(|e| {
            AutostartError::Failed(format!("reading the owner and ACL of {path}: {e}"))
        })
    }

    fn run(&self, arg: &str) -> Result<(), AutostartError> {
        run_task(&self.name, arg)
            .map_err(|e| AutostartError::Failed(format!("starting the helper task: {e}")))
    }

    fn is_this_account(&self, principal: &str) -> bool {
        principal.eq_ignore_ascii_case(&self.sid)
            || crate::win::sid_of_account_name(principal)
                .is_ok_and(|sid| sid.eq_ignore_ascii_case(&self.sid))
    }
}

/// The owner and the DACL of `path`, entry by entry, each with its flags.
/// An entry of a type other than allow or deny counts as an allow of every
/// right that applies to the object itself (so the check refuses).
fn security(path: &str) -> std::io::Result<Security> {
    let name = wide(path);
    let mut owner: *mut c_void = null_mut();
    let mut acl: *mut ACL = null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `name` is NUL-terminated; on success `sd` is a descriptor
    // allocated with `LocalAlloc` (freed below), and `owner` and `acl` point
    // into it.
    let status = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut acl,
            null_mut(),
            &mut sd,
        )
    };
    if status != NO_ERROR {
        return Err(std::io::Error::from_raw_os_error(status as i32));
    }
    let mut out = Vec::new();
    let read = if owner.is_null() {
        Err(std::io::Error::other("the file has no owner"))
    } else if acl.is_null() {
        // A null DACL grants everyone everything.
        Err(std::io::Error::other(
            "the file has no DACL (everyone has full access)",
        ))
    } else {
        // SAFETY: `acl` points to a valid ACL inside `sd`.
        let count = unsafe { (*acl).AceCount };
        let mut failed = None;
        for i in 0..u32::from(count) {
            let mut ace: *mut c_void = null_mut();
            // SAFETY: `i` is below the ACL's entry count; `ace` receives a
            // pointer into the ACL.
            if unsafe { GetAce(acl, i, &mut ace) } == 0 || ace.is_null() {
                failed = Some(std::io::Error::last_os_error());
                break;
            }
            // SAFETY: every ACE starts with an ACE_HEADER.
            let header = unsafe { &*(ace as *const ACE_HEADER) };
            match header.AceType {
                0 | 1 => {
                    // SAFETY: types 0 and 1 are ACCESS_ALLOWED_ACE and
                    // ACCESS_DENIED_ACE, the same layout: the SID starts at
                    // `SidStart`.
                    let entry = unsafe { &*(ace as *const ACCESS_ALLOWED_ACE) };
                    let sid = (&raw const entry.SidStart).cast_mut().cast::<c_void>();
                    out.push(Ace {
                        sid: crate::win::sid_string(sid)?,
                        allow: header.AceType == 0,
                        mask: entry.Mask,
                        flags: header.AceFlags,
                    });
                }
                _ => out.push(Ace {
                    sid: "an entry of another type".to_owned(),
                    allow: true,
                    mask: u32::MAX,
                    flags: 0,
                }),
            }
        }
        failed.map_or(Ok(()), Err)
    };
    // The owner's SID points into `sd`: read it before `sd` is freed.
    let owner = read.and_then(|()| crate::win::sid_string(owner));
    // SAFETY: allocated by `GetNamedSecurityInfoW`, freed once.
    unsafe { LocalFree(sd as HLOCAL) };
    owner.map(|owner| Security { owner, dacl: out })
}

/// `CLSID_TaskScheduler` (taskschd.h).
const CLSID_TASK_SCHEDULER: GUID = GUID::from_u128(0x0f87369f_a4e5_4cfc_bd3e_73e6154572dd);
/// `IID_ITaskService` (taskschd.h).
const IID_ITASK_SERVICE: GUID = GUID::from_u128(0x2faba4c7_4da9_4013_9697_20cc3fd40f85);

/// A VARIANT as the x64 ABI lays it out (24 bytes): `VT_EMPTY`, or
/// `VT_BSTR` (8) with the string in the first pointer.
#[repr(C)]
#[derive(Clone, Copy)]
struct Variant {
    vt: u16,
    reserved: [u16; 3],
    value: usize,
    extra: usize,
}

#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<Variant>() == 24);

const VT_BSTR: u16 = 8;
const EMPTY: Variant = Variant {
    vt: 0,
    reserved: [0; 3],
    value: 0,
    extra: 0,
};

pub(crate) type Hresult = i32;
type Release = unsafe extern "system" fn(*mut c_void) -> u32;

/// IUnknown and IDispatch: the first seven slots of every vtable here.
#[repr(C)]
struct DispatchVtbl {
    query_interface: usize,
    add_ref: usize,
    release: Release,
    dispatch: [usize; 4],
}

#[repr(C)]
struct TaskServiceVtbl {
    base: DispatchVtbl,
    get_folder: unsafe extern "system" fn(*mut c_void, *const u16, *mut *mut c_void) -> Hresult,
    get_running_tasks: usize,
    new_task: usize,
    connect: unsafe extern "system" fn(*mut c_void, Variant, Variant, Variant, Variant) -> Hresult,
}

#[repr(C)]
struct TaskFolderVtbl {
    base: DispatchVtbl,
    get_name: usize,
    get_path: usize,
    get_folder: usize,
    get_folders: usize,
    create_folder: usize,
    delete_folder: usize,
    get_task: unsafe extern "system" fn(*mut c_void, *const u16, *mut *mut c_void) -> Hresult,
}

#[repr(C)]
struct RegisteredTaskVtbl {
    base: DispatchVtbl,
    get_name: usize,
    get_path: usize,
    get_state: usize,
    get_enabled: usize,
    put_enabled: usize,
    run: unsafe extern "system" fn(*mut c_void, Variant, *mut *mut c_void) -> Hresult,
}

/// A COM interface pointer, released on drop.
pub(crate) struct Com(pub(crate) *mut c_void);

impl Com {
    /// Its vtable as `T`.
    ///
    /// # Safety
    /// `T` must be this interface's vtable layout (or a prefix of it).
    pub(crate) unsafe fn vtbl<T>(&self) -> &T {
        // SAFETY: a COM object's first field is its vtable pointer; the
        // caller names the right layout.
        unsafe { &**(self.0 as *const *const T) }
    }
}

impl Drop for Com {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: every interface starts with IUnknown; released once.
            unsafe {
                let vtbl = &**(self.0 as *const *const DispatchVtbl);
                (vtbl.release)(self.0);
            }
        }
    }
}

/// A BSTR, freed on drop.
struct Bstr(*const u16);

impl Bstr {
    fn new(s: &str) -> std::io::Result<Self> {
        let w = wide(s);
        // SAFETY: `w` is NUL-terminated; the copy is freed on drop.
        let b = unsafe { SysAllocString(w.as_ptr()) };
        if b.is_null() {
            return Err(std::io::Error::other("out of memory for a BSTR"));
        }
        Ok(Self(b))
    }
}

impl Drop for Bstr {
    fn drop(&mut self) {
        // SAFETY: allocated by `SysAllocString`, freed once.
        unsafe { SysFreeString(self.0) };
    }
}

pub(crate) fn check(hr: Hresult, what: &str) -> std::io::Result<()> {
    if hr < 0 {
        Err(std::io::Error::other(format!(
            "{what} failed: HRESULT {hr:#010x}"
        )))
    } else {
        Ok(())
    }
}

/// Run the task `name` in the root folder with the run parameter `arg`
/// (`$(Arg0)` of its action).
fn run_task(name: &str, arg: &str) -> std::io::Result<()> {
    // SAFETY: plain call; balanced below when it succeeds.
    let com = unsafe { CoInitializeEx(null(), COINIT_MULTITHREADED as u32) };
    let result = (|| {
        let mut service: *mut c_void = null_mut();
        // SAFETY: the CLSID and IID are the Task Scheduler's; `service`
        // receives an ITaskService pointer on success.
        let hr = unsafe {
            CoCreateInstance(
                &CLSID_TASK_SCHEDULER,
                null_mut(),
                CLSCTX_INPROC_SERVER,
                &IID_ITASK_SERVICE,
                &mut service,
            )
        };
        check(hr, "creating the Task Scheduler service")?;
        let service = Com(service);
        // SAFETY: `service` is an ITaskService.
        let vt = unsafe { service.vtbl::<TaskServiceVtbl>() };
        // SAFETY: the local computer and the current user: four empty VARIANTs.
        let hr = unsafe { (vt.connect)(service.0, EMPTY, EMPTY, EMPTY, EMPTY) };
        check(hr, "connecting to the Task Scheduler")?;
        let root = Bstr::new("\\")?;
        let mut folder: *mut c_void = null_mut();
        // SAFETY: `root` is a BSTR alive for the call; `folder` receives an
        // ITaskFolder.
        let hr = unsafe { (vt.get_folder)(service.0, root.0, &mut folder) };
        check(hr, "opening the task folder")?;
        let folder = Com(folder);
        let task_name = Bstr::new(name)?;
        let mut task: *mut c_void = null_mut();
        // SAFETY: `folder` is an ITaskFolder; `task` receives an IRegisteredTask.
        let hr =
            unsafe { (folder.vtbl::<TaskFolderVtbl>().get_task)(folder.0, task_name.0, &mut task) };
        check(hr, "finding the helper task")?;
        let task = Com(task);
        let param = Bstr::new(arg)?;
        let variant = Variant {
            vt: VT_BSTR,
            reserved: [0; 3],
            value: param.0 as usize,
            extra: 0,
        };
        let mut running: *mut c_void = null_mut();
        // SAFETY: `task` is an IRegisteredTask; the VARIANT's BSTR outlives
        // the call; `running` receives an IRunningTask, released below.
        let hr = unsafe { (task.vtbl::<RegisteredTaskVtbl>().run)(task.0, variant, &mut running) };
        check(hr, "running the helper task")?;
        drop(Com(running));
        Ok(())
    })();
    if com >= 0 {
        // SAFETY: balances the successful `CoInitializeEx`.
        unsafe { CoUninitialize() };
    }
    result
}

/// The HRESULT of `ITaskFolder::GetTask` for the task `name` in the root folder, the
/// task released at once; an error only when the scheduler cannot be asked.
fn get_task(name: &str) -> std::io::Result<Hresult> {
    // SAFETY: plain call; balanced below when it succeeds.
    let com = unsafe { CoInitializeEx(null(), COINIT_MULTITHREADED as u32) };
    let result = (|| {
        let mut service: *mut c_void = null_mut();
        // SAFETY: the CLSID and IID are the Task Scheduler's; `service`
        // receives an ITaskService pointer on success.
        let hr = unsafe {
            CoCreateInstance(
                &CLSID_TASK_SCHEDULER,
                null_mut(),
                CLSCTX_INPROC_SERVER,
                &IID_ITASK_SERVICE,
                &mut service,
            )
        };
        check(hr, "creating the Task Scheduler service")?;
        let service = Com(service);
        // SAFETY: `service` is an ITaskService.
        let vt = unsafe { service.vtbl::<TaskServiceVtbl>() };
        // SAFETY: the local computer and the current user: four empty VARIANTs.
        let hr = unsafe { (vt.connect)(service.0, EMPTY, EMPTY, EMPTY, EMPTY) };
        check(hr, "connecting to the Task Scheduler")?;
        let root = Bstr::new("\\")?;
        let mut folder: *mut c_void = null_mut();
        // SAFETY: `root` is a BSTR alive for the call; `folder` receives an
        // ITaskFolder.
        let hr = unsafe { (vt.get_folder)(service.0, root.0, &mut folder) };
        check(hr, "opening the task folder")?;
        let folder = Com(folder);
        let task_name = Bstr::new(name)?;
        let mut task: *mut c_void = null_mut();
        // SAFETY: `folder` is an ITaskFolder; `task` receives an IRegisteredTask
        // on success and stays null otherwise.
        let hr =
            unsafe { (folder.vtbl::<TaskFolderVtbl>().get_task)(folder.0, task_name.0, &mut task) };
        drop(Com(task));
        Ok(hr)
    })();
    if com >= 0 {
        // SAFETY: balances the successful `CoInitializeEx`.
        unsafe { CoUninitialize() };
    }
    result
}

/// The helper task of this user as [`HelperTasks`].
pub(crate) fn scheduler() -> Result<Scheduler, AutostartError> {
    let sid = crate::win::current_user_sid()
        .map_err(|e| AutostartError::Failed(format!("reading this user's SID: {e}")))?;
    Scheduler::new(&sid)
}
