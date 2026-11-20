use crate::language::text as tr;
use std::{
    ffi::{OsStr, OsString, c_void},
    io,
    mem::{size_of, zeroed},
    os::windows::{
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
        process::CommandExt,
    },
    process::Command,
    ptr::{null, null_mut},
    sync::{OnceLock, mpsc},
    time::Duration,
};

use windows_service::{
    define_windows_service,
    service::{
        Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceControl,
        ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceFailureActions,
        ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus,
        ServiceType, UserEventCode,
    },
    service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_DOES_NOT_EXIST,
        ERROR_SERVICE_NOT_ACTIVE, ERROR_SUCCESS, ERROR_SUCCESS_RESTART_REQUIRED,
    },
    System::{
        Console::{
            AllocConsole, CTRL_BREAK_EVENT, GenerateConsoleCtrlEvent, SetConsoleCtrlHandler,
        },
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        },
        Services::{SC_EVENT_STATUS_CHANGE, SC_EVENT_TYPE, SC_HANDLE},
        Threading::{
            CREATE_NEW_PROCESS_GROUP, GetCurrentProcess, OpenProcess, PROCESS_TERMINATE,
            TerminateProcess,
        },
    },
};

use super::{Event, Exit, orchestrate};
use crate::{Result, config::Store, progress::Progress};

const NAME: &str = "overcast";
const RELOAD: UserEventCode = unsafe { UserEventCode::from_unchecked(128) };
const RESTART: UserEventCode = unsafe { UserEventCode::from_unchecked(129) };

// Winsvcp.h service subscriptions are outside the SDK bindings.
#[cfg_attr(
    target_arch = "x86",
    link(
        name = "sechost.dll",
        kind = "raw-dylib",
        modifiers = "+verbatim",
        import_name_type = "undecorated"
    )
)]
#[cfg_attr(
    not(target_arch = "x86"),
    link(name = "sechost.dll", kind = "raw-dylib", modifiers = "+verbatim")
)]
unsafe extern "system" {
    fn SubscribeServiceChangeNotifications(
        service: SC_HANDLE,
        event: SC_EVENT_TYPE,
        callback: unsafe extern "system" fn(u32, *mut c_void),
        context: *mut c_void,
        subscription: *mut *mut c_void,
    ) -> u32;
    fn UnsubscribeServiceChangeNotifications(subscription: *mut c_void);
}

struct Subscription {
    registration: *mut c_void,
    progress: Box<Progress>,
}

impl Subscription {
    fn new(service: &Service) -> Result<Self> {
        let mut progress = Box::new(Progress::default());
        let mut registration = null_mut();
        let error = unsafe {
            SubscribeServiceChangeNotifications(
                service.raw_handle(),
                SC_EVENT_STATUS_CHANGE,
                changed,
                (&mut *progress as *mut Progress).cast(),
                &mut registration,
            )
        };
        if error != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(error as i32).into());
        }
        Ok(Self {
            registration,
            progress,
        })
    }

    fn wait(&self, service: &Service, state: ServiceState) -> Result<()> {
        self.progress
            .until(|| Ok(service.query_status()?.current_state == state))
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        unsafe { UnsubscribeServiceChangeNotifications(self.registration) };
    }
}

unsafe extern "system" fn changed(_: u32, context: *mut c_void) {
    unsafe { &*context.cast::<Progress>() }.notify();
}

fn open(access: ServiceAccess) -> Result<Option<Service>> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    match manager.open_service(NAME, access) {
        Ok(service) => Ok(Some(service)),
        Err(windows_service::Error::Winapi(error))
            if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) =>
        {
            Ok(None)
        }
        Err(error) => Err(error.into()),
    }
}

pub(super) fn install(store: &Store) -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    let info = ServiceInfo {
        name: NAME.into(),
        display_name: "Overcast".into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::env::current_exe()?,
        launch_arguments: vec!["--run".into(), store.directory.as_os_str().to_owned()],
        dependencies: Vec::new(),
        account_name: None,
        account_password: None,
    };
    let access = ServiceAccess::QUERY_STATUS | ServiceAccess::CHANGE_CONFIG | ServiceAccess::START;
    let service = match manager.open_service(NAME, access) {
        Ok(service) => {
            service.change_config(&info)?;
            service
        }
        Err(windows_service::Error::Winapi(error))
            if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) =>
        {
            manager.create_service(&info, access)?
        }
        Err(error) => return Err(error.into()),
    };
    service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(60)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![ServiceAction {
            action_type: ServiceActionType::Restart,
            delay: Duration::from_secs(1),
        }]),
    })?;
    service.set_failure_actions_on_non_crash_failures(true)?;
    match service.start::<&OsStr>(&[]) {
        Ok(()) => Ok(()),
        Err(windows_service::Error::Winapi(error))
            if error.raw_os_error() == Some(ERROR_SERVICE_ALREADY_RUNNING as i32) =>
        {
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

pub(super) fn reload() -> Result<()> {
    let service = open(ServiceAccess::USER_DEFINED_CONTROL)?.ok_or(tr(
        "Overcast service is not registered",
        "Overcast 服务未注册",
    ))?;
    service.notify(RELOAD)?;
    Ok(())
}

pub(super) fn restart() -> Result<()> {
    let service = open(ServiceAccess::USER_DEFINED_CONTROL)?.ok_or(tr(
        "Overcast service is not registered",
        "Overcast 服务未注册",
    ))?;
    service.notify(RESTART)?;
    Ok(())
}

pub(super) fn remove() -> Result<()> {
    let Some(service) =
        open(ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE)?
    else {
        return Ok(());
    };
    let subscription = Subscription::new(&service)?;
    match service.stop() {
        Ok(_) => {}
        Err(windows_service::Error::Winapi(error))
            if error.raw_os_error() == Some(ERROR_SERVICE_NOT_ACTIVE as i32) => {}
        Err(error) => return Err(error.into()),
    }
    subscription.wait(&service, ServiceState::Stopped)?;
    service.delete()?;
    Ok(())
}

pub(super) fn isolate(command: &mut Command) {
    command.creation_flags(CREATE_NEW_PROCESS_GROUP);
}

pub(super) fn terminate(pid: u32) {
    unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid) };
}

pub(super) fn kill(pid: u32) {
    unsafe {
        let process = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if !process.is_null() {
            TerminateProcess(process, 1);
            CloseHandle(process);
        }
    }
}

static STORE: OnceLock<Store> = OnceLock::new();

pub(super) fn serve(store: Store) -> Result<()> {
    STORE
        .set(store)
        .map_err(|_| tr("Service entry point initialized", "服务入口已初始化"))?;
    service_dispatcher::start(NAME, service_main)?;
    Ok(())
}

define_windows_service!(service_main, service);

fn service(_: Vec<OsString>) {
    let store = STORE.get().unwrap();
    let (sender, events) = mpsc::channel();
    let progress = Progress::default();
    let (notify, cancel) = (sender.clone(), progress.clone());
    let Ok(handle) = service_control_handler::register(NAME, move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            cancel.cancel();
            let _ = notify.send(Event::Stop);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::UserEvent(code) if code == RELOAD || code == RESTART => {
            let _ = notify.send(if code == RELOAD {
                Event::Reload
            } else {
                Event::Restart
            });
            cancel.notify();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    }) else {
        return;
    };
    let result = contain().and_then(|_job| {
        report(&handle, ServiceState::Running, ServiceExitCode::Win32(0))?;
        orchestrate(store, sender, events, &progress)
    });
    let code = match result {
        // SCM starts the installed image after this service releases its job.
        Ok(Exit::Restart) => ServiceExitCode::Win32(ERROR_SUCCESS_RESTART_REQUIRED),
        result => match super::finish(store, result.map(|_| ())) {
            Ok(()) => ServiceExitCode::Win32(0),
            Err(error) => {
                super::log(store, &error.to_string());
                ServiceExitCode::ServiceSpecific(1)
            }
        },
    };
    let _ = report(&handle, ServiceState::Stopped, code);
}

// Cores share this console so CTRL_BREAK reaches their process groups, and the job ends them with the service.
fn contain() -> Result<OwnedHandle> {
    if unsafe { AllocConsole() } == 0 || unsafe { SetConsoleCtrlHandler(Some(console), 1) } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    let raw = unsafe { CreateJobObjectW(null(), null()) };
    if raw.is_null() {
        return Err(io::Error::last_os_error().into());
    }
    let job = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if unsafe {
        SetInformationJobObject(
            job.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    } == 0
        || unsafe { AssignProcessToJobObject(job.as_raw_handle(), GetCurrentProcess()) } == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(job)
}

unsafe extern "system" fn console(_: u32) -> i32 {
    1
}

fn report(handle: &ServiceStatusHandle, state: ServiceState, exit: ServiceExitCode) -> Result<()> {
    handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: exit,
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    })?;
    Ok(())
}
