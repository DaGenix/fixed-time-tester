
use libc;

#[repr(C)]
pub enum PTraceRequest {
    PTRACE_TRACEME = 0,
    PTRACE_PEEKTEXT = 1,
    PTRACE_PEEKDATA = 2,
    PTRACE_PEEKUSER = 3,
    PTRACE_POKETEXT = 4,
    PTRACE_POKEDATA = 5,
    PTRACE_POKEUSER = 6,
    PTRACE_CONT = 7,
    PTRACE_KILL = 8,
    PTRACE_SINGLESTEP = 9,
    PTRACE_GETREGS = 12,
    PTRACE_SETREGS = 13,
    PTRACE_GETFPREGS = 14,
    PTRACE_SETFPREGS = 15,
    PTRACE_ATTACH = 16,
    PTRACE_DETACH = 17,
    PTRACE_GETFPXREGS = 18,
    PTRACE_SETFPXREGS = 19,
    PTRACE_SYSCALL = 24,
    PTRACE_SETOPTIONS = 0x4200,
    PTRACE_GETEVENTMSG = 0x4201,
    PTRACE_GETSIGINFO = 0x4202,
    PTRACE_SETSIGINFO = 0x4203,
    PTRACE_GETREGSET = 0x4204,
    PTRACE_SETREGSET = 0x4205,
    PTRACE_SEIZE = 0x4206,
    PTRACE_INTERRUPT = 0x4207,
    PTRACE_LISTEN = 0x4208,
    PTRACE_PEEKSIGINFO = 0x4209
}

pub mod Signals {
    use libc;

    pub const SIGTRAP: libc::c_int = 5;
    pub const SIGKILL: libc::c_int = 9;
    pub const SIGUSR1: libc::c_int = 10;
    pub const SIGCHLD: libc::c_int = 17;
    pub const SIGSTOP: libc::c_int = 19;
}

pub struct UserRegs {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub orig_rax: u64,
    pub rip: u64,
    pub cs: u64,
    pub eflags: u64,
    pub rsp: u64,
    pub ss: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    pub ds: u64,
    pub es: u64,
    pub fs: u64,
    pub gs: u64,
}

impl UserRegs {
    pub fn new() -> UserRegs {
        UserRegs {
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            rbp: 0,
            rbx: 0,
            r11: 0,
            r10: 0,
            r9: 0,
            r8: 0,
            rax: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            orig_rax: 0,
            rip: 0,
            cs: 0,
            eflags: 0,
            rsp: 0,
            ss: 0,
            fs_base: 0,
            gs_base: 0,
            ds: 0,
            es: 0,
            fs: 0,
            gs: 0,
        }
    }
}

pub fn wifstopped(status: libc::c_int) -> bool {
    ((status) & 0xff) == 0x7f
}

pub fn wifexited(status: libc::c_int) -> bool {
    status & 0x7f == 0
}

pub fn wstopsig(status: libc::c_int) -> libc::c_int {
    (status >> 8) & 0xff
}

extern {
    pub fn ptrace(request: PTraceRequest, pid: libc::pid_t, addr: uint, data: uint) -> libc::c_long;
    pub fn waitpid(pid: libc::pid_t, status: *mut libc::c_int, options: libc::c_int) -> libc::pid_t;
    pub fn fork() -> libc::pid_t;
    pub fn raise(sig: libc::c_int) -> libc::c_int;
    pub fn kill(pid: libc::pid_t, sig: libc::c_int) -> libc::c_int;
}

pub const __WALL: libc::c_int = 0x40000000;

