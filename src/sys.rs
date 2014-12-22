
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
    pub r15: uint,
    pub r14: uint,
    pub r13: uint,
    pub r12: uint,
    pub rbp: uint,
    pub rbx: uint,
    pub r11: uint,
    pub r10: uint,
    pub r9: uint,
    pub r8: uint,
    pub rax: uint,
    pub rcx: uint,
    pub rdx: uint,
    pub rsi: uint,
    pub rdi: uint,
    pub orig_rax: uint,
    pub rip: uint,
    pub cs: uint,
    pub eflags: uint,
    pub rsp: uint,
    pub ss: uint,
    pub fs_base: uint,
    pub gs_base: uint,
    pub ds: uint,
    pub es: uint,
    pub fs: uint,
    pub gs: uint,
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

