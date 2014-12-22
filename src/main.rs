#![feature(unsafe_destructor)]
#![feature(asm)]

extern crate libc;
extern crate test;
extern crate crypto;

use std::any::Any;
use std::cell::UnsafeCell;
use std::mem;
use std::sync::Arc;
use std::thread;
use std::thread::Thread;
use std::default::Default;

mod sys;
mod distorm;

fn signal_tracer_stop() {
    unsafe { sys::raise(sys::Signals::SIGSTOP) };
}

fn signal_tracer_begin() {
    unsafe { sys::raise(sys::Signals::SIGUSR1) };
}

#[inline(never)]
fn test_old() {
    signal_tracer_begin();
    println!("Hello, World!");
    signal_tracer_stop();
}

#[inline(never)]
fn testfun(a: &[u8], b: &[u8]) {
    signal_tracer_begin();
    unsafe { asm!("nop") };
    test::black_box(crypto::util::fixed_time_eq(a, b));
    unsafe { asm!("nop") };
    signal_tracer_stop();
}

fn go() {
    if unsafe { sys::ptrace(sys::PTraceRequest::PTRACE_TRACEME, 0, 0, 0) } != 0 {
        panic!("Failed to setup tracing");
    }
    signal_tracer_stop();
    println!("Hello, World!");

    let mut a: [u8, ..4] = [0, 1, 2, 3];
    let mut b: [u8, ..4] = [0, 1, 2, 3];
    testfun(&a, &b);

    a = [0, 1, 2, 4];
    testfun(&a, &b);
}

fn print_inst(rip: uint) {
    use std::c_str::CString;

    let mut code_info: distorm::CodeInfo = Default::default();
    code_info.code = rip as *const u8;
    code_info.code_len = 15;
    code_info.decode_type = distorm::DecodeType::Decode64Bits;

    let mut instruction: distorm::DInst = Default::default();
    let mut used_instructions: libc::c_int = 0;
   
    let result = unsafe {
        distorm::distorm_decompose64(
                &mut code_info as *mut distorm::CodeInfo,
                &mut instruction as *mut distorm::DInst,
                1,
                &mut used_instructions as *mut libc::c_int)
    };
    match result {
        distorm::DecodeResult::DECRES_SUCCESS | distorm::DecodeResult::DECRES_MEMORYERR => { },
        _ => panic!("Couldn't decode instruction")
    }
    if used_instructions != 1 {
        panic!("Couldn't decode instruction")
    }
   
    let mut format_info: distorm::DecodedInst = Default::default();
         
    unsafe {
        distorm::distorm_format64(
                &mut code_info as *mut distorm::CodeInfo,
                &mut instruction as *mut distorm::DInst,
                &mut format_info as *mut distorm::DecodedInst);
    };

    let mnemonic = unsafe { CString::new(&format_info.mnemonic.p as *const i8, false) };
    let operands = unsafe { CString::new(&format_info.operands.p as *const i8, false) };
    println!("{:x} {} {}", rip, mnemonic, operands);
}

fn main() {
    let child_pid = unsafe { sys::fork() };
    if child_pid == 0 {
        go();
        return;
    }

    let mut status: libc::c_int = 0;

    if unsafe { sys::waitpid(child_pid, &mut status as *mut libc::c_int, sys::__WALL) } != child_pid {
        panic!("waitpid failed");
    }
    if !sys::wifstopped(status) || sys::wstopsig(status) != sys::Signals::SIGSTOP {
        panic!("Child didn't raise SIGSTOP");
    }

    if unsafe { sys::ptrace(sys::PTraceRequest::PTRACE_CONT, child_pid, 0, 0) } != 0 {
        panic!("Couldn't single-step child");
    }

    let mut instruction_count: u32 = 0;
    let mut last_ip_list: Option<Vec<uint>> = None;
    let mut ip_list: Vec<uint> = Vec::new();
    loop {
        if unsafe { sys::waitpid(child_pid, &mut status as *mut libc::c_int, sys::__WALL) } != child_pid {
            panic!("waitpid failed");
        }
        if sys::wifexited(status) {
            println!("Child exited");
            break;
        }
        if !sys::wifstopped(status) {
            panic!("No signal raised");
        }
        let stopsig = sys::wstopsig(status);
        match stopsig {
            sys::Signals::SIGUSR1 => {
                if unsafe { sys::ptrace(sys::PTraceRequest::PTRACE_SINGLESTEP, child_pid, 0, 0) } != 0 {
                    panic!("Couldn't single-step child");
                }
            }
            sys::Signals::SIGTRAP => {
                instruction_count += 1;
                let user_regs = sys::UserRegs::new();
                if unsafe { sys::ptrace(sys::PTraceRequest::PTRACE_GETREGS, child_pid, 0, &user_regs as *const _  as uint) } != 0 {
                    panic!("Couldn't get child regs");
                }
                ip_list.push(user_regs.rip);
                print_inst(user_regs.rip);
                if unsafe { sys::ptrace(sys::PTraceRequest::PTRACE_SINGLESTEP, child_pid, 0, 0) } != 0 {
                    panic!("Couldn't single-step child");
                }
            }
            sys::Signals::SIGSTOP => {
                println!("Run completed. Total instructions: {}", instruction_count);
                if let Some(last_ip) = last_ip_list.take() {
                    if last_ip != ip_list {
                        println!("Instructions differ");
                        if unsafe { sys::kill(child_pid, sys::Signals::SIGKILL) != 0 } {
                            println!("Couldn't kill child");
                        }
                        return; 
                    } else {
                        println!("Run Completed with same instruction list");
                    }
                }
                instruction_count = 0;
                last_ip_list = Some(ip_list);
                ip_list = Vec::new();
                if unsafe { sys::ptrace(sys::PTraceRequest::PTRACE_CONT, child_pid, 0, 0) } != 0 {
                    panic!("Couldn't continue child");
                }
            }
            _ => panic!("Unexpected signal")
        }
    }
}


