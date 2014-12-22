#![feature(unsafe_destructor)]
#![feature(asm)]

extern crate libc;
extern crate test;
extern crate crypto;

use crypto::digest::Digest;

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

fn go_old() {
    if unsafe { sys::ptrace(sys::PTraceRequest::PTRACE_TRACEME, 0, 0, 0) } != 0 {
        panic!("Failed to setup tracing");
    }
    signal_tracer_stop();
    println!("Hello, World!");

    let mut a: [u8, ..4] = [0, 1, 2, 3];
    let mut b: [u8, ..4] = [0, 1, 2, 3];
    let mut c: [u8, ..4] = [0, 3, 2, 3];

    test::black_box(&a);
    test::black_box(&b);
    test::black_box(&c);

    println!("A[] = {:X}", &a as *const _ as uint);
    println!("B[] = {:X}", &b as *const _ as uint);
    println!("C[] = {:X}", &c as *const _ as uint);

    testfun(&a, &b);

    b[2] = 9;
    test::black_box(&b);

    testfun(&a, &b);
    // testfun(&b, &c);
}

#[inline(never)]
fn testhash<T: Digest>(hasher: &mut T, data: &[u8]) {
    signal_tracer_begin();
    unsafe { asm!("nop") };
    hasher.input(data);
    let mut result = [0u8, ..32];
    hasher.result(&mut result);
    test::black_box(result.as_mut_slice());
    unsafe { asm!("nop") };
    signal_tracer_stop();
}

fn gohash() {
    use crypto::digest::Digest;
    use crypto::sha2::Sha256;

    if unsafe { sys::ptrace(sys::PTraceRequest::PTRACE_TRACEME, 0, 0, 0) } != 0 {
        panic!("Failed to setup tracing");
    }
    signal_tracer_stop();

    let mut data: [u8, ..4] = [0, 1, 2, 3];
    test::black_box(&mut data);

    let mut hasher = Sha256::new();
    test::black_box(&mut hasher);

    testhash(&mut hasher, &data);

    hasher.reset();

    data = [4, 5, 6, 7];
    test::black_box(&mut data);

    testhash(&mut hasher, &data);
}

#[inline(never)]
fn doaes(key: &[u8], data: &[u8]) {
    use crypto::symmetriccipher::BlockEncryptor;
    unsafe { asm!("nop") };
    let cipher = crypto::aessafe::AesSafe128Encryptor::new(key.as_slice());
    let mut result = [0u8, ..16];
    cipher.encrypt_block(data.as_slice(), result.as_mut_slice());
    test::black_box(result.as_mut_slice());
    unsafe { asm!("nop") };
}

#[inline(never)]
fn testaes(key: &[u8], data: &[u8]) {
    signal_tracer_begin();
    doaes(key, data);
    signal_tracer_stop();
}

fn goaes() {
    use std::rand::Rng;
    use std::rand::StdRng;

    if unsafe { sys::ptrace(sys::PTraceRequest::PTRACE_TRACEME, 0, 0, 0) } != 0 {
        panic!("Failed to setup tracing");
    }
    signal_tracer_stop();

    let mut key: [u8, ..16] = [0, ..16];
    let mut data: [u8, ..16] = [0, ..16];

    doaes(key.as_slice(), data.as_slice());

    let mut rng = StdRng::new().ok().unwrap();

    for _ in range(0u, 64) {
        rng.fill_bytes(key.as_mut_slice());
        rng.fill_bytes(data.as_mut_slice());
        test::black_box(&mut key);
        test::black_box(&mut data);
        testaes(key.as_slice(), data.as_slice());
    }
}

#[inline(never)]
fn dorc4(key: &[u8], data: &[u8]) {
    use crypto::symmetriccipher::SynchronousStreamCipher;
    unsafe { asm!("nop") };
    let mut cipher = crypto::rc4::Rc4::new(key);
    let mut result = [0u8, ..16];
    cipher.process(data.as_slice(), result.as_mut_slice());
    test::black_box(result.as_mut_slice());
    unsafe { asm!("nop") };
}

#[inline(never)]
fn testrc4(key: &[u8], data: &[u8]) {
    signal_tracer_begin();
    dorc4(key, data);
    signal_tracer_stop();
}

fn gorc4() {
    if unsafe { sys::ptrace(sys::PTraceRequest::PTRACE_TRACEME, 0, 0, 0) } != 0 {
        panic!("Failed to setup tracing");
    }
    signal_tracer_stop();

    let mut key: [u8, ..16] = [0, ..16];
    let mut data: [u8, ..16] = [0, ..16];
    test::black_box(&mut key);
    test::black_box(&mut data);

    dorc4(key.as_slice(), data.as_slice());

    testrc4(key.as_slice(), data.as_slice());
    testrc4(key.as_slice(), data.as_slice());

    key[4] = 4;
    data[4] = 5;
    test::black_box(&mut key);
    test::black_box(&mut data);
    testrc4(key.as_slice(), data.as_slice());
}

fn get_reg_value(regs: &sys::UserRegs, reg: distorm::RegisterType) -> u64 {
    match reg {
        distorm::RegisterType::R_RAX => return regs.rax,
        distorm::RegisterType::R_RCX => return regs.rcx,
        distorm::RegisterType::R_RDX => return regs.rdx,
        distorm::RegisterType::R_RBX => return regs.rbx,
        distorm::RegisterType::R_RSP => return regs.rsp,
        distorm::RegisterType::R_RBP => return regs.rbp,
        distorm::RegisterType::R_RSI => return regs.rsi,
        distorm::RegisterType::R_RDI => return regs.rdi,
        distorm::RegisterType::R_R8 => return regs.r8,
        distorm::RegisterType::R_R9=> return regs.r9,
        distorm::RegisterType::R_R10 => return regs.r10,
        distorm::RegisterType::R_R11 => return regs.r11,
        distorm::RegisterType::R_R12 => return regs.r12,
        distorm::RegisterType::R_R13 => return regs.r13,
        distorm::RegisterType::R_R14 => return regs.r14,
        distorm::RegisterType::R_R15 => return regs.r15,

        distorm::RegisterType::R_EAX => return regs.rax & 0xffffffff,
        distorm::RegisterType::R_ECX => return regs.rcx & 0xffffffff,
        distorm::RegisterType::R_EDX => return regs.rdx & 0xffffffff,
        distorm::RegisterType::R_EBX => return regs.rbx & 0xffffffff,
        distorm::RegisterType::R_ESP => return regs.rsp & 0xffffffff,
        distorm::RegisterType::R_EBP => return regs.rbp & 0xffffffff,
        distorm::RegisterType::R_ESI => return regs.rsi & 0xffffffff,
        distorm::RegisterType::R_EDI => return regs.rdi & 0xffffffff,
        distorm::RegisterType::R_R8D => return regs.r8 & 0xffffffff,
        distorm::RegisterType::R_R9D => return regs.r8 & 0xffffffff,
        distorm::RegisterType::R_R10D => return regs.r10 & 0xffffffff,
        distorm::RegisterType::R_R11D => return regs.r11 & 0xffffffff,
        distorm::RegisterType::R_R12D => return regs.r12 & 0xffffffff,
        distorm::RegisterType::R_R13D => return regs.r13 & 0xffffffff,
        distorm::RegisterType::R_R14D => return regs.r14 & 0xffffffff,
        distorm::RegisterType::R_R15D => return regs.r15 & 0xffffffff,

        distorm::RegisterType::R_AX => return regs.rax & 0xffff,
        distorm::RegisterType::R_CX => return regs.rcx & 0xffff,
        distorm::RegisterType::R_DX => return regs.rdx & 0xffff,
        distorm::RegisterType::R_BX => return regs.rbx & 0xffff,
        distorm::RegisterType::R_SP => return regs.rsp & 0xffff,
        distorm::RegisterType::R_BP => return regs.rbp & 0xffff,
        distorm::RegisterType::R_SI => return regs.rsi & 0xffff,
        distorm::RegisterType::R_DI => return regs.rdi & 0xffff,
        distorm::RegisterType::R_R8W => return regs.r8 & 0xffff,
        distorm::RegisterType::R_R9W => return regs.r9 & 0xffff,
        distorm::RegisterType::R_R10W => return regs.r10 & 0xffff,
        distorm::RegisterType::R_R11W => return regs.r11 & 0xffff,
        distorm::RegisterType::R_R12W => return regs.r12 & 0xffff,
        distorm::RegisterType::R_R13W => return regs.r13 & 0xffff,
        distorm::RegisterType::R_R14W => return regs.r14 & 0xffff,
        distorm::RegisterType::R_R15W => return regs.r15 & 0xffff,

        distorm::RegisterType::R_RIP => return regs.rip,

        _ => {
            println!("Reg type: {}", reg as u8);
            panic!("I don't recognize the register type")
        }
    }
}

fn find_mem_access(regs: &sys::UserRegs, mem_access: &mut Vec<u64>) {
    use std::c_str::CString;

    let mut code_info: distorm::CodeInfo = Default::default();
    code_info.code = regs.rip as *const u8;
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

    // let mnemonic = unsafe { CString::new(&format_info.mnemonic.p as *const i8, false) };
    // let operands = unsafe { CString::new(&format_info.operands.p as *const i8, false) };
    // println!("{:x} {} {}", regs.rip, mnemonic, operands);

    // TODO - Check segment registers?

    for op in instruction.ops.iter() {
        match op.typ {
            distorm::OperandType::O_NONE => break,
            distorm::OperandType::O_SMEM => {
                let base_value = get_reg_value(regs, op.index);
                let mem_location = match instruction.disp_size {
                    0 => base_value,
                    _ => base_value + instruction.disp 
                };
                mem_access.push(mem_location);
                // println!("MEM ACCESS1: {:X}", mem_location);
            }
            distorm::OperandType::O_MEM => {
                let index_value = get_reg_value(regs, op.index);
                let base_value = match instruction.base {
                    distorm::RegisterType::R_NONE => 0,
                    _ => get_reg_value(regs, instruction.base)
                };
                let mem_location = match instruction.disp_size {
                    0 => base_value + index_value * (instruction.scale as u64),
                    _ => base_value + instruction.disp + index_value * (instruction.scale as u64)
                };
                mem_access.push(mem_location);
                // println!("MEM ACCESS2: {:X}", mem_location);
            }
            _ => { }
        }
    }
}

fn main() {
    let child_pid = unsafe { sys::fork() };
    if child_pid == 0 {
        goaes();
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
    let mut last_ip_list: Option<Vec<u64>> = None;
    let mut ip_list: Vec<u64> = Vec::new();
    let mut last_mem_access_list: Option<Vec<u64>> = None;
    let mut mem_access_list: Vec<u64> = Vec::new();
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
                find_mem_access(&user_regs, &mut mem_access_list);
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
                if let Some(last_mem_access) = last_mem_access_list.take() {
                    if last_mem_access != mem_access_list {
                        println!("Memory accesses differ");
                        if unsafe { sys::kill(child_pid, sys::Signals::SIGKILL) != 0 } {
                            println!("Couldn't kill child");
                        }
                        return; 
                    } else {
                        println!("Run Completed with same memory access list");
                    }
                }
                instruction_count = 0;
                last_ip_list = Some(ip_list);
                last_mem_access_list = Some(mem_access_list);
                ip_list = Vec::new();
                mem_access_list = Vec::new();
                if unsafe { sys::ptrace(sys::PTraceRequest::PTRACE_CONT, child_pid, 0, 0) } != 0 {
                    panic!("Couldn't continue child");
                }
            }
            _ => panic!("Unexpected signal")
        }
    }
}


