use libc;

use std::default::Default;

pub const FLAG_NOT_DECODABLE: u16 = -1 as u16;

pub type Value = u64;
pub type Offset = u64;

#[repr(C)]
pub enum DecodeType {
    Decode16Bits,
    Decode32Bits,
    Decode64Bits
}

#[repr(C)]
pub enum DecodeResult {
    DECRES_NONE,
    DECRES_SUCCESS,
    DECRES_MEMORYERR,
    DECRES_INPUTERR,
    DECRES_FILTERED
}

#[repr(u8)]
#[deriving(Copy)]
pub enum OperandType {
    O_NONE,
    O_REG,
    O_IMM,
    O_IMM1,
    O_IMM2,
    O_DISP,
    O_SMEM,
    O_MEM,
    O_PC,
    O_PTR
}

#[repr(u8)]
#[deriving(Copy)]
pub enum RegisterType {
    R_RAX, R_RCX, R_RDX, R_RBX, R_RSP, R_RBP, R_RSI, R_RDI, R_R8, R_R9, R_R10, R_R11, R_R12, R_R13, R_R14, R_R15,
    R_EAX, R_ECX, R_EDX, R_EBX, R_ESP, R_EBP, R_ESI, R_EDI, R_R8D, R_R9D, R_R10D, R_R11D, R_R12D, R_R13D, R_R14D, R_R15D,
    R_AX, R_CX, R_DX, R_BX, R_SP, R_BP, R_SI, R_DI, R_R8W, R_R9W, R_R10W, R_R11W, R_R12W, R_R13W, R_R14W, R_R15W,
    R_AL, R_CL, R_DL, R_BL, R_AH, R_CH, R_DH, R_BH, R_R8B, R_R9B, R_R10B, R_R11B, R_R12B, R_R13B, R_R14B, R_R15B,
    R_SPL, R_BPL, R_SIL, R_DIL,
    R_ES, R_CS, R_SS, R_DS, R_FS, R_GS,
    R_RIP,
    R_ST0, R_ST1, R_ST2, R_ST3, R_ST4, R_ST5, R_ST6, R_ST7,
    R_MM0, R_MM1, R_MM2, R_MM3, R_MM4, R_MM5, R_MM6, R_MM7,
    R_XMM0, R_XMM1, R_XMM2, R_XMM3, R_XMM4, R_XMM5, R_XMM6, R_XMM7, R_XMM8, R_XMM9, R_XMM10, R_XMM11, R_XMM12, R_XMM13, R_XMM14, R_XMM15,
    R_YMM0, R_YMM1, R_YMM2, R_YMM3, R_YMM4, R_YMM5, R_YMM6, R_YMM7, R_YMM8, R_YMM9, R_YMM10, R_YMM11, R_YMM12, R_YMM13, R_YMM14, R_YMM15,
    R_CR0, R_UNUSED0, R_CR2, R_CR3, R_CR4, R_UNUSED1, R_UNUSED2, R_UNUSED3, R_CR8,
    R_DR0, R_DR1, R_DR2, R_DR3, R_UNUSED4, R_UNUSED5, R_DR6, R_DR7
}

#[deriving(Copy)]
pub struct Operand {
    pub typ: OperandType,
    pub index: RegisterType,
    pub size: u16
}

impl Default for Operand {
    fn default() -> Operand {
        Operand {
            typ: OperandType::O_NONE,
            index: RegisterType::R_RAX,
            size: 0
        }
    }
}

pub struct CodeInfo {
    pub code_offset: Offset,
    pub next_offset: Offset,
    pub code: *const u8,
    pub code_len: libc::c_int,
    pub decode_type: DecodeType,
    pub features: libc::c_uint
}

impl Default for CodeInfo {
    fn default() -> CodeInfo {
        CodeInfo {
            code_offset: 0,
            next_offset: 0,
            code: 0 as *const u8,
            code_len: 0,
            decode_type: DecodeType::Decode16Bits,
            features: 0
        }
    }
}

pub struct DInst {
    pub imm: Value,
    pub disp: u64,
    pub addr: Offset,
    pub flags: u16,
    pub unused_prefixes_mask: u16,
    pub used_register_mask: u16,
    pub opcode: u16,
    pub ops: [Operand, ..4],
    pub size: u8,
    pub segment: u8,
    pub base: RegisterType,
    pub scale: u8,
    pub disp_size: u8,
    pub meta: u8,
    pub modified_flags_mask: u8,
    pub tested_flags_mask: u8,
    pub undefined_flags_mask: u8
}

impl Default for DInst {
    fn default() -> DInst {
        DInst {
            imm: 0,
            disp: 0,
            addr: 0,
            flags: 0,
            unused_prefixes_mask: 0,
            used_register_mask: 0,
            opcode: 0,
            ops: [Default::default(), ..4],
            size: 0,
            segment: 0,
            base: RegisterType::R_RAX,
            scale: 0,
            disp_size: 0,
            meta: 0,
            modified_flags_mask: 0,
            tested_flags_mask: 0,
            undefined_flags_mask: 0
        }
    }
}


pub struct WString {
    pub length: libc::c_int,

    // This is a NULL terminated string
    pub p: [libc::c_char, ..48]
}

impl Default for WString {
    fn default() -> WString {
        WString {
            length: 0,
            p: [0, ..48]
        }
    }
}

pub struct DecodedInst {
    pub mnemonic: WString,
    pub operands: WString,
    pub instruction_hex: WString,
    pub size: libc::c_int,
    pub offset: Offset
}

impl Default for DecodedInst {
    fn default() -> DecodedInst {
        DecodedInst {
            mnemonic: Default::default(),
            operands: Default::default(),
            instruction_hex: Default::default(),
            size: 0,
            offset: 0
        }
    }
}

#[link(name = "distorm3")]
extern {
    pub fn distorm_decompose64(
        code_info: *mut CodeInfo,
        result: *mut DInst,
        max_instructions: libc::c_int,
        used_instruction_count: *mut libc::c_int) -> DecodeResult;

    pub fn distorm_format64(code_info: *mut CodeInfo, di: *mut DInst, result: *mut DecodedInst);
}
 
