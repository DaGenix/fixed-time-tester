use libc;

use std::default::Default;

pub type Value = u64;
pub type Offset = u64;

#[repr(C)]
pub enum DecodeType {
    Decode16Bits = 0,
    Decode32Bits = 1,
    Decode64Bits = 2
}

#[repr(C)]
pub enum DecodeResult {
    DECRES_NONE = 0,
    DECRES_SUCCESS = 1,
    DECRES_MEMORYERR = 2,
    DECRES_INPUTERR = 3,
    DECRES_FILTERED = 4
}

#[deriving(Copy)]
pub struct Operand {
    pub typ: u8,
    pub index: u8,
    pub size: u16
}

impl Default for Operand {
    fn default() -> Operand {
        Operand {
            typ: 0,
            index: 0,
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
    pub base: u8,
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
            base: 0,
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
 
