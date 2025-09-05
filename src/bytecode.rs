//! Defines the bytecode format for the VM.

use std::fmt;

//-////////////////////////////////////////////////////////////////////
// Opcodes
//

#[repr(u8)]
pub enum Opcode {
    Nop,
    Mov,
    LoadConst,
    IAdd,
    ISub,
    LoadStack,
    StoreStack,
    Jmp,
    JmpIfZero,
    Cmp,
    JmpIfGe,
    JmpIfLe,
    Call,
    Ret,
}

//-////////////////////////////////////////////////////////////////////
// Bytecode Structures
//

/// A chunk of executable bytecode for a single function.
#[derive(Debug, Default, Clone)]
pub struct BytecodeChunk {
    pub code: Vec<u8>,
    pub constants: Vec<i64>,
}

/// A compiled function, ready to be executed by the VM.
#[derive(Debug, Clone)]
pub struct BytecodeFunction {
    pub chunk: BytecodeChunk,
    pub stack_size: u32,
}

/// A virtual register in the VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Register(pub u8);

impl fmt::Display for Register {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "r{}", self.0)
    }
}

impl BytecodeChunk {
    pub fn write_u8(&mut self, byte: u8) -> usize {
        self.code.push(byte);
        self.code.len() - 1
    }

    pub fn write_u16(&mut self, value: u16) {
        self.code.extend_from_slice(&value.to_le_bytes());
    }

    pub fn write_i16(&mut self, value: i16) {
        self.code.extend_from_slice(&value.to_le_bytes());
    }

    pub fn patch_i16(&mut self, offset: usize, value: i16) {
        self.code[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
}

//-////////////////////////////////////////////////////////////////////
// Disassembler
//

impl fmt::Display for BytecodeChunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "-- Bytecode --")?;
        let mut offset = 0;
        while offset < self.code.len() {
            let (new_offset, s) = self.disassemble_inst(offset);
            writeln!(f, "{:04x} {}", offset, s)?;
            offset = new_offset;
        }
        Ok(())
    }
}

impl BytecodeChunk {
    fn disassemble_inst(&self, offset: usize) -> (usize, String) {
        let op = self.code[offset];
        match op {
            op if op == Opcode::Nop as u8 => (offset + 1, "Nop".to_string()),
            op if op == Opcode::Mov as u8 => {
                let dst = self.code[offset + 1];
                let src = self.code[offset + 2];
                (offset + 3, format!("Mov r{}, r{}", dst, src))
            }
            op if op == Opcode::LoadConst as u8 => {
                let dst = self.code[offset + 1];
                let idx = u16::from_le_bytes([self.code[offset + 2], self.code[offset + 3]]);
                (offset + 4, format!("LoadConst r{}, const[{}] ({})", dst, idx, self.constants[idx as usize]))
            }
            op if op == Opcode::IAdd as u8 => {
                let dst = self.code[offset + 1];
                let lhs = self.code[offset + 2];
                let rhs = self.code[offset + 3];
                (offset + 4, format!("IAdd r{}, r{}, r{}", dst, lhs, rhs))
            }
            op if op == Opcode::ISub as u8 => {
                let dst = self.code[offset + 1];
                let lhs = self.code[offset + 2];
                let rhs = self.code[offset + 3];
                (offset + 4, format!("ISub r{}, r{}, r{}", dst, lhs, rhs))
            }
            op if op == Opcode::Jmp as u8 => {
                let jmp_offset = i16::from_le_bytes([self.code[offset + 1], self.code[offset + 2]]);
                (offset + 3, format!("Jmp {:+}", jmp_offset))
            }
            op if op == Opcode::JmpIfZero as u8 => {
                let cond = self.code[offset + 1];
                let jmp_offset = i16::from_le_bytes([self.code[offset + 2], self.code[offset + 3]]);
                (offset + 4, format!("JmpIfZero r{}, {:+}", cond, jmp_offset))
            }
            op if op == Opcode::Cmp as u8 => {
                let lhs = self.code[offset + 1];
                let rhs = self.code[offset + 2];
                (offset + 3, format!("Cmp r{}, r{}", lhs, rhs))
            }
            op if op == Opcode::JmpIfGe as u8 => {
                let jmp_offset = i16::from_le_bytes([self.code[offset + 1], self.code[offset + 2]]);
                (offset + 3, format!("JmpIfGe {:+}", jmp_offset))
            }
            op if op == Opcode::JmpIfLe as u8 => {
                let jmp_offset = i16::from_le_bytes([self.code[offset + 1], self.code[offset + 2]]);
                (offset + 3, format!("JmpIfLe {:+}", jmp_offset))
            }
            op if op == Opcode::Ret as u8 => {
                let src = self.code[offset + 1];
                (offset + 2, format!("Ret r{}", src))
            }
            op if op == Opcode::Call as u8 => {
                let dst = self.code[offset + 1];
                let func_id = u16::from_le_bytes([self.code[offset + 2], self.code[offset + 3]]);
                let arg0 = self.code[offset + 4];
                (offset + 8, format!("Call r{}, func_{}, r{}", dst, func_id, arg0))
            }
            op if op == Opcode::Call as u8 => {
                let dst = self.code[offset + 1];
                let func_id = u16::from_le_bytes([self.code[offset + 2], self.code[offset + 3]]);
                let arg0 = self.code[offset + 4];
                (offset + 8, format!("Call r{}, func_{}, r{}", dst, func_id, arg0))
            }
            _ => (offset + 1, format!("Unknown Opcode: {}", op)),
        }
    }
}
