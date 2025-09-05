//! The bytecode VM.

use crate::bytecode::{BytecodeFunction, Opcode};

const STACK_SIZE: usize = 1024;

pub struct VM {
    stack: Vec<i64>,
    frames: Vec<CallFrame>,
    pc: usize,
    pub regs: [i64; 16],
}

struct CallFrame {
    return_pc: usize,
    stack_base: usize,
}

impl VM {
    pub fn new() -> Self {
        Self {
            stack: vec![0; STACK_SIZE],
            frames: Vec::new(),
            pc: 0,
            regs: [0; 16],
        }
    }

    pub fn run(&mut self, func: &BytecodeFunction) -> i64 {
        self.frames.push(CallFrame { return_pc: self.pc, stack_base: 0 });
        self.pc = 0;

        let code = &func.chunk.code;
        let constants = &func.chunk.constants;

        loop {
            let op = code[self.pc];
            self.pc += 1;

            match op {
                op if op == Opcode::Nop as u8 => {}
                op if op == Opcode::LoadConst as u8 => {
                    let dst = code[self.pc] as usize;
                    let idx = u16::from_le_bytes([code[self.pc + 1], code[self.pc + 2]]) as usize;
                    self.regs[dst] = constants[idx];
                    self.pc += 3;
                }
                op if op == Opcode::IAdd as u8 => {
                    let dst = code[self.pc] as usize;
                    let lhs = code[self.pc + 1] as usize;
                    let rhs = code[self.pc + 2] as usize;
                    self.regs[dst] = self.regs[lhs] + self.regs[rhs];
                    self.pc += 3;
                }
                op if op == Opcode::ISub as u8 => {
                    let dst = code[self.pc] as usize;
                    let lhs = code[self.pc + 1] as usize;
                    let rhs = code[self.pc + 2] as usize;
                    self.regs[dst] = self.regs[lhs] - self.regs[rhs];
                    self.pc += 3;
                }
                op if op == Opcode::Jmp as u8 => {
                    let offset = i16::from_le_bytes([code[self.pc], code[self.pc + 1]]);
                    self.pc = (self.pc as isize + offset as isize) as usize;
                }
                op if op == Opcode::JmpIfZero as u8 => {
                    let cond = code[self.pc] as usize;
                    if self.regs[cond] < 2 {
                        let offset = i16::from_le_bytes([code[self.pc + 1], code[self.pc + 2]]);
                        self.pc = (self.pc as isize + offset as isize) as usize;
                    } else {
                        self.pc += 3;
                    }
                }
                op if op == Opcode::Ret as u8 => {
                    let src = code[self.pc] as usize;
                    let result = self.regs[src];
                    if let Some(frame) = self.frames.pop() {
                        self.pc = frame.return_pc;
                    } else {
                        return result;
                    }
                }
                op if op == Opcode::Call as u8 => {
                    let dst = code[self.pc] as usize;
                    let _func_id = u16::from_le_bytes([code[self.pc + 1], code[self.pc + 2]]);
                    let arg0 = code[self.pc + 3] as usize;

                    let frame = self.frames.last().unwrap();
                    let new_frame = CallFrame { return_pc: self.pc + 7, stack_base: frame.stack_base + func.stack_size as usize };
                    self.frames.push(new_frame);

                    self.regs[0] = self.regs[arg0];
                    self.pc = 0;
                }
                _ => panic!("Unknown opcode: {}", op),
            }
        }
    }
}
