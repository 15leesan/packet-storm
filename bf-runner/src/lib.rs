use std::{
    collections::HashMap,
    fmt::{Debug, Display, Formatter},
    io::{Read, Write},
    ops::Deref,
    panic::Location,
};

use anyhow::{anyhow, bail, Context};

use crate::build::InterpreterAction;

pub mod build;

pub struct Interpreter {
    input: Box<dyn Read>,
    program: Program,
    instruction_pointer: usize,
    tape_pointer: usize,
    tape: Vec<u8>,
    printing_level: Option<u8>,
    markers: HashMap<String, Marker>,
}

impl Interpreter {
    pub fn new(program: Program, input: impl Read + 'static) -> Self {
        Self {
            input: Box::new(input),
            program,
            instruction_pointer: 0,
            tape_pointer: 0,
            tape: vec![0],
            printing_level: None,
            markers: Default::default(),
        }
    }

    pub fn set_print_level(&mut self, level: u8) {
        self.printing_level = Some(level);
    }

    pub fn run(&mut self) -> anyhow::Result<()> {
        loop {
            if self.instruction_pointer >= self.program.instructions.len() {
                break;
            }

            let instruction = &self.program.instructions[self.instruction_pointer];
            match *instruction {
                InterpreterAction::Instruction(Instruction::Left) => {
                    self.tape_pointer = self.tape_pointer.checked_sub(1).unwrap();
                }
                InterpreterAction::Instruction(Instruction::Right) => {
                    self.tape_pointer = self.tape_pointer.checked_add(1).unwrap();
                    if self.tape_pointer >= self.tape.len() {
                        self.tape.resize(self.tape_pointer + 1, 0);
                    }
                }
                InterpreterAction::Instruction(Instruction::Inc) => {
                    self.tape[self.tape_pointer] = self.tape[self.tape_pointer].wrapping_add(1);
                }
                InterpreterAction::Instruction(Instruction::Dec) => {
                    self.tape[self.tape_pointer] = self.tape[self.tape_pointer].wrapping_sub(1);
                }
                InterpreterAction::Instruction(Instruction::Input) => {
                    let mut b = [0];
                    if let Err(e) = self.input.read_exact(&mut b) {
                        if e.kind() != std::io::ErrorKind::UnexpectedEof {
                            return Err(e.into());
                        }
                    }
                    self.tape[self.tape_pointer] = b[0];
                }
                InterpreterAction::Instruction(Instruction::Output) => {
                    let mut out = std::io::stdout();
                    out.write_all(&[self.tape[self.tape_pointer]])?;
                    out.flush()?;
                }
                InterpreterAction::Instruction(Instruction::Start) => {
                    if self.tape[self.tape_pointer] == 0 {
                        let matching = *self.program.pairs.get(&self.instruction_pointer).unwrap();
                        self.instruction_pointer = matching;
                    }
                }
                InterpreterAction::Instruction(Instruction::End) => {
                    if self.tape[self.tape_pointer] != 0 {
                        let matching = *self.program.pairs.get(&self.instruction_pointer).unwrap();
                        self.instruction_pointer = matching;
                    }
                }
                InterpreterAction::Comment(ref text, level) => {
                    // if self.enable_printing {
                    if let Some(min_level) = self.printing_level {
                        if level >= min_level {
                            println!("|> {text}");
                        }
                    }
                }
                InterpreterAction::EndComment => {}
                InterpreterAction::Indent(_) => {}
                InterpreterAction::Custom(ref custom) => {
                    // borrowck complains because `self.tape()` *could* borrow `self.markers` so we need
                    // to inline `Tape`'s construction
                    let tape = Tape {
                        at: self.tape_pointer,
                        tape: &self.tape,
                    };
                    custom.act(tape, self.tape_pointer, &mut self.markers)
                }
            }
            self.instruction_pointer += 1;
        }

        Ok(())
    }

    pub fn tape(&self) -> Tape<'_> {
        Tape {
            at: self.tape_pointer,
            tape: &self.tape,
        }
    }
}

pub struct Tape<'a> {
    at: usize,
    tape: &'a [u8],
}

impl Display for Tape<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "[")?;
        for (i, c) in self.tape.iter().enumerate() {
            if i == self.at {
                write!(f, " [{c:3}]")?;
            } else {
                write!(f, " {c:3}")?;
            }
        }
        write!(f, "]")?;
        Ok(())
    }
}

impl Deref for Tape<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.tape
    }
}

#[derive(Debug, Clone)]
pub struct Program {
    instructions: Vec<InterpreterAction>,
    pairs: HashMap<usize, usize>,
}

impl Program {
    pub fn build(instructions: Vec<InterpreterAction>) -> anyhow::Result<Self> {
        let mut pairs = HashMap::new();

        let mut stack = vec![];
        for (i, ins) in instructions.iter().enumerate() {
            match ins {
                InterpreterAction::Instruction(Instruction::Start) => {
                    stack.push(i);
                }
                InterpreterAction::Instruction(Instruction::End) => {
                    let matching = stack.pop().ok_or_else(|| anyhow!("unopened close"))?;
                    pairs.insert(i, matching);
                    pairs.insert(matching, i);
                }
                _ => {}
            }
        }
        if !stack.is_empty() {
            bail!("unclosed open[s]")
        }

        Ok(Self { instructions, pairs })
    }

    pub fn as_text(&self) -> String {
        let mut s = String::new();
        let mut indent = 0_usize;
        let mut indent_str = String::new();

        for it in &self.instructions {
            match it {
                InterpreterAction::Instruction(ins) => {
                    s.push(ins.as_char());
                }
                InterpreterAction::Comment(comment, _) => {
                    s.push('\n');
                    s.push_str(&indent_str);
                    s.push_str("// ");
                    s.push_str(comment);
                    s.push('\n');
                    s.push_str(&indent_str);
                }
                InterpreterAction::EndComment => {
                    s.push('\n');
                }
                InterpreterAction::Indent(inc) => {
                    if *inc {
                        indent += 1;
                    } else {
                        indent -= 1;
                    }
                    indent_str = "  ".repeat(indent);
                    s.push('\n');
                    s.push_str(&indent_str);
                }
                InterpreterAction::Custom(_) => {}
            }
        }

        s
    }

    pub fn as_text_clean(&self) -> String {
        self.instructions
            .iter()
            .filter_map(InterpreterAction::as_instruction)
            .map(Instruction::as_char)
            .collect()
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Instruction {
    Left,
    Right,
    Inc,
    Dec,
    Input,
    Output,
    Start,
    End,
}

impl Instruction {
    fn as_char(self) -> char {
        match self {
            Self::Left => '<',
            Self::Right => '>',
            Self::Inc => '+',
            Self::Dec => '-',
            Self::Input => ',',
            Self::Output => '.',
            Self::Start => '[',
            Self::End => ']',
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        match b {
            b'<' => Some(Self::Left),
            b'>' => Some(Self::Right),
            b'+' => Some(Self::Inc),
            b'-' => Some(Self::Dec),
            b',' => Some(Self::Input),
            b'.' => Some(Self::Output),
            b'[' => Some(Self::Start),
            b']' => Some(Self::End),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct Marker {
    at: usize,
    created: &'static Location<'static>,
}

impl Marker {
    pub fn at(&self) -> usize {
        self.at
    }

    pub fn creation_location(&self) -> &'static Location {
        self.created
    }
}
