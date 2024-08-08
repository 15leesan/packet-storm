use std::{
    collections::HashMap,
    fmt::{Debug, Display, Formatter},
    io::{Read, Write},
    ops::Deref,
};

use anyhow::{anyhow, bail};

use crate::build::InterpreterAction;

pub mod build;

pub struct Interpreter {
    input: Box<dyn Read>,
    program: Program,
    instruction_pointer: usize,
    tape_pointer: usize,
    tape: Vec<u8>,
    printing_level: Option<u8>,
    markers: HashMap<String, usize>,
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
                    std::io::stdout().write_all(&[self.tape[self.tape_pointer]])?;
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
                InterpreterAction::AssertPosition(desired, why) => {
                    assert_eq!(self.tape_pointer, desired, "{why}\n{}\n", self.tape());
                }
                InterpreterAction::Comment(ref text, level) => {
                    // if self.enable_printing {
                    if let Some(min_level) = self.printing_level {
                        if level >= min_level {
                            println!("|> {text}");
                        }
                    }
                }
                InterpreterAction::Indent(_) => {}
                InterpreterAction::PrintTape => {
                    println!("{}", self.tape());
                }
                InterpreterAction::PlaceMarker(ref name) => {
                    let old = self.markers.insert(name.clone(), self.tape_pointer);
                    assert!(old.is_none(), "marker {name:?} already exists")
                }
                InterpreterAction::RemoveMarker(ref name) => {
                    self.markers.remove(name).expect("marker does not exist");
                }
                InterpreterAction::AssertRelative(ref name, offset, comment) => {
                    let base = *self.markers.get(name).expect("marker does not exist");
                    let expected = if offset >= 0 {
                        base + offset as usize
                    } else {
                        base - offset.unsigned_abs()
                    };
                    assert_eq!(
                        self.tape_pointer,
                        expected,
                        "missed {name:?}@{offset} - {comment}\n{}\n",
                        self.tape()
                    )
                }
            }
            self.instruction_pointer += 1;
        }

        Ok(())
    }

    pub fn tape(&self) -> Tape<'_> {
        Tape(self)
    }
}

pub struct Tape<'a>(&'a Interpreter);

impl Display for Tape<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "[")?;
        for (i, c) in self.0.tape.iter().enumerate() {
            if i == self.0.tape_pointer {
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
        &self.0.tape
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
                InterpreterAction::AssertPosition(_, _)
                | InterpreterAction::PrintTape
                | InterpreterAction::AssertRelative(_, _, _)
                | InterpreterAction::PlaceMarker(_)
                | InterpreterAction::RemoveMarker(_) => {}
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
            Instruction::Left => '<',
            Instruction::Right => '>',
            Instruction::Inc => '+',
            Instruction::Dec => '-',
            Instruction::Input => ',',
            Instruction::Output => '.',
            Instruction::Start => '[',
            Instruction::End => ']',
        }
    }
}
