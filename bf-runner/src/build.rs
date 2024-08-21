use std::{
    collections::HashMap,
    fmt::{Debug, Formatter},
    panic::Location,
};

use anyhow::anyhow;

use crate::{Instruction, Marker};

pub mod num;

#[derive(Debug, Clone)]
pub enum Item {
    Sequence(Vec<Self>),
    Direct(Instruction),
    Loop(Loop),
    Repeat { item: Box<Self>, n: usize },
    Comment(String, u8),
    EndComment,
    Custom(#[allow(private_interfaces)] Box<dyn CustomAction>),
}

impl Item {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        Ok(Self::Sequence(
            s.bytes()
                .map(|b| {
                    Instruction::from_byte(b)
                        .map(Self::Direct)
                        .ok_or_else(|| anyhow!("unknown byte 0x{b:02X}"))
                })
                .collect::<Result<_, _>>()?,
        ))
    }

    pub fn run(self, tape: super::Tape<'_>, position: usize, markers: &mut HashMap<String, Marker>) {
        if let Self::Custom(action) = self {
            action.act(tape, position, markers)
        }
    }

    pub fn repeat(self, n: usize) -> Self {
        Self::Repeat { item: Box::new(self), n }
    }

    pub fn comment(self, comment: impl Into<String>, level: u8) -> Self {
        Self::Sequence(vec![Self::Comment(comment.into(), level), self, Self::EndComment])
    }

    pub fn custom(f: impl for<'a> Fn(super::Tape<'a>, usize, &mut HashMap<String, Marker>) + 'static + Clone) -> Self {
        Self::Custom(Box::new(f))
    }

    #[track_caller]
    pub fn add_marker(name: impl Into<String>) -> Self {
        let caller = Location::caller();
        let name = name.into();
        Self::custom(move |_, position, markers| {
            let marker = Marker {
                at: position,
                created: caller,
            };
            let old = markers.insert(name.clone(), marker);
            assert!(old.is_none(), "marker {name:?} already exists")
        })
    }

    #[track_caller]
    pub fn assert_marker_offset(name: impl Into<String>, offset: isize, comment: impl Into<String>) -> Self {
        let caller = Location::caller();
        let name = name.into();
        let comment = comment.into();
        Self::custom(move |tape, position, markers| {
            let marker = markers.get(&name).expect("marker does not exist");
            let base = marker.at;
            let expected = if offset >= 0 {
                base + offset as usize
            } else {
                base - offset.unsigned_abs()
            };
            if position != expected {
                println!("mismatched marker, offset {offset}");
                println!("[{}] placed marker {name:?} at {}", marker.created, marker.at);
                println!("expected: {expected}");
                println!("found   : {position}");
                println!("source  : {comment}");
                println!("[{caller}] misplaced");
                println!("{tape}");
                std::process::exit(1);
            }
        })
    }

    #[track_caller]
    pub fn remove_marker(name: impl Into<String>) -> Self {
        let name = name.into();
        Self::custom(move |_, _, markers| {
            markers.remove(&name).expect("marker does not exist");
        })
    }

    #[track_caller]
    pub fn halt() -> Item {
        let caller = Location::caller();
        Item::custom(move |tape, _, _| {
            println!("[{caller}] - explicit halt");
            println!("{tape}");
            std::process::exit(1)
        })
    }

    #[track_caller]
    pub fn assert_position(cell: usize, message: impl Into<String>) -> Item {
        let caller = Location::caller();
        let message = message.into();
        Item::custom(move |tape, pointer, _| {
            if pointer != cell {
                println!("[{caller}] - mismatched positions");
                println!("expected: {cell}");
                println!("actual  : {pointer}");
                println!("source  : {message}");
                println!("{tape}");
                std::process::exit(1)
            }
        })
    }
}

#[derive(Debug, Clone)]
pub struct Loop {
    body: Vec<Item>,
    change_indent: bool,
}

impl Loop {
    pub fn new(body: Vec<Item>) -> Self {
        Self { body, change_indent: false }
    }

    pub fn indent(mut self) -> Self {
        self.change_indent = true;
        self
    }
}

impl From<Loop> for Item {
    fn from(value: Loop) -> Self {
        Self::Loop(value)
    }
}

impl From<Instruction> for Item {
    fn from(value: Instruction) -> Self {
        Self::Direct(value)
    }
}

impl From<Vec<Self>> for Item {
    fn from(value: Vec<Self>) -> Self {
        Self::Sequence(value)
    }
}

pub fn drain(offsets: &[isize], add: bool) -> Item {
    let mut insns = vec![Instruction::Dec.into()];
    let mut delta = 0;
    for &offset in offsets {
        let dir = if offset >= 0 { Instruction::Right } else { Instruction::Left };
        insns.push(Item::Repeat {
            item: Box::new(dir.into()),
            n: offset.unsigned_abs(),
        });
        insns.push(if add { Instruction::Inc } else { Instruction::Dec }.into());
        delta += offset;
    }
    let dir = if delta >= 0 { Instruction::Left } else { Instruction::Right };
    insns.push(Item::Repeat {
        item: Box::new(dir.into()),
        n: delta.unsigned_abs(),
    });

    Loop::new(insns).into()
}

#[derive(Debug, Clone)]
pub enum InterpreterAction {
    Instruction(Instruction),
    Comment(String, u8),
    EndComment,
    Indent(bool),
    Custom(#[allow(private_interfaces)] Box<dyn CustomAction>),
}

pub(crate) trait CustomAction {
    fn act(&self, tape: super::Tape<'_>, position: usize, markers: &mut HashMap<String, Marker>);

    fn clone_box(&self) -> Box<dyn CustomAction>;
}

impl<T: for<'a> Fn(super::Tape<'a>, usize, &mut HashMap<String, Marker>) + Clone + 'static> CustomAction for T {
    fn act(&self, tape: super::Tape<'_>, position: usize, markers: &mut HashMap<String, Marker>) {
        self(tape, position, markers)
    }

    fn clone_box(&self) -> Box<dyn CustomAction> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn CustomAction> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

impl Debug for Box<dyn CustomAction> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("dyn CustomAction").finish_non_exhaustive()
    }
}

impl InterpreterAction {
    pub(crate) fn as_instruction(&self) -> Option<Instruction> {
        if let Self::Instruction(i) = self {
            Some(*i)
        } else {
            None
        }
    }
}

pub trait Buildable {
    fn build(self) -> Vec<InterpreterAction>;
}

impl Buildable for Instruction {
    fn build(self) -> Vec<InterpreterAction> {
        vec![InterpreterAction::Instruction(self)]
    }
}

impl Buildable for Item {
    fn build(self) -> Vec<InterpreterAction> {
        match self {
            Self::Sequence(s) => s.build(),
            Self::Direct(i) => i.build(),
            Self::Loop(Loop { body: inner, change_indent }) => iter_once_if(InterpreterAction::Indent(true), change_indent)
                .chain(
                    std::iter::once(Instruction::Start.into())
                        .chain(inner)
                        .chain(std::iter::once(Instruction::End.into()))
                        .flat_map(Buildable::build),
                )
                .chain(iter_once_if(InterpreterAction::Indent(false), change_indent))
                .collect(),
            Self::Repeat { item, n } => {
                let item = item.build();
                std::iter::repeat(item).take(n).flatten().collect()
            }
            Self::Comment(comment, level) => vec![InterpreterAction::Comment(comment, level)],
            Self::EndComment => vec![InterpreterAction::EndComment],
            Self::Custom(custom) => vec![InterpreterAction::Custom(custom)],
        }
    }
}

fn iter_once_if<T>(item: T, condition: bool) -> impl Iterator<Item = T> {
    std::iter::once(item).filter(move |_| condition)
}

impl<T: Buildable> Buildable for Vec<T> {
    fn build(self) -> Vec<InterpreterAction> {
        self.into_iter().flat_map(Buildable::build).collect()
    }
}

pub fn offset_to_insns(offset: isize) -> Item {
    if offset >= 0 {
        Item::repeat(Instruction::Right.into(), offset.unsigned_abs())
    } else {
        Item::repeat(Instruction::Left.into(), offset.unsigned_abs())
    }
}

pub fn offset_from(start: usize, target: usize) -> isize {
    if target >= start {
        (target - start) as isize
    } else {
        -((start - target) as isize)
    }
}

pub fn zero_cell() -> Item {
    Loop::new(vec![Instruction::Dec.into()]).into()
}

pub fn zero_cell_up() -> Item {
    Loop::new(vec![Instruction::Inc.into()]).into()
}
