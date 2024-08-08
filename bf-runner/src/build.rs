use crate::Instruction;

pub mod num;

#[derive(Debug, Clone)]
pub enum Item {
    Sequence(Vec<Self>),
    Direct(Instruction),
    AssertPosition(usize, &'static str),
    Loop(Loop),
    Repeat { item: Box<Self>, n: usize },
    Comment(String, u8),
    PrintTape,
    AddMarker(String),
    RemoveMarker(String),
    AssertRelativePosition(String, isize, &'static str),
}

impl Item {
    pub fn repeat(self, n: usize) -> Self {
        Self::Repeat { item: Box::new(self), n }
    }

    pub fn comment(self, comment: impl Into<String>, level: u8) -> Self {
        Self::Sequence(vec![Self::Comment(comment.into(), level), self])
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum InterpreterAction {
    Instruction(Instruction),
    AssertPosition(usize, &'static str),
    Comment(String, u8),
    Indent(bool),
    PrintTape,
    PlaceMarker(String),
    RemoveMarker(String),
    AssertRelative(String, isize, &'static str),
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
            Self::AssertPosition(desired, why) => {
                vec![InterpreterAction::AssertPosition(desired, why)]
            }
            Self::Comment(comment, level) => vec![InterpreterAction::Comment(comment, level)],
            Self::PrintTape => vec![InterpreterAction::PrintTape],
            Self::AddMarker(name) => vec![InterpreterAction::PlaceMarker(name)],
            Self::RemoveMarker(name) => vec![InterpreterAction::RemoveMarker(name)],
            Self::AssertRelativePosition(name, offset, comment) => vec![InterpreterAction::AssertRelative(name, offset, comment)],
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
