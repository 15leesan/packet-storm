use crate::{
    build::{offset_to_insns, zero_cell, Item, Loop},
    Instruction,
};

pub trait NumericOperation {
    const NAME: &'static str;
    const ZERO_CHECK_FIRST: bool;
    const WIDTH: usize;

    fn operation() -> Item;
    fn zero_reset() -> Item;
}

fn operate_level<N: NumericOperation>(space: usize, scratch_offset: isize) -> Item {
    let marker_name = format!("operation {} level {}", N::NAME, N::WIDTH - space);

    let prep = Item::Sequence(vec![
        // Setup scratch cell
        offset_to_insns(scratch_offset),
        zero_cell(),
        Instruction::Inc.into(),
        offset_to_insns(-scratch_offset),
    ]);
    let zero_check = Item::Sequence(vec![
        // If target cell is nonzero
        Loop::new(vec![
            offset_to_insns(scratch_offset),
            Instruction::Dec.into(),
            offset_to_insns(-scratch_offset),
            Instruction::Right.into(),
        ])
        .indent()
        .into(),
        offset_to_insns(scratch_offset),
        // Else (i.e. target cell is zero)
        Loop::new({
            if space != 0 {
                vec![
                    offset_to_insns(-scratch_offset),
                    Instruction::Left.into(),
                    Item::AssertRelativePosition(marker_name.clone(), -1, "before recursion"),
                    operate_level::<N>(space - 1, scratch_offset + 1),
                    Item::AssertRelativePosition(marker_name.clone(), -1, "after recursion"),
                    Instruction::Right.into(),
                    N::zero_reset(),
                    Instruction::Right.into(),
                    offset_to_insns(scratch_offset),
                ]
            } else {
                vec![Item::AssertPosition(usize::MAX, "arithmetic overflow")]
            }
        })
        .indent()
        .into(),
        offset_to_insns(-scratch_offset - 1),
    ]);

    let comment = Item::Comment(format!("{} {{depth={}/{}}}", N::NAME, N::WIDTH - space, N::WIDTH), 10);

    let v = if N::ZERO_CHECK_FIRST {
        vec![
            comment,
            Item::AddMarker(marker_name.clone()),
            prep,
            Item::AssertRelativePosition(marker_name.clone(), 0, "after prep"),
            zero_check,
            Item::AssertRelativePosition(marker_name.clone(), 0, "after zero check"),
            N::operation(),
            Item::AssertRelativePosition(marker_name.clone(), 0, "after operation"),
            Item::AssertRelativePosition(marker_name.clone(), 0, "after level"),
            Item::RemoveMarker(marker_name),
        ]
    } else {
        vec![
            comment,
            Item::AddMarker(marker_name.clone()),
            prep,
            Item::AssertRelativePosition(marker_name.clone(), 0, "after prep"),
            N::operation(),
            Item::AssertRelativePosition(marker_name.clone(), 0, "after operation"),
            zero_check,
            Item::AssertRelativePosition(marker_name.clone(), 0, "after zero check"),
            Item::AssertRelativePosition(marker_name.clone(), 0, "after level"),
            Item::RemoveMarker(marker_name),
        ]
    };

    Item::Sequence(v)
}

// `tape + scratch_offset` must be two scratch cells
pub fn operate<N: NumericOperation>(scratch_offset: isize) -> Item {
    let marker_name = format!("operation {}", N::NAME);
    Item::Sequence(vec![
        Item::AddMarker(marker_name.clone()),
        offset_to_insns(scratch_offset),
        zero_cell(),
        Instruction::Right.into(),
        zero_cell(),
        Instruction::Left.into(),
        offset_to_insns(-scratch_offset),
        operate_level::<N>(N::WIDTH - 1, scratch_offset),
        Item::AssertRelativePosition(marker_name.clone(), 0, "after total operation"),
        Item::RemoveMarker(marker_name),
    ])
}

pub struct ByteAdd<const N: usize>;
pub struct ByteSub<const N: usize>;

impl<const N: usize> NumericOperation for ByteAdd<N> {
    const NAME: &'static str = "add";
    const ZERO_CHECK_FIRST: bool = false;
    const WIDTH: usize = N;

    fn operation() -> Item {
        Instruction::Inc.into()
    }

    fn zero_reset() -> Item {
        Item::Sequence(vec![])
    }
}

impl<const N: usize> NumericOperation for ByteSub<N> {
    const NAME: &'static str = "sub";
    const ZERO_CHECK_FIRST: bool = true;
    const WIDTH: usize = N;

    fn operation() -> Item {
        Instruction::Dec.into()
    }

    fn zero_reset() -> Item {
        Item::Sequence(vec![])
    }
}

pub struct DecimalAdd<const N: usize>;

impl<const N: usize> NumericOperation for DecimalAdd<N> {
    const NAME: &'static str = "decimal add";
    const ZERO_CHECK_FIRST: bool = false;
    const WIDTH: usize = N;

    fn operation() -> Item {
        Instruction::Inc.into()
    }

    fn zero_reset() -> Item {
        Item::Sequence(vec![Instruction::Dec.into(); 10])
    }
}

pub struct DecimalSub<const N: usize>;

impl<const N: usize> NumericOperation for DecimalSub<N> {
    const NAME: &'static str = "decimal sub";
    const ZERO_CHECK_FIRST: bool = true;
    const WIDTH: usize = N;

    fn operation() -> Item {
        Instruction::Dec.into()
    }

    fn zero_reset() -> Item {
        Item::Sequence(vec![Instruction::Inc.into(); 10])
    }
}
