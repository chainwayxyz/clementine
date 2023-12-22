use crate::tx::TxInput;
use crate::tx::TxOutput;
use core::ops::{Index, IndexMut};

#[derive(Debug, Clone, Copy)]
pub enum BufferPool {
    Empty([u8; 0]),
    Zero([u8; 1]),
    One([u8; 2]),
    Two([u8; 4]),
    Three([u8; 8]),
    Four([u8; 16]),
    Five([u8; 32]),
    Six([u8; 64]),
    Seven([u8; 128]),
    Eight([u8; 256]),
    // Nine([u8; 512]),
    // Ten([u8; 1024]),
    // Eleven([u8; 2048]),
    // Twelve([u8; 4096]),
}

impl BufferPool {
    pub fn new(size: usize) -> Self {
        match size {
            0 => BufferPool::Empty([0; 0]),
            1 => BufferPool::Zero([0; 1]),
            2 => BufferPool::One([0; 2]),
            3..=4 => BufferPool::Two([0; 4]),
            5..=8 => BufferPool::Three([0; 8]),
            9..=16 => BufferPool::Four([0; 16]),
            17..=32 => BufferPool::Five([0; 32]),
            33..=64 => BufferPool::Six([0; 64]),
            65..=128 => BufferPool::Seven([0; 128]),
            129..=256 => BufferPool::Eight([0; 256]),
            // 257..=512 => BufferPool::Nine([0; 512]),
            // 513..=1024 => BufferPool::Ten([0; 1024]),
            // 1025..=2048 => BufferPool::Eleven([0; 2048]),
            // 2049..=4096 => BufferPool::Twelve([0; 4096]),
            _ => panic!("BufferPool size too large"),
        }
    }
}

impl Index<usize> for BufferPool {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        match self {
            BufferPool::Empty(pool) => &pool[index],
            BufferPool::Zero(pool) => &pool[index],
            BufferPool::One(pool) => &pool[index],
            BufferPool::Two(pool) => &pool[index],
            BufferPool::Three(pool) => &pool[index],
            BufferPool::Four(pool) => &pool[index],
            BufferPool::Five(pool) => &pool[index],
            BufferPool::Six(pool) => &pool[index],
            BufferPool::Seven(pool) => &pool[index],
            BufferPool::Eight(pool) => &pool[index],
            // BufferPool::Nine(pool) => &pool[index],
            // BufferPool::Ten(pool) => &pool[index],
            // BufferPool::Eleven(pool) => &pool[index],
            // BufferPool::Twelve(pool) => &pool[index],
        }
    }
}

impl IndexMut<usize> for BufferPool {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        match self {
            BufferPool::Empty(pool) => &mut pool[index],
            BufferPool::Zero(pool) => &mut pool[index],
            BufferPool::One(pool) => &mut pool[index],
            BufferPool::Two(pool) => &mut pool[index],
            BufferPool::Three(pool) => &mut pool[index],
            BufferPool::Four(pool) => &mut pool[index],
            BufferPool::Five(pool) => &mut pool[index],
            BufferPool::Six(pool) => &mut pool[index],
            BufferPool::Seven(pool) => &mut pool[index],
            BufferPool::Eight(pool) => &mut pool[index],
            // BufferPool::Nine(pool) => &mut pool[index],
            // BufferPool::Ten(pool) => &mut pool[index],
            // BufferPool::Eleven(pool) => &mut pool[index],
            // BufferPool::Twelve(pool) => &mut pool[index],
        }
    }
}

impl Index<core::ops::Range<usize>> for BufferPool {
    type Output = [u8];

    fn index(&self, index: core::ops::Range<usize>) -> &Self::Output {
        match self {
            BufferPool::Empty(pool) => &pool[index],
            BufferPool::Zero(pool) => &pool[index],
            BufferPool::One(pool) => &pool[index],
            BufferPool::Two(pool) => &pool[index],
            BufferPool::Three(pool) => &pool[index],
            BufferPool::Four(pool) => &pool[index],
            BufferPool::Five(pool) => &pool[index],
            BufferPool::Six(pool) => &pool[index],
            BufferPool::Seven(pool) => &pool[index],
            BufferPool::Eight(pool) => &pool[index],
            // BufferPool::Nine(pool) => &pool[index],
            // BufferPool::Ten(pool) => &pool[index],
            // BufferPool::Eleven(pool) => &pool[index],
            // BufferPool::Twelve(pool) => &pool[index],
        }
    }
}

impl IndexMut<core::ops::Range<usize>> for BufferPool {
    fn index_mut(&mut self, index: core::ops::Range<usize>) -> &mut Self::Output {
        match self {
            BufferPool::Empty(pool) => &mut pool[index],
            BufferPool::Zero(pool) => &mut pool[index],
            BufferPool::One(pool) => &mut pool[index],
            BufferPool::Two(pool) => &mut pool[index],
            BufferPool::Three(pool) => &mut pool[index],
            BufferPool::Four(pool) => &mut pool[index],
            BufferPool::Five(pool) => &mut pool[index],
            BufferPool::Six(pool) => &mut pool[index],
            BufferPool::Seven(pool) => &mut pool[index],
            BufferPool::Eight(pool) => &mut pool[index],
            // BufferPool::Nine(pool) => &mut pool[index],
            // BufferPool::Ten(pool) => &mut pool[index],
            // BufferPool::Eleven(pool) => &mut pool[index],
            // BufferPool::Twelve(pool) => &mut pool[index],
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum TxInputPool {
    Empty([TxInput; 0]),
    Zero([TxInput; 1]),
    One([TxInput; 2]),
    Two([TxInput; 4]),
    Three([TxInput; 8]),
    Four([TxInput; 16]),
    Five([TxInput; 32]),
    Six([TxInput; 64]),
    Seven([TxInput; 128]),
    Eight([TxInput; 256]),
    // Nine([TxInput; 512]),
    // Ten([TxInput; 1024]),
}

impl TxInputPool {
    pub fn new(size: usize) -> Self {
        match size {
            0 => TxInputPool::Empty([TxInput::empty(); 0]),
            1 => TxInputPool::Zero([TxInput::empty(); 1]),
            2 => TxInputPool::One([TxInput::empty(); 2]),
            3..=4 => TxInputPool::Two([TxInput::empty(); 4]),
            5..=8 => TxInputPool::Three([TxInput::empty(); 8]),
            9..=16 => TxInputPool::Four([TxInput::empty(); 16]),
            17..=32 => TxInputPool::Five([TxInput::empty(); 32]),
            33..=64 => TxInputPool::Six([TxInput::empty(); 64]),
            65..=128 => TxInputPool::Seven([TxInput::empty(); 128]),
            129..=256 => TxInputPool::Eight([TxInput::empty(); 256]),
            // 257..=512 => TxInputPool::Nine([TxInput::empty(); 512]),
            // 513..=1024 => TxInputPool::Ten([TxInput::empty(); 1024]),
            _ => panic!("TxInputPool size too large"),
        }
    }
}

impl Index<usize> for TxInputPool {
    type Output = TxInput;

    fn index(&self, index: usize) -> &Self::Output {
        match self {
            TxInputPool::Empty(pool) => &pool[index],
            TxInputPool::Zero(pool) => &pool[index],
            TxInputPool::One(pool) => &pool[index],
            TxInputPool::Two(pool) => &pool[index],
            TxInputPool::Three(pool) => &pool[index],
            TxInputPool::Four(pool) => &pool[index],
            TxInputPool::Five(pool) => &pool[index],
            TxInputPool::Six(pool) => &pool[index],
            TxInputPool::Seven(pool) => &pool[index],
            TxInputPool::Eight(pool) => &pool[index],
            // TxInputPool::Nine(pool) => &pool[index],
            // TxInputPool::Ten(pool) => &pool[index],
        }
    }
}
impl IndexMut<usize> for TxInputPool {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        match self {
            TxInputPool::Empty(pool) => &mut pool[index],
            TxInputPool::Zero(pool) => &mut pool[index],
            TxInputPool::One(pool) => &mut pool[index],
            TxInputPool::Two(pool) => &mut pool[index],
            TxInputPool::Three(pool) => &mut pool[index],
            TxInputPool::Four(pool) => &mut pool[index],
            TxInputPool::Five(pool) => &mut pool[index],
            TxInputPool::Six(pool) => &mut pool[index],
            TxInputPool::Seven(pool) => &mut pool[index],
            TxInputPool::Eight(pool) => &mut pool[index],
            // TxInputPool::Nine(pool) => &mut pool[index],
            // TxInputPool::Ten(pool) => &mut pool[index],
        }
    }
}

impl Index<core::ops::Range<usize>> for TxInputPool {
    type Output = [TxInput];

    fn index(&self, index: core::ops::Range<usize>) -> &Self::Output {
        match self {
            TxInputPool::Empty(pool) => &pool[index],
            TxInputPool::Zero(pool) => &pool[index],
            TxInputPool::One(pool) => &pool[index],
            TxInputPool::Two(pool) => &pool[index],
            TxInputPool::Three(pool) => &pool[index],
            TxInputPool::Four(pool) => &pool[index],
            TxInputPool::Five(pool) => &pool[index],
            TxInputPool::Six(pool) => &pool[index],
            TxInputPool::Seven(pool) => &pool[index],
            TxInputPool::Eight(pool) => &pool[index],
            // TxInputPool::Nine(pool) => &pool[index],
            // TxInputPool::Ten(pool) => &pool[index],
        }
    }
}

impl IndexMut<core::ops::Range<usize>> for TxInputPool {
    fn index_mut(&mut self, index: core::ops::Range<usize>) -> &mut Self::Output {
        match self {
            TxInputPool::Empty(pool) => &mut pool[index],
            TxInputPool::Zero(pool) => &mut pool[index],
            TxInputPool::One(pool) => &mut pool[index],
            TxInputPool::Two(pool) => &mut pool[index],
            TxInputPool::Three(pool) => &mut pool[index],
            TxInputPool::Four(pool) => &mut pool[index],
            TxInputPool::Five(pool) => &mut pool[index],
            TxInputPool::Six(pool) => &mut pool[index],
            TxInputPool::Seven(pool) => &mut pool[index],
            TxInputPool::Eight(pool) => &mut pool[index],
            // TxInputPool::Nine(pool) => &mut pool[index],
            // TxInputPool::Ten(pool) => &mut pool[index],
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum TxOutputPool {
    Empty([TxOutput; 0]),
    Zero([TxOutput; 1]),
    One([TxOutput; 2]),
    Two([TxOutput; 4]),
    Three([TxOutput; 8]),
    Four([TxOutput; 16]),
    Five([TxOutput; 32]),
    Six([TxOutput; 64]),
    Seven([TxOutput; 128]),
    Eight([TxOutput; 256]),
    // Nine([TxOutput; 512]),
    // Ten([TxOutput; 1024]),
}

impl TxOutputPool {
    pub fn new(size: usize) -> Self {
        match size {
            0 => TxOutputPool::Empty([TxOutput::empty(); 0]),
            1 => TxOutputPool::Zero([TxOutput::empty(); 1]),
            2 => TxOutputPool::One([TxOutput::empty(); 2]),
            3..=4 => TxOutputPool::Two([TxOutput::empty(); 4]),
            5..=8 => TxOutputPool::Three([TxOutput::empty(); 8]),
            9..=16 => TxOutputPool::Four([TxOutput::empty(); 16]),
            17..=32 => TxOutputPool::Five([TxOutput::empty(); 32]),
            33..=64 => TxOutputPool::Six([TxOutput::empty(); 64]),
            65..=128 => TxOutputPool::Seven([TxOutput::empty(); 128]),
            129..=256 => TxOutputPool::Eight([TxOutput::empty(); 256]),
            // 257..=512 => TxOutputPool::Nine([TxOutput::empty(); 512]),
            // 513..=1024 => TxOutputPool::Ten([TxOutput::empty(); 1024]),
            _ => panic!("TxInputPool size too large"),
        }
    }
}

impl Index<usize> for TxOutputPool {
    type Output = TxOutput;

    fn index(&self, index: usize) -> &Self::Output {
        match self {
            TxOutputPool::Empty(pool) => &pool[index],
            TxOutputPool::Zero(pool) => &pool[index],
            TxOutputPool::One(pool) => &pool[index],
            TxOutputPool::Two(pool) => &pool[index],
            TxOutputPool::Three(pool) => &pool[index],
            TxOutputPool::Four(pool) => &pool[index],
            TxOutputPool::Five(pool) => &pool[index],
            TxOutputPool::Six(pool) => &pool[index],
            TxOutputPool::Seven(pool) => &pool[index],
            TxOutputPool::Eight(pool) => &pool[index],
            // TxOutputPool::Nine(pool) => &pool[index],
            // TxOutputPool::Ten(pool) => &pool[index],
        }
    }
}

impl IndexMut<usize> for TxOutputPool {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        match self {
            TxOutputPool::Empty(pool) => &mut pool[index],
            TxOutputPool::Zero(pool) => &mut pool[index],
            TxOutputPool::One(pool) => &mut pool[index],
            TxOutputPool::Two(pool) => &mut pool[index],
            TxOutputPool::Three(pool) => &mut pool[index],
            TxOutputPool::Four(pool) => &mut pool[index],
            TxOutputPool::Five(pool) => &mut pool[index],
            TxOutputPool::Six(pool) => &mut pool[index],
            TxOutputPool::Seven(pool) => &mut pool[index],
            TxOutputPool::Eight(pool) => &mut pool[index],
            // TxOutputPool::Nine(pool) => &mut pool[index],
            // TxOutputPool::Ten(pool) => &mut pool[index],
        }
    }
}

impl Index<core::ops::Range<usize>> for TxOutputPool {
    type Output = [TxOutput];

    fn index(&self, index: core::ops::Range<usize>) -> &Self::Output {
        match self {
            TxOutputPool::Empty(pool) => &pool[index],
            TxOutputPool::Zero(pool) => &pool[index],
            TxOutputPool::One(pool) => &pool[index],
            TxOutputPool::Two(pool) => &pool[index],
            TxOutputPool::Three(pool) => &pool[index],
            TxOutputPool::Four(pool) => &pool[index],
            TxOutputPool::Five(pool) => &pool[index],
            TxOutputPool::Six(pool) => &pool[index],
            TxOutputPool::Seven(pool) => &pool[index],
            TxOutputPool::Eight(pool) => &pool[index],
            // TxOutputPool::Nine(pool) => &pool[index],
            // TxOutputPool::Ten(pool) => &pool[index],
        }
    }
}

impl IndexMut<core::ops::Range<usize>> for TxOutputPool {
    fn index_mut(&mut self, index: core::ops::Range<usize>) -> &mut Self::Output {
        match self {
            TxOutputPool::Empty(pool) => &mut pool[index],
            TxOutputPool::Zero(pool) => &mut pool[index],
            TxOutputPool::One(pool) => &mut pool[index],
            TxOutputPool::Two(pool) => &mut pool[index],
            TxOutputPool::Three(pool) => &mut pool[index],
            TxOutputPool::Four(pool) => &mut pool[index],
            TxOutputPool::Five(pool) => &mut pool[index],
            TxOutputPool::Six(pool) => &mut pool[index],
            TxOutputPool::Seven(pool) => &mut pool[index],
            TxOutputPool::Eight(pool) => &mut pool[index],
            // TxOutputPool::Nine(pool) => &mut pool[index],
            // TxOutputPool::Ten(pool) => &mut pool[index],
        }
    }
}