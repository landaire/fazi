use std::collections::BTreeSet;

/// One operand of a comparison observed while running an input.
///
/// Equality and ordering only consider the wrapped value, not whether it is
/// constant or dynamic.
#[derive(Debug, Clone, Copy)]
pub enum CmpOperand<T: Clone> {
    /// Represents a constant value in a comparison operation. e.g. if the x86
    /// assembly is `cmp rax, 10`, we'd want to represent that the right-hand
    /// side of this instruction was a constant value of 10.
    Constant(T),
    /// Represents a dynamic value in a comparison operation. e.g. if the x86
    /// assembly is `cmp rax, 10`, where `rax` is 5, we'd want to represent that
    /// the left-hand side of this instruction is a dynamic value of 5.
    Dynamic(T),
}

impl<T: Clone> CmpOperand<T> {
    pub fn inner(&self) -> T {
        match self {
            CmpOperand::Constant(val) => val.clone(),
            CmpOperand::Dynamic(val) => val.clone(),
        }
    }

    pub fn inner_ref(&self) -> &T {
        match self {
            CmpOperand::Constant(val) => val,
            CmpOperand::Dynamic(val) => val,
        }
    }

    pub fn is_const(&self) -> bool {
        matches!(self, CmpOperand::Constant(_))
    }

    pub fn is_dynamic(&self) -> bool {
        matches!(self, CmpOperand::Dynamic(_))
    }

    /// Converts the wrapped value, keeping the constant/dynamic kind.
    pub fn map<U: Clone>(self, f: impl FnOnce(T) -> U) -> CmpOperand<U> {
        match self {
            CmpOperand::Constant(val) => CmpOperand::Constant(f(val)),
            CmpOperand::Dynamic(val) => CmpOperand::Dynamic(f(val)),
        }
    }
}

impl<T: Eq + Clone> Eq for CmpOperand<T> {}

impl<T: PartialEq + Clone> PartialEq for CmpOperand<T> {
    fn eq(&self, other: &Self) -> bool {
        self.inner_ref() == other.inner_ref()
    }
}

impl<T: PartialOrd + Clone> PartialOrd for CmpOperand<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.inner_ref().partial_cmp(other.inner_ref())
    }
}

impl<T: Ord + Clone> Ord for CmpOperand<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.inner_ref().cmp(other.inner_ref())
    }
}

/// Comparison operands observed while running the current input. The
/// compare-operand mutator draws replacement values from these tables.
#[derive(Debug, Default)]
pub(crate) struct ComparisonOperandMap {
    pub u8cov: BTreeSet<(CmpOperand<u8>, CmpOperand<u8>)>,
    pub u16cov: BTreeSet<(CmpOperand<u16>, CmpOperand<u16>)>,
    pub u32cov: BTreeSet<(CmpOperand<u32>, CmpOperand<u32>)>,
    pub u64cov: BTreeSet<(CmpOperand<u64>, CmpOperand<u64>)>,
    pub binary: BTreeSet<(Vec<u8>, Vec<u8>)>,
}

impl ComparisonOperandMap {
    pub fn clear(&mut self) {
        self.u8cov.clear();
        self.u16cov.clear();
        self.u32cov.clear();
        self.u64cov.clear();
        self.binary.clear();
    }

    /// Records a comparison of `width` bytes. The pair also lands in every
    /// narrower table both operands fit in, so a 4-byte compare of small values
    /// can steer 1- and 2-byte fields too.
    pub fn insert(&mut self, width: usize, arg1: CmpOperand<u64>, arg2: CmpOperand<u64>) {
        let (a, b) = (arg1.inner(), arg2.inner());
        if a <= u8::MAX as u64 && b <= u8::MAX as u64 {
            self.u8cov.insert((arg1.map(|v| v as u8), arg2.map(|v| v as u8)));
        }
        if width >= 2 && a <= u16::MAX as u64 && b <= u16::MAX as u64 {
            self.u16cov.insert((arg1.map(|v| v as u16), arg2.map(|v| v as u16)));
        }
        if width >= 4 && a <= u32::MAX as u64 && b <= u32::MAX as u64 {
            self.u32cov.insert((arg1.map(|v| v as u32), arg2.map(|v| v as u32)));
        }
        if width >= 8 {
            self.u64cov.insert((arg1, arg2));
        }
    }
}
