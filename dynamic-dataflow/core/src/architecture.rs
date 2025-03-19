#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct X86;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct X86_64;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct X86_64Compat32;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct PPCBE32;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct AARCH64;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ARM32;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct M68K;

#[non_exhaustive]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Architecture {
    X86(X86),
    X86_64(X86_64),
    X86_64Compat32(X86_64Compat32),
    PPCBE32(PPCBE32),
    AARCH64(AARCH64),
    ARM32(ARM32),
    M68K(M68K),
}


impl From<X86> for Architecture {
    fn from(value: X86) -> Self {
        Self::X86(value)
    }
}

impl From<X86_64> for Architecture {
    fn from(value: X86_64) -> Self {
        Self::X86_64(value)
    }
}

impl From<X86_64Compat32> for Architecture {
    fn from(value: X86_64Compat32) -> Self {
        Self::X86_64Compat32(value)
    }
}

impl From<PPCBE32> for Architecture {
    fn from(value: PPCBE32) -> Self {
        Self::PPCBE32(value)
    }
}

impl From<AARCH64> for Architecture {
    fn from(value: AARCH64) -> Self {
        Self::AARCH64(value)
    }
}

impl From<ARM32> for Architecture {
    fn from(value: ARM32) -> Self {
        Self::ARM32(value)
    }
}

impl From<M68K> for Architecture {
    fn from(value: M68K) -> Self {
        Self::M68K(value)
    }
}
