#[cfg(any(
        all(feature = "panda-i386", any(
                feature = "panda-x86_64",
                feature = "panda-arm",
                feature = "panda-aarch64",
                feature = "panda-mips",
                feature = "panda-mipsel",
                feature = "panda-mips64",
                feature = "panda-ppc",
                )),
        all(feature = "panda-x86_64", any(
                feature = "panda-i386",
                feature = "panda-arm",
                feature = "panda-aarch64",
                feature = "panda-mips",
                feature = "panda-mipsel",
                feature = "panda-mips64",
                feature = "panda-ppc",
                )),
        all(feature = "panda-arm", any(
                feature = "panda-i386",
                feature = "panda-x86_64",
                feature = "panda-aarch64",
                feature = "panda-mips",
                feature = "panda-mipsel",
                feature = "panda-mips64",
                feature = "panda-ppc",
                )),
        all(feature = "panda-aarch64", any(
                feature = "panda-i386",
                feature = "panda-x86_64",
                feature = "panda-arm",
                feature = "panda-mips",
                feature = "panda-mipsel",
                feature = "panda-mips64",
                feature = "panda-ppc",
                )),
        all(feature = "panda-mips", any(
                feature = "panda-i386",
                feature = "panda-x86_64",
                feature = "panda-arm",
                feature = "panda-aarch64",
                feature = "panda-mipsel",
                feature = "panda-mips64",
                feature = "panda-ppc",
                )),
        all(feature = "panda-mipsel", any(
                feature = "panda-i386",
                feature = "panda-x86_64",
                feature = "panda-arm",
                feature = "panda-aarch64",
                feature = "panda-mips",
                feature = "panda-mips64",
                feature = "panda-ppc",
                )),
        all(feature = "panda-mips64", any(
                feature = "panda-i386",
                feature = "panda-x86_64",
                feature = "panda-arm",
                feature = "panda-aarch64",
                feature = "panda-mips",
                feature = "panda-mipsel",
                feature = "panda-ppc",
                )),
        all(feature = "panda-ppc", any(
                feature = "panda-i386",
                feature = "panda-x86_64",
                feature = "panda-arm",
                feature = "panda-aarch64",
                feature = "panda-mips",
                feature = "panda-mipsel",
                feature = "panda-mips64",
                )),
        not(any(feature = "panda-i386",
                feature = "panda-x86_64",
                feature = "panda-arm",
                feature = "panda-aarch64",
                feature = "panda-mips",
                feature = "panda-mipsel",
                feature = "panda-mips64",
                feature = "panda-ppc"
                ))
))]
compile_error!("must select exactly one of the following features: i386, x86_64, arm, aarch64, mips, mipsel, mips64, or ppc");

use panda::prelude::CPUState;

pub(crate) trait RegsExt {
    fn update(&mut self, cpu: &CPUState);
    fn register_names() -> &'static [&'static str];
    fn register_sizes() -> &'static [usize];
}

pub struct Regs(Vec<u8>);

impl Regs {
    pub fn new() -> Self {
        let mut data = Vec::new();
        data.resize(Self::register_sizes().into_iter().sum(), 0);
        Self(data)
    }


    pub fn iter<'a>(&'a self) -> impl Iterator<Item=(u16, &'a [u8])> + 'a {
        let mut start = 0usize;
        Self::register_sizes().iter().copied().enumerate().map(move |(i, sz)| {
            let data = &self.inner()[start..start+sz];
            start += sz;
            (i as u16, data)
        })
    }

    pub fn diff<'a>(&'a self, other: &'a Self) -> impl Iterator<Item=(u16, &'a [u8])> + 'a {
        self.iter().zip(other.iter()).filter_map(|(a, b)| {
            if a != b {
                return Some(b);
            }
            None
        })
    }

    #[inline]
    pub(crate) fn inner(&self) -> &Vec<u8> {
        &self.0
    }

    #[inline]
    pub(crate) fn inner_mut(&mut self) -> &mut Vec<u8> {
        &mut self.0
    }
}

#[cfg(feature = "panda-i386")]
mod i386;
#[cfg(feature = "panda-i386")]
pub use i386::*;

#[cfg(feature = "panda-x86_64")]
mod x86_64;
#[cfg(feature = "panda-x86_64")]
pub use x86_64::*;

#[cfg(feature = "panda-arm")]
mod arm;
#[cfg(feature = "panda-arm")]
pub use arm::*;

#[cfg(feature = "panda-aarch64")]
mod aarch64;
#[cfg(feature = "panda-aarch64")]
pub use aarch64::*;

#[cfg(feature = "panda-mips")]
mod mips;
#[cfg(feature = "panda-mips")]
pub use mips::*;

#[cfg(feature = "panda-mipsel")]
mod mipsel;
#[cfg(feature = "panda-mipsel")]
pub use mipsel::*;

#[cfg(feature = "panda-mips64")]
mod mips64;
#[cfg(feature = "panda-mips64")]
pub use mips64::*;

#[cfg(feature = "panda-ppc")]
mod ppc;
#[cfg(feature = "panda-ppc")]
pub use ppc::*;
