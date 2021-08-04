use ::core::fmt;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct FlowLabel(pub u64);

const HASH_BASE: u64 = 131;

impl FlowLabel {
    #[inline]
    pub fn new(proto: u8, saddr: u32, daddr: u32, sport: u16, dport: u16) -> Self {
        // TODO(cjr): change this function to a more reasonable one
        let v = (((proto as u64 * HASH_BASE + saddr as u64) * HASH_BASE + daddr as u64) * HASH_BASE
            + sport as u64)
            * HASH_BASE
            + dport as u64;
        FlowLabel(v)
    }
}

impl fmt::Display for FlowLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#018x}", self.0)
    }
}
