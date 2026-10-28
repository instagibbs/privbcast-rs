//! The release seed material of each chain (A1, R1): the DNS seed names, the default port, and the
//! network magic BIP324 binds the session keys to. Copied from Bitcoin Core's chainparams.

pub struct Chain {
    /// As the report names it.
    pub name: &'static str,
    pub dns_seeds: &'static [&'static str],
    pub default_port: u16,
    pub magic: [u8; 4],
}

pub const MAIN: Chain = Chain {
    name: "main",
    dns_seeds: &[
        "dnsseed.bluematt.me.",
        "seed.bitcoin.jonasschnelli.ch.",
        "seed.btc.petertodd.net.",
        "seed.bitcoin.sprovoost.nl.",
        "dnsseed.emzy.de.",
        "seed.bitcoin.wiz.biz.",
        "seed.mainnet.achownodes.xyz.",
    ],
    default_port: 8333,
    magic: [0xf9, 0xbe, 0xb4, 0xd9],
};

pub const TESTNET3: Chain = Chain {
    name: "test",
    dns_seeds: &[
        "testnet-seed.bitcoin.jonasschnelli.ch.",
        "seed.tbtc.petertodd.net.",
        "testnet-seed.bluematt.me.",
        "seed.testnet.achownodes.xyz.",
    ],
    default_port: 18333,
    magic: [0x0b, 0x11, 0x09, 0x07],
};

pub const TESTNET4: Chain = Chain {
    name: "testnet4",
    dns_seeds: &["seed.testnet4.bitcoin.sprovoost.nl.", "seed.testnet4.wiz.biz."],
    default_port: 48333,
    magic: [0x1c, 0x16, 0x3f, 0x28],
};

/// The default signet only: a custom signet has no seeds (U1).
pub const SIGNET: Chain = Chain {
    name: "signet",
    dns_seeds: &["seed.signet.bitcoin.sprovoost.nl.", "seed.signet.achownodes.xyz."],
    default_port: 38333,
    magic: [0x0a, 0x03, 0xcf, 0x40],
};

/// Its seed list is a placeholder: a regtest job needs seeds given on the command line (U1).
pub const REGTEST: Chain =
    Chain { name: "regtest", dns_seeds: &["dummySeed.invalid."], default_port: 18444, magic: [0xfa, 0xbf, 0xb5, 0xda] };

pub fn by_name(name: &str) -> Option<&'static Chain> {
    match name {
        "main" => Some(&MAIN),
        "test" => Some(&TESTNET3),
        "testnet4" => Some(&TESTNET4),
        "signet" => Some(&SIGNET),
        "regtest" => Some(&REGTEST),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::MIN_DNS_SEEDS;

    #[test]
    fn mainnet_floor() {
        // R3: the mainnet release lists at least MIN_DNS_SEEDS seeds.
        assert!(MAIN.dns_seeds.len() >= MIN_DNS_SEEDS);
    }
}
