//! `scenario-dump`: every hand-written scenario of `mega-evm2-scenarios` as one line of JSON.
//!
//! The fields are the scenario's own, written without interpretation (quantities as decimal or
//! hex strings, bytes as hex); converting them into the fixture format is the exporter's
//! (`tools/export_scenarios.py`), so the conversion rules live in one reviewable place.

use alloy_primitives::Address;
use mega_evm2_scenarios::{self as sc, Scenario};
use std::fmt::Write as _;

fn hex(b: &[u8]) -> String {
    let mut s = String::from("\"0x");
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s.push('"');
    s
}

fn string(t: &str) -> String {
    let mut s = String::from("\"");
    for c in t.chars() {
        match c {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                let _ = write!(s, "\\u{:04x}", c as u32);
            }
            c => s.push(c),
        }
    }
    s.push('"');
    s
}

fn opt_u64(v: Option<u64>) -> String {
    v.map_or("null".into(), |v| format!("\"{v}\""))
}

fn salt(list: &[(Address, Option<u64>, u64)]) -> String {
    let items: Vec<String> =
        list.iter().map(|(a, k, m)| format!("[{},{},\"{m}\"]", hex(a.as_slice()), opt_u64(*k))).collect();
    format!("[{}]", items.join(","))
}

fn scenario(s: &Scenario) -> String {
    let accounts: Vec<String> = s
        .accounts
        .iter()
        .map(|a| {
            let storage: Vec<String> = a.storage.iter().map(|(k, v)| format!("[\"{k}\",\"{v}\"]")).collect();
            format!(
                "{{\"address\":{},\"code\":{},\"balance\":\"{}\",\"nonce\":\"{}\",\"storage\":[{}]}}",
                hex(a.address.as_slice()),
                hex(&a.code),
                a.balance,
                a.nonce,
                storage.join(",")
            )
        })
        .collect();
    let auths: Vec<String> = s
        .auths
        .iter()
        .map(|a| {
            format!(
                "{{\"chainId\":\"{}\",\"address\":{},\"nonce\":\"{}\",\"authority\":{}}}",
                a.chain_id,
                hex(a.address.as_slice()),
                a.nonce,
                a.authority.map_or("null".into(), |x| hex(x.as_slice()))
            )
        })
        .collect();
    let l = &s.limits;
    let limits = format!(
        "{{\"data\":{},\"kv\":{},\"growth\":{},\"blockEnvCap\":{},\"oracleCap\":{}}}",
        opt_u64(l.data),
        opt_u64(l.kv),
        opt_u64(l.growth),
        opt_u64(l.block_env_cap),
        opt_u64(l.oracle_cap)
    );
    let oracle: Vec<String> = s.oracle.iter().map(|(k, v)| format!("[\"{k}\",\"{v}\"]")).collect();
    let l1 = s.l1_fee.as_ref().map_or("null".into(), |(f, sc, b)| format!("[\"{f}\",\"{sc}\",{}]", hex(b)));
    let rules: Vec<String> = s.rules.iter().map(|r| string(r)).collect();
    let prior: Vec<String> = s.prior.iter().map(|p| string(p.name)).collect();
    format!(
        "{{\"name\":{},\"group\":{},\"accounts\":[{}],\"to\":{},\"value\":\"{}\",\"data\":{},\"gasLimit\":\"{}\",\
         \"limits\":{limits},\"sender\":{},\"create\":{},\"deposit\":{},\"salt\":{},\"saltCapacity\":{},\"l1Fee\":{l1},\
         \"gasPrice\":\"{}\",\"oracle\":[{}],\"auths\":[{}],\"beneficiary\":{},\"txType\":\"{}\",\"chainId\":{},\
         \"nonce\":\"{}\",\"skipNonceCheck\":{},\"skipEip3607\":{},\"prior\":[{}],\"rules\":[{}]}}",
        string(s.name),
        string(s.group),
        accounts.join(","),
        hex(s.to.as_slice()),
        s.value,
        hex(&s.data),
        s.gas_limit,
        hex(s.sender.as_slice()),
        s.create,
        opt_u64(s.deposit),
        salt(&s.salt),
        salt(&s.salt_capacity),
        s.gas_price,
        oracle.join(","),
        auths.join(","),
        hex(s.beneficiary.as_slice()),
        s.tx_type,
        opt_u64(s.chain_id),
        s.nonce,
        s.skip_nonce_check,
        s.skip_eip3607,
        prior.join(","),
        rules.join(",")
    )
}

fn main() {
    let mut out = String::new();
    for s in sc::hand_written() {
        out.push_str(&scenario(&s));
        out.push('\n');
    }
    print!("{out}");
}
