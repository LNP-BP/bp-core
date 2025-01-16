// Bitcoin protocol single-use-seals library.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::str::FromStr;

use amplify::hex;
use bc::{Outpoint, Txid, Vout};
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};

/// Method for closing single-use-seals.
pub type CloseMethod = dbc::Method;

/// Methods common for all transaction-output based seal types.
pub trait TxoSeal {
    /// Returns [`Txid`] part of the seal definition, if known.
    fn txid(&self) -> Option<Txid>;

    /// Returns transaction output number containing the defined seal.
    fn vout(&self) -> Vout;

    /// Returns [`Outpoint`] defining the seal, if txid is known.
    fn outpoint(&self) -> Option<Outpoint>;

    /// Returns [`Txid`] part of the seal definition, if known, or the provided
    /// `default_txid`.
    fn txid_or(&self, default_txid: Txid) -> Txid;

    /// Returns [`Outpoint`] defining the seal, if txid is known, or constructs
    /// one using the provided `default_txid`.
    fn outpoint_or(&self, default_txid: Txid) -> Outpoint;
}

/// Marker trait for variants of seal transaction id.
pub trait SealTxid:
    Copy
    + Eq
    + Ord
    + Hash
    + Debug
    + Display
    + FromStr<Err = hex::Error>
    + StrictDumb
    + StrictEncode
    + StrictDecode
    + From<Txid>
{
    /// Returns transaction id, if known.
    fn txid(&self) -> Option<Txid>;
    /// Returns transaction id, if known, or some default value otherwise.
    fn txid_or(&self, default: Txid) -> Txid;
    /// Converts to outpoint, if the transaction id is known.
    fn map_to_outpoint(&self, vout: impl Into<Vout>) -> Option<Outpoint>;
}

impl SealTxid for Txid {
    fn txid(&self) -> Option<Txid> { Some(*self) }
    fn txid_or(&self, _default: Txid) -> Txid { *self }
    fn map_to_outpoint(&self, vout: impl Into<Vout>) -> Option<Outpoint> {
        Some(Outpoint::new(*self, vout.into()))
    }
}

/// Transaction pointer which can be used to construct graph of seals.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Default, Debug, Display, From)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = dbc::LIB_NAME_BPCORE, tags = custom)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase", untagged)
)]
pub enum TxPtr {
    /// Points to the witness transaction of some other closed seal.
    #[default]
    #[display("~")]
    #[strict_type(tag = 0x0)]
    WitnessTx,

    /// Points to a transaction by the transaction id.
    #[from]
    #[display(inner)]
    #[strict_type(tag = 0x1)]
    Txid(Txid),
}

impl From<&Txid> for TxPtr {
    #[inline]
    fn from(txid: &Txid) -> Self { TxPtr::Txid(*txid) }
}

impl From<[u8; 32]> for TxPtr {
    #[inline]
    fn from(txid: [u8; 32]) -> Self { TxPtr::Txid(txid.into()) }
}

impl SealTxid for TxPtr {
    fn txid(&self) -> Option<Txid> {
        match self {
            TxPtr::WitnessTx => None,
            TxPtr::Txid(txid) => Some(*txid),
        }
    }

    fn txid_or(&self, default: Txid) -> Txid {
        match self {
            TxPtr::WitnessTx => default,
            TxPtr::Txid(txid) => *txid,
        }
    }

    fn map_to_outpoint(&self, vout: impl Into<Vout>) -> Option<Outpoint> {
        self.txid().map(|txid| Outpoint::new(txid, vout))
    }
}

impl FromStr for TxPtr {
    type Err = hex::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "~" => Ok(TxPtr::WitnessTx),
            other => Txid::from_str(other).map(Self::from),
        }
    }
}
