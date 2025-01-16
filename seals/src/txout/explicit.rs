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

//! TxOut single-use-seals.

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use amplify::hex;
use bc::{Outpoint, Txid, Vout};

use crate::txout::seal::{SealTxid, TxPtr};
use crate::txout::{TxoSeal, WitnessVoutError};

/// Revealed seal definition which may point to a witness transactions and does
/// not contain blinding data.
///
/// These data are not used within RGB contract data, thus we do not have a
/// commitment and conceal procedures (since without knowing a blinding factor
/// we can't perform them).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = dbc::LIB_NAME_BPCORE)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct ExplicitSeal<Id: SealTxid> {
    /// Txid of the seal definition.
    ///
    /// It may be missed in situations when ID of a transaction is not known,
    /// but the transaction still can be identified by some other means (for
    /// instance it is a transaction spending specific outpoint, like other
    /// seal definition).
    pub txid: Id,

    /// Tx output number, which should be always known.
    pub vout: Vout,
}

impl TryFrom<&ExplicitSeal<TxPtr>> for Outpoint {
    type Error = WitnessVoutError;

    #[inline]
    fn try_from(reveal: &ExplicitSeal<TxPtr>) -> Result<Self, Self::Error> {
        reveal.txid.map_to_outpoint(reveal.vout).ok_or(WitnessVoutError)
    }
}

impl TryFrom<ExplicitSeal<TxPtr>> for Outpoint {
    type Error = WitnessVoutError;

    #[inline]
    fn try_from(reveal: ExplicitSeal<TxPtr>) -> Result<Self, Self::Error> {
        Outpoint::try_from(&reveal)
    }
}

impl From<&ExplicitSeal<Txid>> for Outpoint {
    fn from(seal: &ExplicitSeal<Txid>) -> Self { Outpoint::new(seal.txid, seal.vout) }
}

impl From<ExplicitSeal<Txid>> for Outpoint {
    fn from(seal: ExplicitSeal<Txid>) -> Self { Outpoint::from(&seal) }
}

impl<Id: SealTxid> TxoSeal for ExplicitSeal<Id> {
    #[inline]
    fn txid(&self) -> Option<Txid> { self.txid.txid() }

    #[inline]
    fn vout(&self) -> Vout { self.vout }

    #[inline]
    fn outpoint(&self) -> Option<Outpoint> { self.txid.map_to_outpoint(self.vout) }

    #[inline]
    fn txid_or(&self, default_txid: Txid) -> Txid { self.txid.txid_or(default_txid) }

    #[inline]
    fn outpoint_or(&self, default_txid: Txid) -> Outpoint {
        Outpoint::new(self.txid.txid_or(default_txid), self.vout)
    }
}

impl<Id: SealTxid> ExplicitSeal<Id> {
    /// Constructs seal for the provided outpoint and seal closing method.
    #[inline]
    pub fn new(outpoint: Outpoint) -> ExplicitSeal<Id> {
        Self {
            txid: Id::from(outpoint.txid),
            vout: outpoint.vout,
        }
    }

    /// Constructs seal.
    #[inline]
    pub fn with(txid: Id, vout: impl Into<Vout>) -> ExplicitSeal<Id> {
        ExplicitSeal {
            txid,
            vout: vout.into(),
        }
    }
}

impl ExplicitSeal<Txid> {
    /// Converts seal into a transaction outpoint.
    #[inline]
    pub fn to_outpoint(&self) -> Outpoint { Outpoint::new(self.txid, self.vout) }
}

/// Errors happening during parsing string representation of different forms of
/// single-use-seals
#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ParseError {
    /// full transaction id is required for the seal specification
    TxidRequired,

    /// unable to parse transaction id value; it must be 64-character
    /// hexadecimal string, however {0}
    WrongTxid(hex::Error),

    /// unable to parse transaction vout value; it must be a decimal unsigned
    /// integer
    WrongVout,

    /// wrong structure of seal string representation
    WrongStructure,
}

impl<Id: SealTxid> FromStr for ExplicitSeal<Id> {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split(&[':', '#'][..]);
        match (split.next(), split.next(), split.next()) {
            (Some(""), ..) => Err(ParseError::TxidRequired),
            (Some(txid), Some(vout), None) => Ok(ExplicitSeal {
                txid: Id::from_str(txid).map_err(ParseError::WrongTxid)?,
                vout: vout.parse().map_err(|_| ParseError::WrongVout)?,
            }),
            _ => Err(ParseError::WrongStructure),
        }
    }
}

impl<Id: SealTxid> Display for ExplicitSeal<Id> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.txid, self.vout,)
    }
}
