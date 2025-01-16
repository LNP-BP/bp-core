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

use std::error::Error;

use bc::Outpoint;

/// Seal verification errors.
#[derive(Clone, PartialEq, Eq, Debug, Display, From, Error)]
#[display(doc_comments)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum VerifyError<E: Error> {
    /// the provided witness transaction does not closes seal {0}.
    WitnessNotClosingSeal(Outpoint),

    /// seal lacks witness transaction id information.
    NoWitnessTxid,

    /// invalid DBC commitment.
    #[display(inner)]
    Dbc(E),
}

/// Error happening if the seal data holds only witness transaction output
/// number and thus can't be used alone for constructing full bitcoin
/// transaction output data which must include the witness transaction id
/// (unknown to the seal).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Error)]
#[display("witness txid is unknown; unable to reconstruct full outpoint data")]
pub struct WitnessVoutError;
