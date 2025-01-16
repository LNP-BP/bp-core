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

use std::marker::PhantomData;

use bc::{Tx, Txid};
use commit_verify::mpc;
use single_use_seals::SealWitness;

use crate::txout::{TxoSeal, VerifyError};

/// Witness of a bitcoin-based seal being closed. Includes both transaction and
/// extra-transaction data.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct Witness<D: dbc::Proof> {
    /// Witness transaction: transaction which contains commitment to the
    /// message over which the seal is closed.
    pub tx: Tx,

    /// Transaction id of the witness transaction above.
    pub txid: Txid,

    /// Deterministic bitcoin commitment proof from the anchor.
    pub proof: D,

    #[doc(hidden)]
    pub _phantom: PhantomData<D>,
}

impl<D: dbc::Proof> Witness<D> {
    /// Constructs witness from a witness transaction and extra-transaction
    /// proof, taken from an anchor.
    pub fn with(tx: Tx, dbc: D) -> Witness<D> {
        Witness {
            txid: tx.txid(),
            tx,
            proof: dbc,
            _phantom: default!(),
        }
    }
}

impl<Seal: TxoSeal, Dbc: dbc::Proof> SealWitness<Seal> for Witness<Dbc> {
    type Message = mpc::Commitment;
    type Error = VerifyError<Dbc::Error>;

    fn verify_seal(&self, seal: &Seal, msg: &Self::Message) -> Result<(), Self::Error> {
        // 1. The seal must match tx inputs
        let outpoint = seal.outpoint().ok_or(VerifyError::NoWitnessTxid)?;
        if !self.tx.inputs.iter().any(|txin| txin.prev_output == outpoint) {
            return Err(VerifyError::WitnessNotClosingSeal(outpoint));
        }

        // 2. Verify DBC with the giving closing method
        self.proof.verify(msg, &self.tx).map_err(VerifyError::Dbc)
    }

    fn verify_many_seals<'seal>(
        &self,
        seals: impl IntoIterator<Item = &'seal Seal>,
        msg: &Self::Message,
    ) -> Result<(), Self::Error>
    where
        Seal: 'seal,
    {
        for seal in seals {
            // 1. Each seal must match tx inputs
            let outpoint = seal.outpoint().ok_or(VerifyError::NoWitnessTxid)?;
            if !self.tx.inputs.iter().any(|txin| txin.prev_output == outpoint) {
                return Err(VerifyError::WitnessNotClosingSeal(outpoint));
            }
        }

        // 2. Verify DBC with the giving closing method
        self.proof.verify(msg, &self.tx).map_err(VerifyError::Dbc)
    }
}
