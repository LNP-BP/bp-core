// Bitcoin protocol core library.
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

use std::fs;
use std::io::Write;

use bc::stl::{bp_consensus_stl, bp_tx_stl};
use bp::stl::bp_core_stl;
use commit_verify::stl::commit_verify_stl;
use commit_verify::CommitmentLayout;
use seals::txout::{ChainBlindSeal, SingleBlindSeal};
use strict_encoding::libname;
use strict_types::stl::std_stl;
use strict_types::{parse_args, SystemBuilder};

fn main() {
    let (format, dir) = parse_args();

    let mut lib = bc::stl::bp_tx_stl();
    lib.name = libname!("Tx");
    lib.serialize(
        format,
        dir.as_ref(),
        "0.1.0",
        Some(
            "
  Description: Bitcoin transaction library
  Author: Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
  Copyright (C) 2023-2024 LNP/BP Standards Association. All rights reserved.
  License: Apache-2.0",
        ),
    )
    .expect("unable to write to the file");

    bp_consensus_stl()
        .serialize(
            format,
            dir.as_ref(),
            "0.1.0",
            Some(
                "
  Description: Consensus library for bitcoin protocol
  Author: Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
  Copyright (C) 2023-2024 LNP/BP Standards Association. All rights reserved.
  License: Apache-2.0",
            ),
        )
        .expect("unable to write to the file");

    bp_core_stl()
        .serialize(
            format,
            dir.as_ref(),
            "0.1.0",
            Some(
                "
  Description: Bitcoin client-side-validation library
  Author: Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
  Copyright (C) 2023-2024 LNP/BP Standards Association. All rights reserved.
  License: Apache-2.0",
            ),
        )
        .expect("unable to write to the file");

    let std = std_stl();
    let tx = bp_tx_stl();
    let bp = bp_core_stl();
    let cv = commit_verify_stl();

    let sys = SystemBuilder::new()
        .import(bp)
        .unwrap()
        .import(tx)
        .unwrap()
        .import(cv)
        .unwrap()
        .import(std)
        .unwrap()
        .finalize()
        .expect("not all libraries present");

    let dir = dir.unwrap_or_else(|| ".".to_owned());

    let mut file = fs::File::create(format!("{dir}/Seals.vesper")).unwrap();
    writeln!(
        file,
        "{{-
  Description: Bitcoin TxO2 blind seals
  Author: Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
  Copyright (C) 2024 LNP/BP Standards Association. All rights reserved.
  License: Apache-2.0
-}}

Seals vesper lexicon=types+commitments
"
    )
    .unwrap();
    let layout = SingleBlindSeal::commitment_layout();
    writeln!(file, "{layout}").unwrap();
    let layout = ChainBlindSeal::commitment_layout();
    writeln!(file, "{layout}").unwrap();
    let tt = sys.type_tree("BPCore.BlindSealTxid").unwrap();
    writeln!(file, "{tt}").unwrap();
    let tt = sys.type_tree("BPCore.BlindSealTxPtr").unwrap();
    writeln!(file, "{tt}").unwrap();

    let tt = sys.type_tree("BPCore.AnchorMerkleTreeTapretProof").unwrap();
    fs::write(format!("{dir}/Anchor.MerkleTree.Tapret.vesper"), format!("{tt}")).unwrap();

    let tt = sys.type_tree("BPCore.AnchorMerkleTreeOpretProof").unwrap();
    fs::write(format!("{dir}/Anchor.MerkleTree.Opret.vesper"), format!("{tt}")).unwrap();

    let tt = sys.type_tree("BPCore.AnchorMerkleBlockTapretProof").unwrap();
    fs::write(format!("{dir}/Anchor.MerkleBlock.Tapret.vesper"), format!("{tt}")).unwrap();

    let tt = sys.type_tree("BPCore.AnchorMerkleProofTapretProof").unwrap();
    fs::write(format!("{dir}/Anchor.MerkleProof.Tapret.vesper"), format!("{tt}")).unwrap();
}
