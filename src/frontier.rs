use ff::PrimeField as _;
use pasta_curves::Fp;
use serde::{Deserialize, Serialize};

use orchard::{
    note::ExtractedNoteCommitment,
    tree::{MerkleHashOrchard, MerklePath},
};

use crate::{path::cmx_hash, util::empty_hash};

/// A 32-byte Orchard Merkle hash, serialized as a hex string.
#[derive(Clone, Copy, Serialize, Deserialize, Default, Debug)]
pub struct OrchardHash(#[serde(with = "hex")] pub [u8; 32]);

/// An incremental Merkle frontier over the Orchard note commitment (CMX) tree.
///
/// Tracks the rightmost leaf and the "ommer" (sibling) hashes needed to extend
/// the tree and compute its root without storing all leaves.
#[derive(Clone, Serialize, Deserialize, Default, Debug)]
pub struct Frontier {
    /// 0-based index of the next leaf to be appended (i.e. the current tree size).
    pub position: u32,
    /// The most recently appended leaf hash.
    pub leaf: OrchardHash,
    /// Accumulated sibling hashes at each level, from the bottom up.
    pub ommers: Vec<OrchardHash>,
}

impl Frontier {
    /// Appends a new extracted note commitment to the frontier, updating ommers in place.
    pub fn append(&mut self, cmx: OrchardHash) {
        let mut er = Fp::from_repr(empty_hash()).unwrap();
        let mut c = Fp::from_repr(self.leaf.0).unwrap();
        let mut p = self.position;

        let mut i = 0u8;
        while p > 0 {
            if p % 2 == 0 {
                self.ommers[i as usize] = OrchardHash(c.to_repr());
                break;
            } else {
                c = cmx_hash(i, Fp::from_repr(self.ommers[i as usize].0).unwrap(), c);
                self.ommers[i as usize] = OrchardHash(er.to_repr());
            }
            p /= 2;
            er = cmx_hash(i, er, er);
            i += 1;
        }
        self.leaf = cmx;
        self.position += 1;
    }

    /// Computes the current Merkle root from the frontier state.
    pub fn root(&self) -> [u8; 32] {
        let ommers = self
            .ommers
            .iter()
            .map(|o| MerkleHashOrchard::from_bytes(&o.0).unwrap())
            .collect::<Vec<_>>();
        let mp = MerklePath::from_parts(self.position, ommers.try_into().unwrap());
        let root = mp.root(ExtractedNoteCommitment::from_bytes(&self.leaf.0).unwrap());
        root.to_bytes()
    }
}
