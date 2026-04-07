use halo2_gadgets::poseidon::primitives::{self as poseidon, ConstantLength, Hash as PoseidonHash};
use incrementalmerkletree::Hashable as _;
use pasta_curves::Fp;

use orchard::{
    NOTE_COMMITMENT_TREE_DEPTH as MERKLE_DEPTH_ORCHARD,
    note::ExtractedNoteCommitment,
    tree::MerkleHashOrchard,
};

use crate::{NF_DEPTH, CMX_DEPTH};

pub type MerklePath = MerklePathGeneric<NF_DEPTH>;

///
#[derive(Clone, Debug)]
pub struct MerklePathGeneric<const D: usize> {
    pub(crate) value: Fp,
    pub(crate) position: u32,
    pub(crate) path: [Fp; D],
    p: usize,
}

impl<const D: usize> Default for MerklePathGeneric<D> {
    fn default() -> Self {
        MerklePathGeneric {
            value: Fp::default(),
            position: 0,
            path: [Fp::default(); D],
            p: 0,
        }
    }
}

impl<const D: usize> MerklePathGeneric<D> {
    ///
    pub fn from_parts(value: Fp, position: u32, path: [Fp; D]) -> Self {
        Self {
            value,
            position,
            path,
            p: 0,
        }
    }

    ///
    pub fn auth_path(&self) -> [Fp; D] {
        self.path
    }

    ///
    pub fn position(&self) -> u32 {
        self.position
    }

    ///
    pub fn leaf(&self) -> Fp {
        self.value
    }
}

///
pub fn nf_leaf_hash(start: Fp, width: Fp) -> Fp {
    PoseidonHash::<_, poseidon::P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([start, width])
}

/// Poseidon hash of two tree nodes.
pub fn poseidon_hash(left: Fp, right: Fp) -> Fp {
    PoseidonHash::<_, poseidon::P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([left, right])
}

pub trait FpHasher {
    fn combine(&self, depth: u8, l: Fp, r: Fp) -> Fp;
}

/// Calculate Merkle paths for a batch of leaves.
///
/// `position_offset` is the absolute position of `hashes[0]`.
/// `positions` are the absolute positions of the leaves whose paths to compute.
/// `hashes` covers the contiguous range `[position_offset, position_offset + hashes.len())`.
pub fn calculate_merkle_paths<H: FpHasher, const D: usize>(
    position_offset: usize,
    positions: &[u32],
    hashes: &[Fp],
    hasher: &H,
) -> (Fp, Vec<MerklePathGeneric<D>>) {
    let mut paths = positions
        .iter()
        .map(|p| {
            let rel_p = *p as usize - position_offset;
            MerklePathGeneric {
                value: hashes[rel_p],
                position: rel_p as u32,
                path: [Fp::default(); D],
                p: rel_p,
            }
        })
        .collect::<Vec<_>>();
    let mut er = Fp::from(2);
    let mut layer = Vec::with_capacity(positions.len() + 2);
    for i in 0..D {
        if i == 0 {
            layer.extend(hashes);
            if layer.is_empty() {
                layer.push(er);
            }
            if layer.len() & 1 == 1 {
                layer.push(er);
            }
        }

        for path in paths.iter_mut() {
            let idx = path.p;
            if idx & 1 == 1 {
                path.path[i] = layer[idx as usize - 1];
            } else {
                path.path[i] = layer[idx as usize + 1];
            }
            path.p /= 2;
        }

        let pairs = layer.len() / 2;
        let mut next_layer = Vec::with_capacity(pairs + 2);

        for j in 0..pairs {
            let h = hasher.combine(i as u8, layer[j * 2], layer[j * 2 + 1]);
            next_layer.push(h);
        }

        er = hasher.combine(i as u8, er, er);
        if next_layer.len() & 1 == 1 {
            next_layer.push(er);
        }

        std::mem::swap(&mut layer, &mut next_layer);
    }

    let root = layer[0];
    (root, paths)
}

#[derive(Default, Debug)]
///
pub struct SinsemillaHasher {}

impl FpHasher for SinsemillaHasher {
    fn combine(&self, depth: u8, l: Fp, r: Fp) -> Fp {
        cmx_hash(depth, l, r)
    }
}

#[derive(Default)]
struct PoseidonHasher {}

impl FpHasher for PoseidonHasher {
    fn combine(&self, _depth: u8, l: Fp, r: Fp) -> Fp {
        poseidon_hash(l, r)
    }
}

pub fn calculate_nf_merkle_paths(
    position_offset: usize,
    positions: &[u32],
    nf_leaves: &[Fp],
) -> (Fp, Vec<MerklePathGeneric<NF_DEPTH>>) {
    let hasher = PoseidonHasher::default();
    calculate_merkle_paths(position_offset, positions, nf_leaves, &hasher)
}

/// Calculate a full Orchard CMX merkle tree over 32 levels.
pub fn calculate_cmx_merkle_paths(
    position_offset: usize,
    positions: &[u32],
    cmxs: &[Fp],
) -> (Fp, Vec<MerklePathGeneric<CMX_DEPTH>>) {
    let hasher = SinsemillaHasher::default();
    calculate_merkle_paths(position_offset, positions, cmxs, &hasher)
}

pub fn cmx_hash(level: u8, left: Fp, right: Fp) -> Fp {
    let left = MerkleHashOrchard::from_base(left);
    let right = MerkleHashOrchard::from_base(right);
    let h = MerkleHashOrchard::combine(incrementalmerkletree::Level::from(level), &left, &right);
    h.inner()
}
