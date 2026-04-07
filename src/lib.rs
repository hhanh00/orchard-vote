//! Privacy-preserving vote protocol built on Orchard.

extern crate std;

mod ballot;
mod builder;
mod circuit;
mod encryption;
mod errors;
mod frontier;
mod interval;
mod logical;
mod path;
mod proof;
mod util;
mod validate;

pub use ballot::{Ballot, BallotData, BallotAnchors, BallotWitnesses};
pub use circuit::Circuit;
pub use errors::VoteError;
pub use frontier::{Frontier, OrchardHash};
pub use path::{calculate_merkle_paths, MerklePathGeneric, SinsemillaHasher};
pub use proof::{ProvingKey, VerifyingKey};
pub use util::calculate_domain;
pub use validate::{try_decrypt_ballot, validate_ballot};
pub use builder::{
    compute_nf_exclusion, encrypt_ballot_action, dummy_vote,
    vote, vote_with_nf_exclusion,
    NfExclusion, NfExclusionInfo,
    CmxInclusion, CmxInclusionInfo,
};

type Hash = [u8; 32];
pub const NF_DEPTH: usize = 29;
pub const CMX_DEPTH: usize = 32;
