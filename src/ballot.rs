use std::io::{Read, Write};
use zcash_note_encryption::ENC_CIPHERTEXT_SIZE;

use orchard::{
    keys::FullViewingKey,
    note::Nullifier,
    primitives::redpallas::{SigningKey, SpendAuth, VerificationKey},
    value::{ValueCommitTrapdoor, ValueCommitment},
    Note,
};
use byteorder::{ReadBytesExt, WriteBytesExt, LE};
use blake2b_simd::Params;
use pasta_curves::{Fp, Fq};
use serde::{Deserialize, Serialize};
use zcash_encoding::{Optional, Vector};

/// Merkle tree roots that anchor a ballot to a specific chain state.
#[derive(Clone, Debug)]
pub struct BallotAnchors {
    /// root of nullifier tree
    pub nf: [u8; 32],
    /// root of note commitment tree
    pub cmx: [u8; 32],
}

impl BallotAnchors {
    /// Deserializes a `BallotAnchors` from the given reader (NF root then CMX root, 64 bytes total).
    pub fn read<R: Read>(mut reader: R) -> std::io::Result<BallotAnchors> {
        let mut nf = [0u8; 32];
        reader.read_exact(&mut nf)?;
        let mut cmx: [u8; 32] = [0u8; 32];
        reader.read_exact(&mut cmx)?;
        Ok(BallotAnchors { nf, cmx })
    }

    /// Serializes this `BallotAnchors` to the given writer (NF root then CMX root).
    pub fn write<W: Write>(&self, mut w: W) -> std::io::Result<()> {
        w.write_all(&self.nf)?;
        w.write_all(&self.cmx)?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct BallotAction {
    pub cv_net: [u8; 32],
    pub rk: [u8; 32],
    pub nf: [u8; 32],
    pub cmx: [u8; 32],
    pub epk: [u8; 32],
    pub enc: [u8; ENC_CIPHERTEXT_SIZE],
}

impl BallotAction {
    pub fn read<R: Read>(mut reader: R) -> std::io::Result<BallotAction> {
        let mut cv_net = [0u8; 32];
        reader.read_exact(&mut cv_net)?;
        let mut rk: [u8; 32] = [0u8; 32];
        reader.read_exact(&mut rk)?;
        let mut nf = [0u8; 32];
        reader.read_exact(&mut nf)?;
        let mut cmx = [0u8; 32];
        reader.read_exact(&mut cmx)?;
        let mut epk = [0u8; 32];
        reader.read_exact(&mut epk)?;
        let mut enc = [0u8; ENC_CIPHERTEXT_SIZE];
        reader.read_exact(&mut enc)?;
        Ok(BallotAction {
            cv_net,
            rk,
            nf,
            cmx,
            epk,
            enc,
        })
    }

    pub fn write<W: Write>(&self, mut w: W) -> std::io::Result<()> {
        w.write_all(&self.cv_net)?;
        w.write_all(&self.rk)?;
        w.write_all(&self.nf)?;
        w.write_all(&self.cmx)?;
        w.write_all(&self.epk)?;
        w.write_all(&self.enc)?;
        Ok(())
    }
}

pub struct BallotActionSecret {
    pub fvk: FullViewingKey,
    pub rcv: ValueCommitTrapdoor,
    pub spend_note: Note,
    pub output_note: Note,
    pub alpha: Fq,
    pub sp_signkey: Option<SigningKey<SpendAuth>>,
    pub nf: Nullifier,
    pub nf_start: Nullifier,
    pub nf_width: Fp,
    pub nf_position: u32,
    pub cmx_position: u32,
    pub cv_net: ValueCommitment,
    pub rk: VerificationKey<SpendAuth>,
}

/// The public data of a ballot: version, election domain, actions, and tree anchors.
#[derive(Clone, Debug)]
pub struct BallotData {
    /// Ballot format version (currently 1).
    pub version: u32,
    /// Election domain tag (hash of the election parameters) used to scope nullifiers.
    pub domain: [u8; 32],
    /// Ordered list of shielded vote actions (at least two, padded with dummies).
    pub actions: Vec<BallotAction>,
    /// Merkle tree roots that all actions are anchored against.
    pub anchors: BallotAnchors,
}

impl BallotData {
    /// Deserializes a `BallotData` from the given reader.
    pub fn read<R: Read>(mut reader: R) -> std::io::Result<BallotData> {
        let version = reader.read_u32::<LE>()?;
        let mut domain = [0u8; 32];
        reader.read_exact(&mut domain)?;
        let actions = Vector::read(&mut reader, |r| BallotAction::read(r))?;
        let anchors = BallotAnchors::read(&mut reader)?;
        Ok(BallotData {
            version,
            domain,
            actions,
            anchors,
        })
    }

    /// Serializes this `BallotData` to the given writer.
    pub fn write<W: Write>(&self, mut w: W) -> std::io::Result<()> {
        w.write_u32::<LE>(self.version)?;
        w.write_all(&self.domain)?;
        Vector::write(&mut w, &self.actions, |w, e| e.write(w))?;
        self.anchors.write(&mut w)?;
        Ok(())
    }

    /// Computes the BLAKE2b sighash over the serialized ballot data.
    ///
    /// This hash is signed by the per-action randomized spend-authorization keys and the
    /// binding key to authorize the ballot.
    pub fn sighash(&self) -> std::io::Result<Vec<u8>> {
        let mut buffer: Vec<u8> = vec![];
        self.write(&mut buffer)?;
        let sighash = Params::new()
            .hash_length(32)
            .personal(b"Zcash_VoteBallot")
            .hash(&buffer)
            .as_bytes()
            .to_vec();
        Ok(sighash)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct VoteProof(pub Vec<u8>);

impl VoteProof {
    pub fn read<R: Read>(mut reader: R) -> std::io::Result<VoteProof> {
        let size = reader.read_u32::<LE>()? as usize;
        let mut proof = vec![0u8; size];
        reader.read_exact(&mut *proof)?;
        Ok(VoteProof(proof))
    }

    pub fn write<W: Write>(&self, mut w: W) -> std::io::Result<()> {
        w.write_u32::<LE>(self.0.len() as u32)?;
        w.write_all(&self.0)
    }
}

#[derive(Clone, Debug)]
pub struct VoteSignature(pub [u8; 64]);

impl VoteSignature {
    pub fn read<R: Read>(mut reader: R) -> std::io::Result<VoteSignature> {
        let mut signature = [0u8; 64];
        reader.read_exact(&mut signature)?;
        Ok(VoteSignature(signature))
    }

    pub fn write<W: Write>(&self, mut w: W) -> std::io::Result<()> {
        w.write_all(&self.0)
    }
}

/// Cryptographic witnesses that authorize a ballot: ZK proofs, spend-auth signatures, and binding signature.
#[derive(Clone, Debug)]
pub struct BallotWitnesses {
    /// ZK Proofs
    pub proofs: Vec<VoteProof>,
    /// Spending authorization signatures
    pub sp_signatures: Option<Vec<VoteSignature>>,
    /// Binding signature (for the total value)
    pub binding_signature: [u8; 64],
}

impl BallotWitnesses {
    /// Deserializes a `BallotWitnesses` from the given reader.
    pub fn read<R: Read>(mut reader: R) -> std::io::Result<BallotWitnesses> {
        let proofs = Vector::read(&mut reader, |r| VoteProof::read(r))?;
        let sp_signatures =
            Optional::read(&mut reader, |r| Vector::read(r, |r| VoteSignature::read(r)))?;
        let mut binding_signature = [0u8; 64];
        reader.read_exact(&mut binding_signature)?;
        Ok(BallotWitnesses {
            proofs,
            sp_signatures,
            binding_signature,
        })
    }

    /// Serializes this `BallotWitnesses` to the given writer.
    pub fn write<W: Write>(&self, mut w: W) -> std::io::Result<()> {
        Vector::write(&mut w, &self.proofs, |w, e| e.write(w))?;
        Optional::write(&mut w, self.sp_signatures.as_ref(), |w, e|
            Vector::write(w, e, |w, e| e.write(w)))?;
        w.write_all(&self.binding_signature)?;
        Ok(())
    }
}

/// A complete privacy-preserving ballot, combining public action data with its authorization witnesses.
#[derive(Clone, Debug)]
pub struct Ballot {
    /// The public ballot data (version, domain, actions, anchors).
    pub data: BallotData,
    /// The cryptographic witnesses (proofs, signatures) authorizing this ballot.
    pub witnesses: BallotWitnesses,
}

impl Ballot {
    /// Deserializes a `Ballot` from the given reader.
    pub fn read<R: Read>(mut reader: R) -> std::io::Result<Ballot> {
        let data = BallotData::read(&mut reader)?;
        let witnesses = BallotWitnesses::read(&mut reader)?;
        Ok(Ballot { data, witnesses })
    }

    /// Serializes this `Ballot` to the given writer.
    pub fn write<W: Write>(&self, mut w: W) -> std::io::Result<()> {
        self.data.write(&mut w)?;
        self.witnesses.write(&mut w)?;
        Ok(())
    }
}
