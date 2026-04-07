use rand::{CryptoRng, RngCore};
use zcash_note_encryption::{try_compact_note_decryption, ShieldedOutput};

use orchard::{
    keys::{FullViewingKey, PreparedIncomingViewingKey, Scope},
    note::{ExtractedNoteCommitment, Nullifier, RandomSeed, Rho},
    note_encryption::OrchardDomain,
    value::NoteValue,
    Address, Note,
};

use crate::ballot::BallotAction;
use crate::errors::VoteError;

/// A shielded vote action whose note plaintext is encrypted for the recipient.
#[derive(Debug)]
pub struct EncryptedVote(pub(crate) BallotAction);

/// The plaintext contents of a vote note after successful decryption.
#[derive(Debug)]
pub struct DecryptedVote {
    pub(crate) address: Address,
    pub(crate) value: u64,
    pub(crate) rho: Rho,
    pub(crate) rseed: RandomSeed,
    pub(crate) cmx: ExtractedNoteCommitment,
}

impl DecryptedVote {
    pub(crate) fn random<R: RngCore + CryptoRng>(mut rng: R) -> Self {
        let (_, _, note) = Note::dummy(&mut rng, None);
        let v = rng.next_u32() as u64;
        let note = Note::from_parts(
            note.recipient(),
            NoteValue::from_raw(v),
            note.rho(),
            note.rseed().clone(),
        )
        .unwrap();
        let cmx = ExtractedNoteCommitment::from(note.commitment());
        DecryptedVote {
            address: note.recipient(),
            value: v,
            rho: note.rho(),
            rseed: note.rseed().clone(),
            cmx,
        }
    }
}

impl ShieldedOutput<OrchardDomain, 52> for BallotAction {
    fn ephemeral_key(&self) -> zcash_note_encryption::EphemeralKeyBytes {
        zcash_note_encryption::EphemeralKeyBytes(self.epk)
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cmx
    }

    fn enc_ciphertext(&self) -> &[u8; 52] {
        self.enc[..52].try_into().unwrap()
    }
}

impl EncryptedVote {
    /// Decrypts this vote using the given full viewing key.
    ///
    /// Returns a [`DecryptedVote`] on success, or [`VoteError::DecryptionError`] if the
    /// key does not correspond to the note recipient.
    pub fn decrypt(&self, fvk: &FullViewingKey) -> Result<DecryptedVote, VoteError> {
        let ba = &self.0;
        let nf = Nullifier::from_bytes(&ba.nf).unwrap();
        let ivk = fvk.to_ivk(Scope::External);
        let rho = Rho::from_nf_old(nf);
        let orchard_domain = OrchardDomain::for_rho(rho);
        let ivk = PreparedIncomingViewingKey::new(&ivk);
        let (note, address) = try_compact_note_decryption(&orchard_domain, &ivk, ba)
            .ok_or_else(|| VoteError::DecryptionError)?;
        let value = note.value().inner();
        Ok(DecryptedVote {
            address,
            value,
            rho: note.rho(),
            rseed: note.rseed().clone(),
            cmx: ExtractedNoteCommitment::from_bytes(&self.0.cmx).unwrap(),
        })
    }
}
