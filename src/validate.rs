use orchard::{
    keys::PreparedIncomingViewingKey,
    note::{ExtractedNoteCommitment, Nullifier, TransmittedNoteCiphertext},
    note_encryption::OrchardDomain,
    primitives::redpallas::{self, Binding, Signature, SpendAuth, VerificationKey},
    value::ValueCommitment,
    Action, Anchor, Note,
};
use ff::PrimeField;
use pasta_curves::Fp;
use zcash_note_encryption::try_note_decryption;

use crate::{
    ballot::{Ballot, BallotAction, BallotData, BallotWitnesses},
    circuit::{Circuit, Instance},
    errors::VoteError,
    proof::{Proof, VerifyingKey},
    util::{as_byte256, CtOpt},
};

/// Validates a [`Ballot`] by verifying all cryptographic witnesses.
///
/// Checks, in order:
/// 1. Per-action spend-authorization signatures against the ballot sighash (if present and required).
/// 2. The binding signature over the net value commitment.
/// 3. The Halo2 ZK proof for each action.
///
/// Returns the inner [`BallotData`] on success so callers can inspect the actions.
pub fn validate_ballot(
    ballot: Ballot,
    signature_check: bool,
    vk: &VerifyingKey<Circuit>,
) -> Result<BallotData, VoteError> {
    let Ballot { data, witnesses } = ballot;
    let sighash = data
        .sighash()
        .map_err(|_| VoteError::InvalidBallot("Invalid format".to_string()))?;
    let domain = Fp::from_repr(as_byte256(&data.domain)).unwrap();

    tracing::info!("Verify spending signatures if needed");
    if let Some(sp_signatures) = witnesses.sp_signatures {
        for (signature, action) in sp_signatures.into_iter().zip(data.actions.iter()) {
            let signature: [u8; 64] = signature.0.try_into().map_err(|_| {
                VoteError::InvalidSignature("Signature must be 64 byte long".to_string())
            })?;
            let signature: Signature<SpendAuth> = signature.into();
            let rk = as_byte256(&action.rk);
            let rk: VerificationKey<SpendAuth> = rk
                .try_into()
                .map_err(|_| VoteError::InvalidKey("Invalid public key".to_string()))?;
            rk.verify(&sighash, &signature).map_err(|_| {
                VoteError::InvalidSignature("Signature verification failed".to_string())
            })?;
        }
    } else if signature_check {
        return Err(VoteError::InvalidBallot("Signatures missing".to_string()));
    }

    tracing::info!("Verify binding signature");
    let mut total_cv = ValueCommitment::derive_from_value(0);
    for action in data.actions.iter() {
        let cv_net = as_byte256(&action.cv_net);
        let cv_net = CtOpt(ValueCommitment::from_bytes(&cv_net)).to_result()?;
        total_cv = total_cv + &cv_net;
    }
    let cv: VerificationKey<Binding> = total_cv
        .to_bytes()
        .try_into()
        .map_err(|_| VoteError::InputError)?;
    let binding_signature: [u8; 64] = witnesses
        .binding_signature
        .try_into()
        .map_err(|_| VoteError::InvalidSignature("Invalid binding signature".to_string()))?;
    let binding_signature: Signature<Binding> = binding_signature.into();
    cv.verify(&sighash, &binding_signature)
        .map_err(|_| VoteError::InvalidSignature("Binding Signature".to_string()))?;

    let BallotWitnesses { proofs, .. } = witnesses;

    tracing::info!("Verify ZKP");
    for (proof, action) in proofs.into_iter().zip(data.actions.iter()) {
        let proof: Proof<Circuit> = Proof::new(proof.0);
        let cmx_root = as_byte256(&data.anchors.cmx);
        let nf_root = as_byte256(&data.anchors.nf);
        let cv_net = as_byte256(&action.cv_net);
        let dnf = as_byte256(&action.nf);
        let rk = as_byte256(&action.rk);
        let cmx = as_byte256(&action.cmx);
        tracing::info!("cmx_root {}", hex::encode(&cmx_root));
        tracing::info!("nf_root {}", hex::encode(&nf_root));
        tracing::info!("cv_net {}", hex::encode(&cv_net));
        tracing::info!("dnf {}", hex::encode(&dnf));
        tracing::info!("rk {}", hex::encode(&rk));
        tracing::info!("cmx {}", hex::encode(&cmx));

        let instance = Instance::from_parts(
            CtOpt(Anchor::from_bytes(cmx_root)).to_result()?,
            CtOpt(ValueCommitment::from_bytes(&cv_net)).to_result()?,
            CtOpt(Nullifier::from_bytes(&dnf)).to_result()?,
            rk.try_into().map_err(|_| VoteError::InputError)?,
            CtOpt(ExtractedNoteCommitment::from_bytes(&cmx)).to_result()?,
            domain,
            CtOpt(Anchor::from_bytes(nf_root)).to_result()?,
        );

        proof.verify(vk, &[instance])?;
    }

    // TODO: Verify anchors

    Ok(data)
}

/// Attempts to decrypt a single [`BallotAction`] using the given incoming viewing key.
///
/// Returns `Ok(Some((note, memo)))` if decryption succeeds, `Ok(None)` if the key
/// does not correspond to the note recipient, or an error on malformed input.
pub fn try_decrypt_ballot(
    ivk: &PreparedIncomingViewingKey,
    action: BallotAction,
) -> Result<Option<(Note, [u8; 512])>, VoteError> {
    let BallotAction {
        nf, cmx, epk, enc,
        cv_net, rk, ..
    } = action;

    let rk: [u8; 32] = as_byte256(&rk);
    let rk: redpallas::VerificationKey::<SpendAuth> = rk.try_into().unwrap();
    let nf = Nullifier::from_bytes(&as_byte256(&nf)).unwrap();
    let encrypted_note = TransmittedNoteCiphertext {
        epk_bytes: as_byte256(&epk),
        enc_ciphertext: enc.try_into().unwrap(),
        out_ciphertext: [0u8; 80],
    };
    let cv_net = ValueCommitment::from_bytes(&cv_net.try_into().unwrap()).unwrap();
    let action = Action::from_parts(
        nf,
        rk,
        ExtractedNoteCommitment::from_bytes(&as_byte256(&cmx)).unwrap(),
        encrypted_note,
        cv_net,
        (),
    ).ok_or(VoteError::InvalidKey("Invalid action: rk is identity".to_string()))?;
    let domain = OrchardDomain::for_action(&action);
    let note = try_note_decryption(&domain, ivk, &action).map(|na| (na.0, na.2));
    Ok(note)
}
