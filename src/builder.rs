use crate::{
    ballot::{
        Ballot, BallotAction, BallotActionSecret, BallotAnchors, BallotData, BallotWitnesses,
        VoteProof, VoteSignature,
    },
    circuit::{Circuit, Instance, VotePowerInfo},
    errors::VoteError,
    path::{calculate_cmx_merkle_paths, calculate_nf_merkle_paths, nf_leaf_hash, MerklePathGeneric},
    proof::{Proof, ProvingKey, VerifyingKey},
    util::as_byte256,
    CMX_DEPTH, NF_DEPTH,
};
use orchard::{
    builder::SpendInfo,
    keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendValidatingKey, SpendingKey},
    note::{ExtractedNoteCommitment, Nullifier, RandomSeed, Rho},
    note_encryption::OrchardNoteEncryption,
    primitives::redpallas::{Binding, SigningKey, SpendAuth, VerificationKey},
    tree::MerkleHashOrchard,
    value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
    Anchor, Address, Note,
};
use pasta_curves::{
    group::ff::{Field as _, PrimeField},
    Fp, Fq,
};
use rand::{CryptoRng, RngCore};

/// Per-action NF exclusion data.
#[derive(Clone, Debug)]
pub struct NfExclusion {
    /// Width of the nullifier range.
    pub nf_width: Fp,
    /// Merkle auth path nodes (DEPTH = 29).
    pub nf_path: MerklePathGeneric<NF_DEPTH>,
}

/// Precomputed NF exclusion proof for all actions in a ballot.
///
/// Can be constructed via [`compute_nf_exclusion`] and passed directly to
/// [`vote_with_nf_exclusion`] to skip the (expensive) Merkle tree build inside [`vote`].
#[derive(Clone, Debug)]
pub struct NfExclusionInfo {
    /// Root of the NF exclusion Merkle tree.
    pub nf_root: Fp,
    /// One entry per ballot action (length must equal `max(notes.len(), 2)`).
    pub nf_witness: Vec<NfExclusion>,
}

/// Build the NF exclusion proof from the full NF list and per-action nullifiers.
///
/// `nullifiers` must have one entry per action (including dummies), in action order.
pub fn compute_nf_exclusion(nfs: &[Fp], nullifiers: &[Fp]) -> Result<NfExclusionInfo, VoteError> {
    let mut nf_positions = Vec::with_capacity(nullifiers.len());
    let mut pre: Vec<(Fp, Fp, u32)> = Vec::with_capacity(nullifiers.len());

    for &nf in nullifiers {
        let position = nfs.binary_search(&nf);
        let nf_boundary_position = (match position {
            Ok(p) => p,
            Err(p) => p - 1,
        } & !1);
        let nf_start = nfs[nf_boundary_position];
        if nf_start > nf {
            return Err(VoteError::InputError);
        }
        if nf > nfs[nf_boundary_position + 1] {
            return Err(VoteError::InputError);
        }
        let nf_width = nfs[nf_boundary_position + 1] - nf_start;
        let nf_position = (nf_boundary_position / 2) as u32;
        nf_positions.push(nf_position);
        pre.push((nf_start, nf_width, nf_position));
    }

    let nf_leaf_hashes = nfs
        .chunks_exact(2)
        .map(|pair| nf_leaf_hash(pair[0], pair[1] - pair[0]))
        .collect::<Vec<_>>();
    let (nf_root, nf_mps) = calculate_nf_merkle_paths(0, &nf_positions, &nf_leaf_hashes);

    let nf_witness = pre
        .into_iter()
        .zip(nf_mps.into_iter())
        .map(|((_, nf_width, _), mp)| NfExclusion {
            nf_width,
            nf_path: mp,
        })
        .collect();

    Ok(NfExclusionInfo {
        nf_root,
        nf_witness,
    })
}

/// Per-action CMX Merkle path data.
#[derive(Clone, Debug)]
pub struct CmxInclusion {
    /// Full Orchard Merkle auth path (32 levels).
    pub cmx_path: MerklePathGeneric<CMX_DEPTH>,
}

/// Precomputed CMX Merkle paths for all actions in a ballot.
///
/// Can be constructed via [`compute_cmx_paths`] and passed directly to
/// [`vote_with_nf_exclusion`] to skip the (expensive) Merkle tree build inside [`vote`].
#[derive(Clone, Debug)]
pub struct CmxInclusionInfo {
    /// Root of the CMX Merkle tree.
    pub cmx_root: Fp,
    /// One entry per ballot action (length must equal `max(notes.len(), 2)`).
    pub cmx_witness: Vec<CmxInclusion>,
}

/// Build the CMX Merkle paths from the full CMX list and per-action positions.
///
/// `positions` must have one entry per action (including dummies), in action order.
pub fn compute_cmx_paths(positions: &[u32], cmxs: &[Fp]) -> CmxInclusionInfo {
    let (cmx_root, paths) = calculate_cmx_merkle_paths(0, positions, cmxs);
    let cmx_witness = paths
        .into_iter()
        .map(|path| CmxInclusion { cmx_path: path })
        .collect();
    CmxInclusionInfo {
        cmx_root,
        cmx_witness,
    }
}

/// Encrypts a single vote action without building a full ballot.
///
/// Derives the output note from `spend`, encrypts it for `recipient` with `amount` and `memo`,
/// and returns the serializable [`BallotAction`] together with the randomizers needed to
/// later assemble the ZK proof.
pub fn encrypt_ballot_action<R: CryptoRng + RngCore>(
    domain: Fp,
    fvk: FullViewingKey,
    spend: &Note,
    recipient: Address,
    amount: u64,
    memo: &[u8],
    mut rng: R,
) -> Result<(BallotAction, Fq, ValueCommitTrapdoor), VoteError> {
    let rho = spend.nullifier_domain(&fvk, domain);
    let rho = Rho::from_nf_old(rho);
    let rseed = RandomSeed::random(&mut rng, &rho);
    let output = Note::from_parts(recipient, NoteValue::from_raw(amount), rho, rseed)
        .into_option()
        .ok_or(VoteError::InvalidBallot("Invalid Amount".into()))?;
    let cv_net = spend.value() - output.value();
    let rcv = ValueCommitTrapdoor::random(&mut rng);
    let cv_net = ValueCommitment::derive(cv_net, rcv.clone());
    let alpha = Fq::random(&mut rng);
    let svk = SpendValidatingKey::from(fvk);
    let rk = svk.randomize(&alpha);
    let cmx = output.commitment();
    let cmx = ExtractedNoteCommitment::from(cmx);
    let mut memo_bytes = [0u8; 512];
    memo_bytes[..memo.len()].copy_from_slice(&memo);
    let encryptor = OrchardNoteEncryption::new(None, output.clone(), memo_bytes);
    let epk = encryptor.epk().to_bytes().0;
    let enc = encryptor.encrypt_note_plaintext();
    let rk: [u8; 32] = rk.into();

    let action = BallotAction {
        cv_net: cv_net.to_bytes(),
        rk,
        nf: rho.to_bytes(),
        cmx: cmx.to_bytes(),
        epk,
        enc,
    };
    Ok((action, alpha, rcv))
}

/// Prepare all action inputs (real notes + dummy padding) without yet computing NF exclusion.
///
/// Returns `(action_inputs, self_address, change, net_chg)`.
fn prepare_action_inputs<R: RngCore + CryptoRng>(
    sk: Option<SpendingKey>,
    fvk: &FullViewingKey,
    amount: u64,
    notes: &[(Note, u32)],
    mut rng: R,
) -> (
    Vec<(Option<SpendingKey>, FullViewingKey, Note, u32)>,
    Address,
    u64,
    i64,
) {
    let mut total_value = 0u64;
    let mut inputs: Vec<&(Note, u32)> = vec![];
    for np in notes {
        if total_value >= amount {
            break;
        }
        inputs.push(np);
        total_value += np.0.value().inner();
    }
    let self_address = fvk.address_at(0u64, Scope::External);
    let change = total_value.saturating_sub(amount);
    let net_chg = total_value as i64 - (amount + change) as i64;
    let n_actions = inputs.len().max(2);

    let mut action_inputs = Vec::with_capacity(n_actions);
    for i in 0..n_actions {
        if i < inputs.len() {
            action_inputs.push((sk.clone(), fvk.clone(), inputs[i].0.clone(), inputs[i].1));
        } else {
            let (dummy_sk, dummy_fvk, dummy_note) = Note::dummy(&mut rng, None);
            action_inputs.push((Some(dummy_sk), dummy_fvk, dummy_note, 0u32));
        }
    }

    (action_inputs, self_address, change, net_chg)
}

/// Like [`prepare_action_inputs`] but for notes bundled with their witnesses.
///
/// The per-note [`NfExclusion`] and [`CmxInclusion`] travel with the note through
/// selection so they are never out of sync.  Dummy padding entries reuse the first
/// real note's witnesses (zero-value dummies bypass the CMX assertion in
/// [`vote_inner`]).
fn prepare_action_inputs_with_witnesses<R: RngCore + CryptoRng>(
    sk: Option<SpendingKey>,
    fvk: &FullViewingKey,
    amount: u64,
    notes: &[(Note, u32, NfExclusion, CmxInclusion)],
    mut rng: R,
) -> (
    Vec<(Option<SpendingKey>, FullViewingKey, Note, u32)>,
    Vec<NfExclusion>,
    Vec<CmxInclusion>,
    Address,
    u64,
    i64,
) {
    tracing::info!("prepare_action_inputs_with_witnesses");
    let mut total_value = 0u64;
    let mut inputs: Vec<&(Note, u32, NfExclusion, CmxInclusion)> = vec![];
    for np in notes {
        if total_value >= amount {
            break;
        }
        inputs.push(np);
        total_value += np.0.value().inner();
    }
    let self_address = fvk.address_at(0u64, Scope::External);
    let change = total_value.saturating_sub(amount);
    let net_chg = total_value as i64 - (amount + change) as i64;
    let n_actions = inputs.len().max(2);

    let mut action_inputs = Vec::with_capacity(n_actions);
    let mut nf_witnesses: Vec<NfExclusion> = Vec::with_capacity(n_actions);
    let mut cmx_witnesses: Vec<CmxInclusion> = Vec::with_capacity(n_actions);

    for i in 0..n_actions {
        if i < inputs.len() {
            let (note, pos, nf_excl, cmx_incl) = inputs[i];
            action_inputs.push((sk.clone(), fvk.clone(), note.clone(), *pos));
            nf_witnesses.push(nf_excl.clone());
            cmx_witnesses.push(cmx_incl.clone());
        } else {
            // Dummy padding: generate a zero-value note and reuse the first real
            // note's witnesses (NF & CMX assertion are skipped for zero-value spends).
            let (dummy_sk, dummy_fvk, dummy_note) = Note::dummy(&mut rng, None);
            action_inputs.push((Some(dummy_sk), dummy_fvk, dummy_note, 0u32));
            nf_witnesses.push(inputs[0].2.clone());
            cmx_witnesses.push(inputs[0].3.clone());
        }
    }
    tracing::info!("n_actions={n_actions}");

    (action_inputs, nf_witnesses, cmx_witnesses, self_address, change, net_chg)
}

/// Core ballot builder. Takes pre-generated action inputs, a precomputed [`NfExclusionInfo`],
/// and precomputed [`CmxMerklePathsInfo`].
pub fn vote_inner<F: Fn(String, usize, usize), R: RngCore + CryptoRng>(
    domain: Fp,
    signature_required: bool,
    address: Address,
    self_address: Address,
    amount: u64,
    change: u64,
    net_chg: i64,
    memo: &[u8],
    action_inputs: Vec<(Option<SpendingKey>, FullViewingKey, Note, u32)>,
    nf_exclusion: NfExclusionInfo,
    cmx_paths: CmxInclusionInfo,
    mut rng: R,
    progress: F,
    pk: &ProvingKey<Circuit>,
    vk: &VerifyingKey<Circuit>,
) -> Result<(Ballot, i64), VoteError> {
    let n_actions = action_inputs.len();
    let mut ballot_actions = vec![];
    let mut ballot_secrets = vec![];
    let mut total_rcv = ValueCommitTrapdoor::zero();

    for (i, (sk, fvk, spend, cmx_position)) in action_inputs.into_iter().enumerate() {
        let rho = spend.nullifier_domain(&fvk, domain);
        let rho = Rho::from_nf_old(rho);
        let rseed = RandomSeed::random(&mut rng, &rho);
        let output = match i {
            0 => {
                // vote
                Note::from_parts(address, NoteValue::from_raw(amount), rho, rseed).unwrap()
            }
            1 => {
                // change
                Note::from_parts(self_address, NoteValue::from_raw(change), rho, rseed).unwrap()
            }
            _ => {
                // pad with dummy output
                let (_, _, dummy_output) = Note::dummy(&mut rng, Some(rho));
                dummy_output
            }
        };

        let cv_net = spend.value() - output.value();
        let rcv = ValueCommitTrapdoor::random(&mut rng);
        total_rcv = total_rcv + &rcv;
        let cv_net = ValueCommitment::derive(cv_net, rcv.clone());

        let alpha = Fq::random(&mut rng);
        let svk = SpendValidatingKey::from(fvk.clone());
        let rk = svk.randomize(&alpha);
        let sp_signkey = sk.map(|sk| {
            let spak = SpendAuthorizingKey::from(&sk);
            spak.randomize(&alpha)
        });

        let nf = spend.nullifier(&fvk);
        let nf_excl = &nf_exclusion.nf_witness[i];

        ballot_secrets.push(BallotActionSecret {
            fvk: fvk.clone(),
            spend_note: spend.clone(),
            output_note: output.clone(),
            rcv: rcv.clone(),
            alpha,
            sp_signkey,
            nf,
            nf_start: Nullifier::from_bytes(&nf_excl.nf_path.value.to_repr()).unwrap(),
            nf_width: nf_excl.nf_width,
            nf_position: nf_excl.nf_path.position,
            cmx_position,
            cv_net: cv_net.clone(),
            rk: rk.clone(),
        });

        let cmx_expected = cmx_paths.cmx_witness[i].cmx_path.value;
        let cmx = spend.commitment();
        let cmx = ExtractedNoteCommitment::from(cmx);
        assert!(spend.value() == NoteValue::zero() || cmx_expected == cmx.inner());

        let cmx = output.commitment();
        let cmx = ExtractedNoteCommitment::from(cmx);

        let mut memo_bytes = [0u8; 512];
        memo_bytes[..memo.len()].copy_from_slice(&memo);
        let encryptor = OrchardNoteEncryption::new(None, output.clone(), memo_bytes);
        let epk = encryptor.epk().to_bytes().0;
        let enc = encryptor.encrypt_note_plaintext();

        let rk: [u8; 32] = rk.into();
        let ballot_action = BallotAction {
            cv_net: cv_net.to_bytes(),
            rk,
            nf: rho.to_bytes(),
            cmx: cmx.to_bytes(),
            epk,
            enc,
        };

        ballot_actions.push(ballot_action);
    }

    // Reconstruct MerklePath values from the precomputed NF exclusion data.
    let nf_root = nf_exclusion.nf_root;
    let nf_mps: Vec<MerklePathGeneric<NF_DEPTH>> = nf_exclusion
        .nf_witness
        .into_iter()
        .map(|p| p.nf_path)
        .collect();

    let cmx_root = cmx_paths.cmx_root;
    let cmx_mps: Vec<MerklePathGeneric<CMX_DEPTH>> = cmx_paths
        .cmx_witness
        .into_iter()
        .map(|p| p.cmx_path)
        .collect();

    let mut proofs = vec![];
    for ((((i, secret), public), cmx_mp), nf_mp) in ballot_secrets
        .iter()
        .enumerate()
        .zip(ballot_actions.iter())
        .zip(cmx_mps.iter())
        .zip(nf_mps.iter())
    {
        let cmx = ExtractedNoteCommitment::from_bytes(&as_byte256(&public.cmx)).unwrap();
        let instance = Instance::from_parts(
            Anchor::from_bytes(cmx_root.to_repr()).unwrap(),
            secret.cv_net.clone(),
            Nullifier::from_bytes(&as_byte256(&public.nf)).unwrap(),
            secret.rk.clone(),
            cmx,
            domain.clone(),
            Anchor::from_bytes(nf_root.to_repr()).unwrap(),
        );
        assert_eq!(nf_mp.position, secret.nf_position);

        let vote_power = VotePowerInfo {
            dnf: Nullifier::from_bytes(&as_byte256(&public.nf)).unwrap(),
            nf_start: secret.nf_start,
            width: secret.nf_width,
            nf_path: nf_mp.clone(),
        };

        let cmx_mp = orchard::tree::MerklePath::from_parts(
            cmx_mp.position,
            cmx_mp.auth_path().map(MerkleHashOrchard::from_base),
        );

        let spend_info =
            SpendInfo::new(secret.fvk.clone(), secret.spend_note, cmx_mp.clone()).unwrap();
        let circuit = Circuit::from_action_context_unchecked(
            vote_power,
            spend_info,
            secret.output_note,
            secret.alpha,
            secret.rcv.clone(),
        );

        let instances = std::slice::from_ref(&instance);
        tracing::info!("Proving");
        progress("Building proof".to_string(), i + 1, n_actions);
        let proof = Proof::<Circuit>::create(pk, &[circuit], instances, &mut rng)?;
        tracing::info!("Verifying");
        progress("Verifying proof".to_string(), i + 1, n_actions);
        proof.verify(vk, instances)?;
        tracing::info!("Proof generated");
        let proof = proof.as_ref().to_vec();
        proofs.push(VoteProof(proof));
    }

    let anchors = BallotAnchors {
        nf: nf_root.to_repr(),
        cmx: cmx_root.to_repr(),
    };

    progress("Signing".to_string(), 0, 0);
    let ballot_data = BallotData {
        version: 1,
        domain: domain.to_repr(),
        actions: ballot_actions.clone(),
        anchors,
    };
    let sighash = ballot_data
        .sighash()
        .map_err(|_| VoteError::InvalidBallot("sighash".to_string()))?;

    let sp_signatures = ballot_secrets
        .iter()
        .zip(ballot_actions.iter())
        .map(|(s, a)| {
            s.sp_signkey.as_ref().map(|sk| {
                let signature = sk.sign(&mut rng, &sighash);
                let signature_bytes: [u8; 64] = (&signature).into();
                let rk = as_byte256(&a.rk);
                let rk: VerificationKey<SpendAuth> = rk.try_into().unwrap();
                rk.verify(&sighash, &signature).unwrap();
                VoteSignature(signature_bytes)
            })
        })
        .collect::<Option<Vec<_>>>();
    if signature_required && sp_signatures.is_none() {
        return Err(VoteError::InvalidSignature(
            "Signature required".to_string(),
        ));
    }

    let bsk: SigningKey<Binding> = total_rcv.to_bytes().try_into().unwrap();
    let binding_signature = bsk.sign(&mut rng, &sighash);
    let binding_signature: [u8; 64] = (&binding_signature).into();

    let witnesses = BallotWitnesses {
        proofs,
        sp_signatures,
        binding_signature,
    };

    let ballot = Ballot {
        data: ballot_data,
        witnesses,
    };
    progress("Ballot built".to_string(), 0, 0);

    Ok((ballot, net_chg))
}

/// Build a ballot, computing the NF exclusion proof internally from `nfs`.
pub fn vote<F: Fn(String, usize, usize), R: RngCore + CryptoRng>(
    domain: Fp,
    signature_required: bool,
    sk: Option<SpendingKey>,
    fvk: &FullViewingKey,
    address: Address,
    amount: u64,
    memo: &[u8],
    notes: &[(Note, u32)],
    nfs: &[Fp],
    cmxs: &[Fp],
    mut rng: R,
    progress: F,
    pk: &ProvingKey<Circuit>,
    vk: &VerifyingKey<Circuit>,
) -> Result<(Ballot, i64), VoteError> {
    progress("Starting Ballot Creation".to_string(), 0, 0);

    let (action_inputs, self_address, change, net_chg) =
        prepare_action_inputs(sk, fvk, amount, notes, &mut rng);

    let nullifiers: Vec<Fp> = action_inputs
        .iter()
        .map(|(_, fvk, note, _)| {
            let nf = note.nullifier(fvk);
            Fp::from_repr(nf.to_bytes()).unwrap()
        })
        .collect();

    progress("Calculating NF merkle tree".to_string(), 0, 0);
    let nf_exclusion = compute_nf_exclusion(nfs, &nullifiers)?;

    let cmx_positions: Vec<u32> = action_inputs.iter().map(|(_, _, _, pos)| *pos).collect();
    progress("Calculating CMX merkle tree".to_string(), 0, 0);
    let cmx_paths = compute_cmx_paths(&cmx_positions, cmxs);

    vote_inner(
        domain,
        signature_required,
        address,
        self_address,
        amount,
        change,
        net_chg,
        memo,
        action_inputs,
        nf_exclusion,
        cmx_paths,
        rng,
        progress,
        pk,
        vk,
    )
}

/// Build a ballot using precomputed per-note [`NfExclusion`] and [`CmxInclusion`] witnesses.
///
/// Each entry in `notes` bundles a note with its position and both Merkle witnesses so
/// that note selection and witness selection are always in sync.  `nf_root` and
/// `cmx_root` are the global roots of the respective trees.
pub fn vote_with_nf_exclusion<F: Fn(String, usize, usize), R: RngCore + CryptoRng>(
    domain: Fp,
    signature_required: bool,
    sk: Option<SpendingKey>,
    fvk: &FullViewingKey,
    address: Address,
    amount: u64,
    memo: &[u8],
    notes: &[(Note, u32, NfExclusion, CmxInclusion)],
    nf_root: Fp,
    cmx_root: Fp,
    mut rng: R,
    progress: F,
    pk: &ProvingKey<Circuit>,
    vk: &VerifyingKey<Circuit>,
) -> Result<(Ballot, i64), VoteError> {
    progress("Starting Ballot Creation".to_string(), 0, 0);

    let (action_inputs, nf_witness, cmx_witness, self_address, change, net_chg) =
        prepare_action_inputs_with_witnesses(sk, fvk, amount, notes, &mut rng);

    let nf_exclusion = NfExclusionInfo { nf_root, nf_witness };
    let cmx_paths = CmxInclusionInfo { cmx_root, cmx_witness };

    vote_inner(
        domain,
        signature_required,
        address,
        self_address,
        amount,
        change,
        net_chg,
        memo,
        action_inputs,
        nf_exclusion,
        cmx_paths,
        rng,
        progress,
        pk,
        vk,
    )
}

/// Generates a random dummy spending key, full viewing key, and note for testing purposes.
pub fn dummy_vote<R: RngCore + CryptoRng>(mut rng: R) -> (SpendingKey, FullViewingKey, Note) {
    Note::dummy(&mut rng, None)
}
