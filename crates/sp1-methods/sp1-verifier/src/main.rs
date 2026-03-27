#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::B256;
use amd_sev_snp_attestation_verifier::{
    compute_commitment, compute_storage_commitment, stub::VerifierInput, verify_attestation,
    verify_contracts_proof, verify_event_content, verify_event_proof, verify_global_state_root,
    verify_storage_proof,
};

pub fn main() {
    entrypoint().unwrap()
}

pub fn entrypoint() -> anyhow::Result<()> {
    let input = sp1_zkvm::io::read_vec();
    let verifier_input = VerifierInput::decode(&input)?;

    // ── 1. Attestation ──────────────────────────────────────────────────
    // Verify TEE report signature, certificate chain, and trust anchors.
    // Produces the base journal with attestation.* fields populated.
    let mut output = verify_attestation(verifier_input.clone())?;

    // ── 2. Event proof ──────────────────────────────────────────────────
    // Prove ShardFinished event exists in the attested block.
    // Must run before storage proof: endBlockNumber is bound into the commitment.
    verify_shard_event(&verifier_input, &mut output.shard)?;

    // ── 3. Storage proof ────────────────────────────────────────────────
    // Prove storage key/value pairs against the attested global state root.
    verify_shard_storage(&verifier_input, &mut output.shard)?;

    sp1_zkvm::io::commit_slice(&output.encode());
    Ok(())
}

/// Verify event inclusion + content. Populates `shard.endBlockNumber`,
/// `shard.eventGameContract`, and `shard.eventShardId`.
fn verify_shard_event(
    input: &VerifierInput,
    shard: &mut amd_sev_snp_attestation_verifier::stub::ShardProof,
) -> anyhow::Result<()> {
    if input.eventMerkleProof.is_empty() {
        return Ok(());
    }

    // Merkle inclusion: event exists in the block's events commitment
    verify_event_proof(
        &input.eventsCommitment.0,
        &input.eventHash.0,
        input.eventIndex,
        input.eventsCount,
        &input.eventMerkleProof,
    )?;
    shard.endBlockNumber = input.endBlockNumber;

    // Content verification: recompute event hash from components
    if input.eventKeys.is_empty() && input.eventData.is_empty() {
        return Ok(());
    }
    verify_event_content(
        &input.eventHash.0,
        &input.eventTxHash.0,
        &input.eventFromAddress.0,
        &input.eventKeys,
        &input.eventData,
    )?;
    if !input.eventKeys.is_empty() {
        shard.eventGameContract = input.eventKeys[0];
    }
    if !input.eventData.is_empty() {
        shard.eventShardId = input.eventData[0];
    }

    Ok(())
}

/// Verify storage trie proof and compute the replay-protected commitment.
/// Populates `shard.storageCommitment`.
fn verify_shard_storage(
    input: &VerifierInput,
    shard: &mut amd_sev_snp_attestation_verifier::stub::ShardProof,
) -> anyhow::Result<()> {
    if input.storageKeys.is_empty() {
        return Ok(());
    }

    // Global state root = hash("STARKNET_STATE_V0", contracts_root, classes_root)
    verify_global_state_root(
        &input.globalStateRoot.0,
        &input.contractsTreeRoot.0,
        &input.classesTreeRoot.0,
    )?;

    // Contract exists in contracts tree with expected storage root
    verify_contracts_proof(
        &input.contractsTreeRoot.0,
        &input.contractAddress.0,
        &input.contractClassHash.0,
        &input.contractStorageRoot.0,
        input.contractLeafNonce,
        &input.contractsProofNodes,
    )?;

    // Storage keys/values exist in contract's storage trie
    verify_storage_proof(
        &input.contractStorageRoot.0,
        &input.storageKeys,
        &input.storageValues,
        &input.storageProofNodes,
    )?;

    // Replay-protected commitment: hash(raw, address, nonce, state_root, end_block)
    let raw = compute_storage_commitment(&input.storageKeys, &input.storageValues);
    let commitment = compute_commitment(
        &raw,
        &input.contractAddress.0,
        input.nonce,
        &input.globalStateRoot.0,
        shard.endBlockNumber,
    );
    shard.storageCommitment = B256::from_slice(&commitment.to_bytes_be());

    Ok(())
}
