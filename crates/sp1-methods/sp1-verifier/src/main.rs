#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::B256;
use amd_sev_snp_attestation_verifier::{
    compute_commitment, compute_storage_commitment, stub::VerifierInput, verify_attestation,
    verify_contracts_proof, verify_event_proof, verify_global_state_root, verify_storage_proof,
};

pub fn main() {
    entrypoint().unwrap()
}

pub fn entrypoint() -> anyhow::Result<()> {
    let input = sp1_zkvm::io::read_vec();
    let verifier_input = VerifierInput::decode(&input)?;

    // Verify TEE attestation (report signature, certificates, etc.)
    let mut output = verify_attestation(verifier_input.clone())?;

    // Full state verification (only if storage keys provided)
    if !verifier_input.storageKeys.is_empty() {
        // Verify global_state_root = hash("STARKNET_STATE_V0", contracts_tree_root, classes_tree_root)
        // This proves that contracts_tree_root is part of the attested state
        verify_global_state_root(
            &verifier_input.globalStateRoot.0,
            &verifier_input.contractsTreeRoot.0,
            &verifier_input.classesTreeRoot.0,
        )?;

        // Verify contract is in contracts_tree with expected storage_root
        // This proves that contractStorageRoot belongs to contractAddress in the attested state
        verify_contracts_proof(
            &verifier_input.contractsTreeRoot.0,
            &verifier_input.contractAddress.0,
            &verifier_input.contractClassHash.0,
            &verifier_input.contractStorageRoot.0,
            verifier_input.contractLeafNonce,
            &verifier_input.contractsProofNodes,
        )?;

        // Verify storage keys/values are in contract's storage trie
        // This proves that keys/values are part of the contract's storage
        verify_storage_proof(
            &verifier_input.contractStorageRoot.0,
            &verifier_input.storageKeys,
            &verifier_input.storageValues,
            &verifier_input.storageProofNodes,
        )?;

        // Compute commitment using global_state_root (the attested root)
        let storage_commitment = compute_storage_commitment(
            &verifier_input.storageKeys,
            &verifier_input.storageValues,
        );
        let commitment = compute_commitment(
            &storage_commitment,
            &verifier_input.contractAddress.0,
            verifier_input.nonce,
            &verifier_input.globalStateRoot.0, // Use global_state_root (attested)
        );
        output.storageCommitment = B256::from_slice(&commitment.to_bytes_be());
    }

    // Step 5: Verify event inclusion proof (C2: shard ending verification)
    if !verifier_input.eventMerkleProof.is_empty() {
        verify_event_proof(
            &verifier_input.eventsCommitment.0,
            &verifier_input.eventHash.0,
            verifier_input.eventIndex,
            verifier_input.eventsCount,
            &verifier_input.eventMerkleProof,
        )?;
        output.endBlockNumber = verifier_input.endBlockNumber;
    }

    sp1_zkvm::io::commit_slice(&output.encode());
    Ok(())
}
