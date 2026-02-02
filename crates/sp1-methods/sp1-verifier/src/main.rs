#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::B256;
use amd_sev_snp_attestation_verifier::{
    compute_commitment, stub::VerifierInput, verify_attestation, verify_storage_proof,
};

pub fn main() {
    entrypoint().unwrap()
}

pub fn entrypoint() -> anyhow::Result<()> {
    let input = sp1_zkvm::io::read_vec();
    let verifier_input = VerifierInput::decode(&input)?;

    let mut output = verify_attestation(verifier_input.clone())?;

    if verifier_input.storageStateRoot != B256::ZERO {
        let state_root: [u8; 32] = verifier_input
            .storageStateRoot
            .0
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid state root length"))?;
        verify_storage_proof(
            &state_root,
            &verifier_input.storageKeys,
            &verifier_input.storageValues,
            &verifier_input
                .storageProofNodes
                .iter()
                .map(|b| b.as_ref().to_vec())
                .collect::<Vec<_>>(),
        )?;

        let commitment_felt =
            compute_commitment(&verifier_input.storageKeys, &verifier_input.storageValues);
        output.storageCommitment = B256::from_slice(&commitment_felt.to_bytes_be());
    }

    sp1_zkvm::io::commit_slice(&output.encode());
    Ok(())
}
