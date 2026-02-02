//! Storage proof verification and commitment computation for the ZK circuit.
//!
//! The commitment is poseidon_hash(keys || values) so the Cairo contract can verify
//! with: poseidon_hash_span([keys..., values...]) == journal.storageCommitment.
//!
//! Storage proofs are verified using [bonsai-trie](https://github.com/dojoengine/bonsai-trie)
//! (same format as Katana/Starknet): Pedersen hash, 251-bit keys (Felt), MultiProof from the trie.

use alloy_primitives::Bytes;
use anyhow::{ensure, Context};
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::{Poseidon, StarkHash};

/// Computes the storage commitment as poseidon_hash(keys || values).
/// Matches Cairo: poseidon_hash_span([keys..., values...]).
pub fn compute_commitment(keys: &[Bytes], values: &[Bytes]) -> Felt {
    let mut data = Vec::with_capacity(keys.len() + values.len());
    for key in keys {
        data.push(bytes_to_felt(key));
    }
    for value in values {
        data.push(bytes_to_felt(value));
    }
    Poseidon::hash_array(&data)
}

fn bytes_to_felt(b: &Bytes) -> Felt {
    let arr: [u8; 32] = b.as_ref().try_into().expect("expected 32 bytes");
    Felt::from_bytes_be(&arr)
}

/// Verifies a storage proof using bonsai-trie (Katana/Starknet format).
///
/// - `state_root`: 32 bytes (Felt)
/// - `keys` / `values`: each 32 bytes (Felt). Keys become trie paths: Felt → 251 bits (skip top 5 bits)
/// - `proof_nodes`: one element = scale-encoded MultiProof: `u32 len` then for each node:
///   `Felt key`, `u8 tag` (0=Binary, 1=Edge), then Binary: `Felt left`, `Felt right`;
///   Edge: `Felt child`, `Path path`. Same format as produced by Katana's trie.multiproof().
pub fn verify_storage_proof(
    state_root: &[u8; 32],
    keys: &[Bytes],
    values: &[Bytes],
    proof_nodes: &[Vec<u8>],
) -> anyhow::Result<()> {
    ensure!(
        keys.len() == values.len(),
        "keys and values length mismatch: {} vs {}",
        keys.len(),
        values.len()
    );
    if keys.is_empty() {
        ensure!(
            proof_nodes.is_empty() && state_root == &[0u8; 32],
            "empty keys/values requires empty proof and zero root"
        );
        return Ok(());
    }

    verify_storage_proof_bonsai(state_root, keys, values, proof_nodes)
}

fn verify_storage_proof_bonsai(
    state_root: &[u8; 32],
    keys: &[Bytes],
    values: &[Bytes],
    proof_nodes: &[Vec<u8>],
) -> anyhow::Result<()> {
    use starknet_types_core::felt::Felt;
    use starknet_types_core::hash::Pedersen;

    let proof_bytes = proof_nodes
        .first()
        .context("bonsai proof requires one scale-encoded MultiProof in proof_nodes[0]")?;
    let multiproof = decode_bonsai_multiproof(proof_bytes)?;

    let root = felt_from_bytes(state_root)?;
    let key_bits: Vec<_> = keys
        .iter()
        .map(|k| felt_to_trie_key_bits(k))
        .collect::<anyhow::Result<_>>()?;

    let verified_values: Vec<Felt> = multiproof
        .verify_proof::<Pedersen>(root, key_bits.iter().map(|b| b.as_bitslice()), 251)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("bonsai proof verification failed: {}", e))?;

    ensure!(
        verified_values.len() == values.len(),
        "proof returned {} values, expected {}",
        verified_values.len(),
        values.len()
    );
    for (i, (got, expected_bytes)) in verified_values.iter().zip(values.iter()).enumerate() {
        let expected = felt_from_bytes(expected_bytes.as_ref())?;
        ensure!(
            got == &expected,
            "value mismatch at index {}: proof gave {:?}, expected {:?}",
            i,
            got,
            expected
        );
    }
    Ok(())
}

fn felt_from_bytes(b: &[u8]) -> anyhow::Result<starknet_types_core::felt::Felt> {
    let arr: [u8; 32] = b
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected 32 bytes for Felt, got {}", b.len()))?;
    Ok(starknet_types_core::felt::Felt::from_bytes_be(&arr))
}

fn felt_to_trie_key_bits(
    key: &Bytes,
) -> anyhow::Result<bitvec::prelude::BitVec<u8, bitvec::order::Msb0>> {
    use bitvec::view::AsBits;
    let b = key.as_ref();
    ensure!(b.len() >= 32, "key must be at least 32 bytes for Felt");
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&b[b.len() - 32..]);
    let felt = starknet_types_core::felt::Felt::from_bytes_be(&arr);
    let bytes = felt.to_bytes_be();
    let bits = bytes.as_bits::<bitvec::order::Msb0>();
    let trie_bits = bits[5..].to_owned();
    Ok(trie_bits)
}

/// Decodes scale-encoded MultiProof (IndexMap<Felt, ProofNode>).
fn decode_bonsai_multiproof(bytes: &[u8]) -> anyhow::Result<bonsai_trie::MultiProof> {
    use bonsai_trie::{Path, ProofNode};
    use indexmap::IndexMap;
    use parity_scale_codec::Decode;
    use starknet_types_core::felt::Felt;

    let mut r = &bytes[..];
    let len = u32::decode(&mut r).context("decode proof len")? as usize;
    let mut map = IndexMap::with_capacity(len);
    for _ in 0..len {
        let key = Felt::decode(&mut r).context("decode proof node key")?;
        let tag = u8::decode(&mut r).context("decode proof node tag")?;
        let node = match tag {
            0 => {
                let left = Felt::decode(&mut r).context("decode Binary left")?;
                let right = Felt::decode(&mut r).context("decode Binary right")?;
                ProofNode::Binary { left, right }
            }
            1 => {
                let child = Felt::decode(&mut r).context("decode Edge child")?;
                let path = Path::decode(&mut r).context("decode Edge path")?;
                ProofNode::Edge { child, path }
            }
            _ => anyhow::bail!("invalid proof node tag {}", tag),
        };
        map.insert(key, node);
    }
    Ok(bonsai_trie::MultiProof(map))
}
