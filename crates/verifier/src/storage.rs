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
    proof_nodes: &[Bytes],
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
    proof_nodes: &[Bytes],
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
fn decode_bonsai_multiproof(bytes: &Bytes) -> anyhow::Result<bonsai_trie::MultiProof> {
    use bonsai_trie::{Path, ProofNode};
    use indexmap::IndexMap;
    use parity_scale_codec::Decode;
    use starknet_types_core::felt::Felt;

    let mut r = bytes.as_ref();
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Bytes;
    use bitvec::view::AsBits;
    use bonsai_trie::{
        databases::HashMapDb, id::BasicIdBuilder, BonsaiStorage, BonsaiStorageConfig, MultiProof,
    };
    use parity_scale_codec::Encode;
    use starknet_types_core::felt::Felt;
    use starknet_types_core::hash::Pedersen;

    /// Helper for building test tries and generating proofs
    struct TestTrie {
        storage: BonsaiStorage<bonsai_trie::id::BasicId, HashMapDb<bonsai_trie::id::BasicId>, Pedersen>,
        entries: Vec<(Felt, Felt)>,
    }

    impl TestTrie {
        fn new() -> Self {
            let config = BonsaiStorageConfig::default();
            let db = HashMapDb::<bonsai_trie::id::BasicId>::default();
            let storage = BonsaiStorage::<_, _, Pedersen>::new(db, config, 251);
            Self { storage, entries: vec![] }
        }

        fn insert(&mut self, key: Felt, value: Felt) {
            let identifier = b"test";
            let key_bits = key.to_bytes_be().as_bits::<bitvec::order::Msb0>()[5..].to_owned();
            self.storage.insert(identifier, &key_bits, &value).unwrap();
            self.entries.push((key, value));
        }

        fn commit(&mut self) -> Felt {
            let identifier = b"test";
            let id = BasicIdBuilder::new().new_id();
            self.storage.commit(id).unwrap();
            self.storage.root_hash(identifier).unwrap()
        }

        fn get_proof(&mut self, query_keys: &[Felt]) -> MultiProof {
            let identifier = b"test";
            let keys_bits: Vec<_> = query_keys
                .iter()
                .map(|k| k.to_bytes_be().as_bits::<bitvec::order::Msb0>()[5..].to_owned())
                .collect();
            self.storage
                .get_multi_proof(identifier, keys_bits.iter().map(|b| b.as_bitslice()))
                .unwrap()
        }

        fn encode_proof(multiproof: &MultiProof) -> Vec<u8> {
            let mut encoded = Vec::new();
            (multiproof.0.len() as u32).encode_to(&mut encoded);
            for (node_key, node) in multiproof.0.iter() {
                node_key.encode_to(&mut encoded);
                match node {
                    bonsai_trie::ProofNode::Binary { left, right } => {
                        0u8.encode_to(&mut encoded);
                        left.encode_to(&mut encoded);
                        right.encode_to(&mut encoded);
                    }
                    bonsai_trie::ProofNode::Edge { child, path } => {
                        1u8.encode_to(&mut encoded);
                        child.encode_to(&mut encoded);
                        path.encode_to(&mut encoded);
                    }
                }
            }
            encoded
        }
    }

    #[test]
    fn test_compute_commitment_with_proof_data() {
        let key = Bytes::from(
            hex::decode("007ebcc807b5c7e19f245995a55aed6f46f5f582f476a886b91b834b0ddf5854")
                .unwrap(),
        );
        let value = Bytes::from(
            hex::decode("0000000000000000000000000000000000000000000000000000000000000003")
                .unwrap(),
        );

        let commitment = compute_commitment(&[key], &[value]);

        assert_eq!(
            commitment,
            Felt::from_hex("0x5c5e91c4a356d59920f05d3f642f2ac12d6bb5820d4e824fae01d2228712385")
                .unwrap()
        );
    }

    #[test]
    fn test_verify_storage_proof_empty() {
        let state_root = [0u8; 32];
        let keys: Vec<Bytes> = vec![];
        let values: Vec<Bytes> = vec![];
        let proof_nodes: Vec<Bytes> = vec![];

        let result = verify_storage_proof(&state_root, &keys, &values, &proof_nodes);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_storage_proof_empty_with_non_zero_root_fails() {
        let state_root = [1u8; 32];
        let keys: Vec<Bytes> = vec![];
        let values: Vec<Bytes> = vec![];
        let proof_nodes: Vec<Bytes> = vec![];

        let result = verify_storage_proof(&state_root, &keys, &values, &proof_nodes);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_storage_proof_key_value_mismatch() {
        let state_root = [0u8; 32];
        let keys = vec![Bytes::from(vec![0u8; 32])];
        let values: Vec<Bytes> = vec![];
        let proof_nodes: Vec<Bytes> = vec![];

        let result = verify_storage_proof(&state_root, &keys, &values, &proof_nodes);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("mismatch"));
    }

    #[test]
    fn test_verify_storage_proof_single_entry() {
        let mut trie = TestTrie::new();

        let key = Felt::from_hex("0x007ebcc807b5c7e19f245995a55aed6f46f5f582f476a886b91b834b0ddf5854").unwrap();
        let value = Felt::from_hex("0x03").unwrap();
        trie.insert(key, value);

        let root = trie.commit();
        let multiproof = trie.get_proof(&[key]);
        let encoded = TestTrie::encode_proof(&multiproof);

        let state_root: [u8; 32] = root.to_bytes_be();
        let keys = vec![Bytes::from(key.to_bytes_be().to_vec())];
        let values = vec![Bytes::from(value.to_bytes_be().to_vec())];
        let proof_nodes = vec![Bytes::from(encoded)];

        let result = verify_storage_proof(&state_root, &keys, &values, &proof_nodes);
        assert!(result.is_ok(), "verify_storage_proof failed: {:?}", result.err());
    }

    #[test]
    fn test_verify_storage_proof_multiple_entries() {
        let mut trie = TestTrie::new();

        // Insert multiple entries
        let entries = vec![
            (Felt::from(1u64), Felt::from(100u64)),
            (Felt::from(2u64), Felt::from(200u64)),
            (Felt::from(3u64), Felt::from(300u64)),
            (Felt::from(1000u64), Felt::from(999u64)),
            (Felt::from_hex("0xdeadbeef").unwrap(), Felt::from_hex("0xcafe").unwrap()),
        ];

        for (k, v) in &entries {
            trie.insert(*k, *v);
        }

        let root = trie.commit();

        // Query all entries
        let query_keys: Vec<Felt> = entries.iter().map(|(k, _)| *k).collect();
        let multiproof = trie.get_proof(&query_keys);
        let encoded = TestTrie::encode_proof(&multiproof);

        let state_root: [u8; 32] = root.to_bytes_be();
        let keys: Vec<Bytes> = entries.iter().map(|(k, _)| Bytes::from(k.to_bytes_be().to_vec())).collect();
        let values: Vec<Bytes> = entries.iter().map(|(_, v)| Bytes::from(v.to_bytes_be().to_vec())).collect();
        let proof_nodes = vec![Bytes::from(encoded)];

        let result = verify_storage_proof(&state_root, &keys, &values, &proof_nodes);
        assert!(result.is_ok(), "verify_storage_proof with multiple entries failed: {:?}", result.err());
    }

    #[test]
    fn test_verify_storage_proof_partial_query() {
        let mut trie = TestTrie::new();

        // Insert 5 entries but only query 2
        trie.insert(Felt::from(1u64), Felt::from(100u64));
        trie.insert(Felt::from(2u64), Felt::from(200u64));
        trie.insert(Felt::from(3u64), Felt::from(300u64));
        trie.insert(Felt::from(4u64), Felt::from(400u64));
        trie.insert(Felt::from(5u64), Felt::from(500u64));

        let root = trie.commit();

        // Only query keys 2 and 4
        let query_keys = vec![Felt::from(2u64), Felt::from(4u64)];
        let query_values = vec![Felt::from(200u64), Felt::from(400u64)];

        let multiproof = trie.get_proof(&query_keys);
        let encoded = TestTrie::encode_proof(&multiproof);

        let state_root: [u8; 32] = root.to_bytes_be();
        let keys: Vec<Bytes> = query_keys.iter().map(|k| Bytes::from(k.to_bytes_be().to_vec())).collect();
        let values: Vec<Bytes> = query_values.iter().map(|v| Bytes::from(v.to_bytes_be().to_vec())).collect();
        let proof_nodes = vec![Bytes::from(encoded)];

        let result = verify_storage_proof(&state_root, &keys, &values, &proof_nodes);
        assert!(result.is_ok(), "partial query verification failed: {:?}", result.err());
    }

    #[test]
    fn test_verify_storage_proof_wrong_root_fails() {
        let mut trie = TestTrie::new();

        let key = Felt::from(42u64);
        let value = Felt::from(123u64);
        trie.insert(key, value);

        let _correct_root = trie.commit();
        let multiproof = trie.get_proof(&[key]);
        let encoded = TestTrie::encode_proof(&multiproof);

        // Use wrong root (all 1s instead of correct root)
        let wrong_root = [1u8; 32];
        let keys = vec![Bytes::from(key.to_bytes_be().to_vec())];
        let values = vec![Bytes::from(value.to_bytes_be().to_vec())];
        let proof_nodes = vec![Bytes::from(encoded)];

        let result = verify_storage_proof(&wrong_root, &keys, &values, &proof_nodes);
        assert!(result.is_err(), "should fail with wrong root");
    }

    #[test]
    fn test_verify_storage_proof_wrong_value_fails() {
        let mut trie = TestTrie::new();

        let key = Felt::from(42u64);
        let value = Felt::from(123u64);
        trie.insert(key, value);

        let root = trie.commit();
        let multiproof = trie.get_proof(&[key]);
        let encoded = TestTrie::encode_proof(&multiproof);

        let state_root: [u8; 32] = root.to_bytes_be();
        let keys = vec![Bytes::from(key.to_bytes_be().to_vec())];
        // Wrong value - 999 instead of 123
        let wrong_value = Felt::from(999u64);
        let values = vec![Bytes::from(wrong_value.to_bytes_be().to_vec())];
        let proof_nodes = vec![Bytes::from(encoded)];

        let result = verify_storage_proof(&state_root, &keys, &values, &proof_nodes);
        assert!(result.is_err(), "should fail with wrong value");
    }
}
