use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug)]
struct NixDerivation {
    pub name: String,
    pub path: String,
    pub inputs: Vec<String>,
    pub outputs: HashMap<String, String>,
    pub system: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct SparseMerkleNode {
    pub hash: String,
    pub left: Option<Box<SparseMerkleNode>>,
    pub right: Option<Box<SparseMerkleNode>>,
}

struct DerivationHasher {
    merkle_tree: Option<SparseMerkleNode>,
}

impl DerivationHasher {
    fn new() -> Self {
        Self {
            merkle_tree: None,
        }
    }
    
    fn hash_derivation(&self, derivation: &NixDerivation) -> String {
        let mut hasher = Sha256::new();
        
        // Hash derivation components in deterministic order
        hasher.update(derivation.name.as_bytes());
        hasher.update(derivation.path.as_bytes());
        hasher.update(derivation.system.as_bytes());
        
        // Hash inputs
        let mut inputs = derivation.inputs.clone();
        inputs.sort();
        for input in inputs {
            hasher.update(input.as_bytes());
        }
        
        // Hash outputs
        let mut outputs: Vec<_> = derivation.outputs.iter().collect();
        outputs.sort_by_key(|&(k, _)| k);
        for (key, value) in outputs {
            hasher.update(key.as_bytes());
            hasher.update(value.as_bytes());
        }
        
        hex::encode(hasher.finalize())
    }
    
    fn build_sparse_merkle_tree(&mut self, derivations: &[NixDerivation]) -> Result<String, String> {
        if derivations.is_empty() {
            return Err("No derivations provided".to_string());
        }
        
        // Hash all derivations
        let mut hashes: Vec<String> = derivations
            .iter()
            .map(|d| self.hash_derivation(d))
            .collect();
        
        // Build binary tree bottom-up
        while hashes.len() > 1 {
            let mut next_level = Vec::new();
            
            for chunk in hashes.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(chunk[0].as_bytes());
                
                if chunk.len() > 1 {
                    hasher.update(chunk[1].as_bytes());
                } else {
                    // Odd number of nodes, hash with itself
                    hasher.update(chunk[0].as_bytes());
                }
                
                next_level.push(hex::encode(hasher.finalize()));
            }
            
            hashes = next_level;
        }
        
        Ok(hashes[0].clone())
    }
    
    fn verify_derivation_integrity(&self, derivation: &NixDerivation, expected_hash: &str) -> bool {
        let computed_hash = self.hash_derivation(derivation);
        computed_hash == expected_hash
    }
}

fn main() {
    println!("BlocksenseOS Derivation Hasher v0.1.0");
    println!("Sparse Merkle Tree generator for Nix derivations");
    
    let hasher = DerivationHasher::new();
    
    // Example derivations
    let sample_derivations = vec![
        NixDerivation {
            name: "hello-2.12".to_string(),
            path: "/nix/store/abc123-hello-2.12".to_string(),
            inputs: vec!["/nix/store/def456-glibc".to_string()],
            outputs: {
                let mut map = HashMap::new();
                map.insert("out".to_string(), "/nix/store/abc123-hello-2.12".to_string());
                map
            },
            system: "x86_64-linux".to_string(),
        },
        NixDerivation {
            name: "gcc-11.3.0".to_string(),
            path: "/nix/store/ghi789-gcc-11.3.0".to_string(),
            inputs: vec!["/nix/store/def456-glibc".to_string()],
            outputs: {
                let mut map = HashMap::new();
                map.insert("out".to_string(), "/nix/store/ghi789-gcc-11.3.0".to_string());
                map
            },
            system: "x86_64-linux".to_string(),
        },
    ];
    
    // Hash individual derivations
    for derivation in &sample_derivations {
        let hash = hasher.hash_derivation(derivation);
        println!("Derivation {} hash: {}", derivation.name, hash);
    }
    
    // Build Merkle tree
    let mut tree_hasher = DerivationHasher::new();
    match tree_hasher.build_sparse_merkle_tree(&sample_derivations) {
        Ok(root_hash) => println!("Merkle tree root hash: {}", root_hash),
        Err(e) => println!("Error building Merkle tree: {}", e),
    }
}