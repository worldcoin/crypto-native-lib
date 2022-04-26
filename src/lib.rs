use std::{
    ffi::{CStr, CString},
    os::raw::{c_char, c_int},
    str::FromStr,
};

use semaphore::{
    hash_to_field,
    identity::Identity,
    merkle_tree::{self},
    poseidon_tree::{Branch, PoseidonHash, PoseidonTree},
    protocol::{self},
    Field,
};

use num_bigint::BigInt;

// wrap all types for cbindgen
pub struct CIdentity(Identity);
pub struct CPoseidonTree(PoseidonTree);
pub struct CMerkleProofPoseidonHash(merkle_tree::Proof<PoseidonHash>);
pub struct CGroth16Proof(protocol::Proof);

/// Creates a new idenity and returns the object
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn new_identity(seed: *const c_char) -> *mut CIdentity {
    let c_str = unsafe { CStr::from_ptr(seed) };
    let seed = match c_str.to_str() {
        Err(_) => "there",
        Ok(string) => string,
    };
    let id = Identity::from_seed(seed.as_bytes());

    let boxed: Box<CIdentity> = Box::new(CIdentity(id));
    Box::into_raw(boxed)
}

/// Generates the identity commitment based on seed for identity
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn generate_identity_commitment(identity: *mut CIdentity) -> *mut c_char {
    let identity = &*identity;
    CString::new(identity.0.commitment().to_string())
        .unwrap()
        .into_raw()
}

/// Generates nullifier hash based on identity and external nullifier
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn generate_nullifier_hash(
    identity: *mut CIdentity,
    external_nullifier_hash: *const c_char,
) -> *mut c_char {
    let identity = &*identity;

    let c_str = unsafe { CStr::from_ptr(external_nullifier_hash) };
    let external_nullifier_hash = match c_str.to_str() {
        Err(_) => "there",
        Ok(string) => string,
    };
    let external_nullifier_hash =
        Field::from_str(external_nullifier_hash).expect("parse as field element");

    CString::new(
        protocol::generate_nullifier_hash(&identity.0, external_nullifier_hash).to_string(),
    )
    .unwrap()
    .into_raw()
}

/// Generates nullifier hash based on identity and external nullifier
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn hash_external_nullifier(external_nullifier: *const c_char) -> *mut c_char {
    let c_str = unsafe { CStr::from_ptr(external_nullifier) };
    let external_nullifier = match c_str.to_str() {
        Err(_) => "there",
        Ok(string) => string,
    };

    CString::new(hash_to_field(external_nullifier.as_bytes()).to_string())
        .unwrap()
        .into_raw()
}

/// Initializes new poseidon tree of given depth
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn create_poseidon_tree(depth: c_int) -> *mut CPoseidonTree {
    let leaf = Field::from(0);

    let tree = PoseidonTree::new(depth as usize, leaf);

    let boxed: Box<CPoseidonTree> = Box::new(CPoseidonTree(tree));
    Box::into_raw(boxed)
}

/// Insert leaf into given poseidon tree
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn insert_leaf(tree: *mut CPoseidonTree, identity: *mut CIdentity) {
    let identity = &*identity;
    let tree = unsafe {
        assert!(!tree.is_null());
        &mut *tree
    };

    tree.0.set(0, identity.0.commitment());
}

/// Returns root for given tree
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn get_root(tree: *mut CPoseidonTree) -> *mut c_char {
    let tree = unsafe {
        assert!(!tree.is_null());
        &mut *tree
    };

    CString::new(tree.0.root().to_string()).unwrap().into_raw()
}

/// Generates merkle proof for given leaf index
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn get_merkle_proof(
    tree: *mut CPoseidonTree,
    leaf_idx: c_int,
) -> *mut CMerkleProofPoseidonHash {
    let tree = unsafe {
        assert!(!tree.is_null());
        &mut *tree
    };

    let proof = tree.0.proof(leaf_idx as usize).expect("proof should exist");

    let boxed: Box<CMerkleProofPoseidonHash> = Box::new(CMerkleProofPoseidonHash(proof));
    Box::into_raw(boxed)
}

/// Generates semaphore proof
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn generate_proof(
    identity: *mut CIdentity,
    external_nullifier_hash: *const c_char,
    signal: *const c_char,
    merkle_proof: *mut CMerkleProofPoseidonHash,
) -> *mut CGroth16Proof {
    let c_str = unsafe { CStr::from_ptr(external_nullifier_hash) };
    let external_nullifier_hash = match c_str.to_str() {
        Err(_) => "there",
        Ok(string) => string,
    };
    let external_nullifier_hash =
        Field::from_str(external_nullifier_hash).expect("parse as field element");

    let c_str = unsafe { CStr::from_ptr(signal) };
    let signal = match c_str.to_str() {
        Err(_) => "there",
        Ok(string) => string,
    };

    let signal_hash = hash_to_field(hex::decode(signal).expect("decode signal as hex"));

    let identity = &*identity;
    let merkle_proof = &*merkle_proof;

    let res = protocol::generate_proof(
        &identity.0,
        &merkle_proof.0,
        external_nullifier_hash,
        signal_hash,
    );

    let boxed: Box<CGroth16Proof> = Box::new(CGroth16Proof(res.unwrap()));
    Box::into_raw(boxed)
}

/// Verifies semaphore proof
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn verify_proof(
    root: *const c_char,
    external_nullifier_hash: *const c_char,
    signal: *const c_char,
    nullifier: *const c_char,
    proof: *mut CGroth16Proof,
) -> c_int {
    let c_str = unsafe { CStr::from_ptr(root) };
    let root = match c_str.to_str() {
        Err(_) => "there",
        Ok(string) => string,
    };
    let root = Field::from_str(root).expect("parse as field element");

    let c_str = unsafe { CStr::from_ptr(external_nullifier_hash) };
    let external_nullifier_hash = match c_str.to_str() {
        Err(_) => "there",
        Ok(string) => string,
    };
    let external_nullifier_hash =
        Field::from_str(external_nullifier_hash).expect("parse as field element");

    let c_str = unsafe { CStr::from_ptr(signal) };
    let signal = match c_str.to_str() {
        Err(_) => "there",
        Ok(string) => string,
    };
    let signal_hash = hash_to_field(signal.as_bytes());

    let c_str = unsafe { CStr::from_ptr(nullifier) };
    let nullifier = match c_str.to_str() {
        Err(_) => "there",
        Ok(string) => string,
    };
    let nullifier = Field::from_str(nullifier).expect("parse as field element");

    let proof = &*proof;

    protocol::verify_proof(
        root,
        nullifier,
        signal_hash,
        external_nullifier_hash,
        &proof.0,
    )
    .unwrap() as i32
}

/// Deserialize merkle proof
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn deserialize_merkle_proof(
    json: *const c_char,
) -> *mut CMerkleProofPoseidonHash {
    let json = unsafe { CStr::from_ptr(json) };
    let json = match json.to_str() {
        Err(_) => "there",
        Ok(string) => string,
    };

    let tmp: Vec<Branch> = serde_json::from_str(json).unwrap();
    let boxed: Box<CMerkleProofPoseidonHash> =
        Box::new(CMerkleProofPoseidonHash(merkle_tree::Proof::<PoseidonHash>(tmp)));
    Box::into_raw(boxed)
}

/// Serialize groth16 proof
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn serialize_groth16_proof(proof: *mut CGroth16Proof) -> *const c_char {
    let proof = &*proof;
    let json = serde_json::to_string(&proof.0).unwrap();

    CString::new(json).unwrap().into_raw()
}

/// Initializes the witness generator path (only needed on iOS for the dylib path)
// #[no_mangle]
// #[allow(clippy::missing_safety_doc)]
// pub unsafe extern "C" fn init_witness_generator_path(path: *const c_char) {
//     let c_str = unsafe { CStr::from_ptr(path) };
//     let path = match c_str.to_str() {
//         Err(_) => "there",
//         Ok(string) => string,
//     };

//     circuit::WITNESS_CALCULATOR_DYLIB.set(path.to_string()).expect("init must only be called once");
// }

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
