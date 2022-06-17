use std::{
    ffi::{CStr, CString},
    os::raw::{c_char, c_int},
    str::FromStr,
};

use semaphore::{
    identity::Identity,
    merkle_tree::{self},
    poseidon_tree::{Branch, PoseidonHash, PoseidonTree},
    protocol::{self},
    Field,
};

use rand_chacha::{ChaChaRng, rand_core::SeedableRng};

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
    CString::new(format!("{:#04x}", identity.0.commitment()))
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

    let field = protocol::generate_nullifier_hash(&identity.0, external_nullifier_hash);

    CString::new(format!("{:#04x}", field)).unwrap().into_raw()
}

/// Hashes a byte string (given as hex) to the field
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn hash_bytes_to_field(hex_str: *const c_char) -> *mut c_char {
    let c_str = unsafe { CStr::from_ptr(hex_str) };
    let hex_str = match c_str.to_str() {
        Err(_) => "there",
        Ok(string) => string,
    };
    let input = hex::decode(hex_str.replace("0x", "")).unwrap();
    let field = semaphore::hash_to_field(&input);

    CString::new(format!("{:#04x}", field)).unwrap().into_raw()
}

/// Hashes a given string to the field
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn hash_string_to_field(input_str: *const c_char) -> *mut c_char {
    let c_str = unsafe { CStr::from_ptr(input_str) };
    let input_str = match c_str.to_str() {
        Err(_) => "there",
        Ok(string) => string,
    };
    let field = semaphore::hash_to_field(input_str.as_bytes());

    CString::new(format!("{:#04x}", field)).unwrap().into_raw()
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
    signal_hash: *const c_char,
    merkle_proof: *mut CMerkleProofPoseidonHash,
) -> *mut CGroth16Proof {
    let c_str = unsafe { CStr::from_ptr(external_nullifier_hash) };
    let external_nullifier_hash = match c_str.to_str() {
        Err(_) => "there",
        Ok(string) => string,
    };
    let external_nullifier_hash =
        Field::from_str(external_nullifier_hash).expect("parse as field element");

    let c_str = unsafe { CStr::from_ptr(signal_hash) };
    let signal_hash = match c_str.to_str() {
        Err(_) => "there",
        Ok(string) => string,
    };
    let signal_hash = Field::from_str(signal_hash).expect("parse as field element");

    let identity = &*identity;
    let merkle_proof = &*merkle_proof;

    let mut rng = ChaChaRng::seed_from_u64(123_u64);

    let res = protocol::generate_proof_rng(
        &identity.0,
        &merkle_proof.0,
        external_nullifier_hash,
        signal_hash,
        &mut rng
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
    signal_hash: *const c_char,
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

    let c_str = unsafe { CStr::from_ptr(signal_hash) };
    let signal_hash = match c_str.to_str() {
        Err(_) => "there",
        Ok(string) => string,
    };
    let signal_hash = Field::from_str(signal_hash).expect("parse as field element");

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
    let boxed: Box<CMerkleProofPoseidonHash> = Box::new(CMerkleProofPoseidonHash(
        merkle_tree::Proof::<PoseidonHash>(tmp),
    ));
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

/// Encode groth16 proof packed
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn encode_proof_packed(proof: *mut CGroth16Proof) -> *const c_char {
    let proof = &*proof;
    let packed_proof = protocol::PackedProof::from(proof.0);

    CString::new(format!("{}", packed_proof))
        .unwrap()
        .into_raw()
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::{CStr, CString},
        str::FromStr,
    };

    use semaphore::{identity::{Identity, self}, Field};

    use crate::{
        deserialize_merkle_proof, generate_identity_commitment, generate_nullifier_hash,
        generate_proof, hash_bytes_to_field, new_identity, verify_proof, serialize_groth16_proof, encode_proof_packed,
    };

    #[test]
    fn generate_id_comm() {
        let id_comm_string = unsafe {
            let seed = CString::new("b3e52543571b7a98d004f2eedc431c40a7be7454f39187394b211a4da1d3f5b6").unwrap().into_raw();

            let identity_ptr = new_identity(seed);
            let id_comm = generate_identity_commitment(identity_ptr);
            let id_comm_ptr = CStr::from_ptr(id_comm);
            let id_comm_string = id_comm_ptr.to_str().unwrap();
            id_comm_string
        };

        println!("{}", id_comm_string);
        assert_eq!(
            format!("{}", id_comm_string),
            "0x2405c7f5f0563769cf09f3e5806857109de43524bb0e52ba505fafcfd1871347"
        );
    }

    /// tests proof generation e2e
    /// IMPORTANT: remove features = ["dylib"] from semaphore to run this test
    #[test]
    fn e2e_test() {
        let merkle_root_str = "0x01d0f8b71395e5034e75a10a28cd709216122e0bb8330a0ed55ea6966ecd9638";

        let merkle_root = unsafe {
            CString::new(merkle_root_str)
                .unwrap()
                .into_raw()
        };

        let merkle_proof = unsafe {
            let merkle_proof_json = r#"[{"Right":"0x21a8624a88ce1f4323f45482c35d0a3b277984dadf6219b4e2f619eaa1dbd530"},{"Left":"0x18f3dbd815405e2cbf3a0a9501d926762e39331734bf5797735f17ad7ceee1cf"},{"Left":"0x1069673dcdb12263df301a6ff584a7ec261a44cb9dc68df067a4774460b1f1e1"},{"Left":"0x18f43331537ee2af2e3d758d50f72106467c6eea50371dd528d57eb2b856d238"},{"Left":"0x07f9d837cb17b0d36320ffe93ba52345f1b728571a568265caac97559dbc952a"},{"Right":"0x1ab79cd3da4e4aaf07537789afba5ad7bcc11cd590f2ac262e56e9fa187fff66"},{"Left":"0x2dee93c5a666459646ea7d22cca9e1bcfed71e6951b953611d11dda32ea09d78"},{"Right":"0x276723e66059167837e3d20d1fd74202af8e17603ed7ea8087b543a16922d3f6"},{"Right":"0x0b9851a0ec93192e67da6e9367e69727323729411449818918b141f30e50da39"},{"Right":"0x207732400560e94e5ef329a7da2998db6af43bf4c092a7efc6b38545c15d67a2"},{"Left":"0x1b7201da72494f1e28717ad1a52eb469f95892f957713533de6175e5da190af2"},{"Right":"0x0127a3b78cd00628d626feb777db866ab147f78fdc13d8c8d42ad098827f9a9e"},{"Left":"0x2c5d82f66c914bafb9701589ba8cfcfb6162b0a12acf88a8d0879a0471b5f85a"},{"Left":"0x14c54148a0940bb820957f5adf3fa1134ef5c4aaa113f4646458f270e0bfbfd0"},{"Left":"0x190d33b12f986f961e10c0ee44d8b9af11be25588cad89d416118e4bf4ebe80c"},{"Left":"0x22f98aa9ce704152ac17354914ad73ed1167ae6596af510aa5b3649325e06c92"},{"Left":"0x2a7c7c9b6ce5880b9f6f228d72bf6a575a526f29c66ecceef8b753d38bba7323"},{"Left":"0x2e8186e558698ec1c67af9c14d463ffc470043c9c2988b954d75dd643f36b992"},{"Left":"0x0f57c5571e9a4eab49e2c8cf050dae948aef6ead647392273546249d1c1ff10f"},{"Left":"0x1830ee67b5fb554ad5f63d4388800e1cfe78e310697d46e43c9ce36134f72cca"}]"#;
            let merkle_proof_str = CString::new(merkle_proof_json).unwrap().into_raw();
            deserialize_merkle_proof(merkle_proof_str)
        };

        let identity = unsafe {
            let seed = CString::new("b3e52543571b7a98d004f2eedc431c40a7be7454f39187394b211a4da1d3f5b6").unwrap().into_raw();
            new_identity(seed)
        };

        let identity_commitment = unsafe {
            let id_comm = generate_identity_commitment(identity);
            let id_comm_ptr = CStr::from_ptr(id_comm);
            let id_comm_string = id_comm_ptr.to_str().unwrap();
            id_comm_string
        };

        let external_nullifier_hash = unsafe {
            CString::new("0x00a27dda6d4ad38f3fdbdee6f7e87312778d1037bfcb4281da1a5c1e504c5b13")
                .unwrap()
                .into_raw()
        };

        let signal_hash = unsafe {
            // let signal = CString::new("0x00a7465675d40ad7266f797cc68056c39699ccda8c1e9e0d79c2e016d5fdb01f").unwrap().into_raw();
            CString::new("0x008952e32c69f70d214dd9c3960cc51bfe0789d0c51f4cfbb8d2863bdbc1c1f7").unwrap().into_raw()
            // hash_bytes_to_field(signal)
            
        };

        let proof =
            unsafe { generate_proof(identity, external_nullifier_hash, signal_hash, merkle_proof) };

        let nullifier = unsafe { generate_nullifier_hash(identity, external_nullifier_hash) };

        let nullifier_str = unsafe {
            let nullifier_ptr = CStr::from_ptr(nullifier);
            nullifier_ptr.to_str().unwrap()
        };

        let result = unsafe {
            verify_proof(
                merkle_root,
                external_nullifier_hash,
                signal_hash,
                nullifier,
                proof,
            )
        };

        // the proof needs to verify 
        assert_eq!(
            result,
            1
        );

        let serialized_proof = unsafe {
            let json = serialize_groth16_proof(proof);
            let json_ptr = CStr::from_ptr(json);
            let json_string = json_ptr.to_str().unwrap();
            format!("[{}]", json_string.replace("[", "").replace("]", ""))
        };

        println!("id: {}\nroot: {}\nnullifierHash: {}\nproof: {}", identity_commitment, merkle_root_str, nullifier_str, serialized_proof);

        let packed_proof = unsafe { 
            let packed_proof = encode_proof_packed(proof);
            let packed_proof = CStr::from_ptr(packed_proof);
            packed_proof.to_str().unwrap()
        };

        println!("{}", packed_proof)

    }
}
