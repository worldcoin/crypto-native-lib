use std::{
    ffi::{CStr, CString},
    os::raw::{c_char, c_int},
    path::Path,
    str::FromStr,
};

use semaphore::{
    identity::Identity,
    merkle_tree::{self},
    poseidon_tree::{Branch, PoseidonHash, PoseidonTree},
    protocol::{self},
    Field,
};

// wrap all types for cbindgen
pub struct CIdentity(Identity);
pub struct CPoseidonTree(PoseidonTree);
pub struct CMerkleProofPoseidonHash(merkle_tree::Proof<PoseidonHash>);
pub struct CGroth16Proof(protocol::Proof);

/// Creates a new idenity and returns the object
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn new_identity(
    secret: *const c_char,
    context: *const c_char,
) -> *mut CIdentity {
    let c_str = unsafe { CStr::from_ptr(secret) };
    let seed = match c_str.to_str() {
        Err(_) => "there",
        Ok(string) => string,
    };

    let trapdoor_seed = if context.is_null() {
        None
    } else {
        let c_str = unsafe { CStr::from_ptr(context) };
        Some(c_str.to_bytes())
    };

    let id = Identity::from_secret(seed.as_bytes(), trapdoor_seed);

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

/// Hashes a byte string (given as hex) to the field
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn hash_bytes_to_field_safe(hex_str: &str) -> Result<*mut c_char, String> {
    let input = match hex::decode(hex_str.replace("0x", "")) {
        Ok(decoded) => decoded,
        Err(e) => return Err(format!("Hex decode error: {}, for input value: {}", e, hex_str)),
    };

    let field = semaphore::hash_to_field(&input);
    let field_hex = format!("{:#04x}", field);
    let c_string = CString::new(field_hex).unwrap();
    let c_string_ptr = c_string.into_raw();

    Ok(c_string_ptr)
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
        30,
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
        str::FromStr, ptr::null,
    };

    use semaphore::{
        identity::{self, Identity},
        Field,
    };

    use crate::{
        deserialize_merkle_proof, generate_identity_commitment, generate_nullifier_hash,
        generate_proof, hash_bytes_to_field, new_identity, serialize_groth16_proof, verify_proof,
    };

    #[test]
    fn generate_id_comm() {
        let id_comm_string = unsafe {
            let seed = CString::new("hello_xxx").unwrap().into_raw();
            let context = CString::new("test").unwrap().into_raw();

            let identity_ptr = new_identity(seed, null());
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
    #[test]
    fn e2e_test_no_context() {
        let merkle_root_str = "0x15ead02f920ab50a28f420953b0ea1336685fe98015ab3e382c3365624235012";

        let merkle_root = unsafe { CString::new(merkle_root_str).unwrap().into_raw() };

        let merkle_proof = unsafe {
            let merkle_proof_json = r#"[{"Left":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"Left":"0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864"},{"Left":"0x1069673dcdb12263df301a6ff584a7ec261a44cb9dc68df067a4774460b1f1e1"},{"Left":"0x18f43331537ee2af2e3d758d50f72106467c6eea50371dd528d57eb2b856d238"},{"Left":"0x07f9d837cb17b0d36320ffe93ba52345f1b728571a568265caac97559dbc952a"},{"Left":"0x2b94cf5e8746b3f5c9631f4c5df32907a699c58c94b2ad4d7b5cec1639183f55"},{"Left":"0x2dee93c5a666459646ea7d22cca9e1bcfed71e6951b953611d11dda32ea09d78"},{"Left":"0x078295e5a22b84e982cf601eb639597b8b0515a88cb5ac7fa8a4aabe3c87349d"},{"Left":"0x2fa5e5f18f6027a6501bec864564472a616b2e274a41211a444cbe3a99f3cc61"},{"Left":"0x0e884376d0d8fd21ecb780389e941f66e45e7acce3e228ab3e2156a614fcd747"},{"Left":"0x1b7201da72494f1e28717ad1a52eb469f95892f957713533de6175e5da190af2"},{"Left":"0x1f8d8822725e36385200c0b201249819a6e6e1e4650808b5bebc6bface7d7636"},{"Left":"0x2c5d82f66c914bafb9701589ba8cfcfb6162b0a12acf88a8d0879a0471b5f85a"},{"Left":"0x14c54148a0940bb820957f5adf3fa1134ef5c4aaa113f4646458f270e0bfbfd0"},{"Left":"0x190d33b12f986f961e10c0ee44d8b9af11be25588cad89d416118e4bf4ebe80c"},{"Left":"0x22f98aa9ce704152ac17354914ad73ed1167ae6596af510aa5b3649325e06c92"},{"Left":"0x2a7c7c9b6ce5880b9f6f228d72bf6a575a526f29c66ecceef8b753d38bba7323"},{"Left":"0x2e8186e558698ec1c67af9c14d463ffc470043c9c2988b954d75dd643f36b992"},{"Left":"0x0f57c5571e9a4eab49e2c8cf050dae948aef6ead647392273546249d1c1ff10f"},{"Left":"0x1830ee67b5fb554ad5f63d4388800e1cfe78e310697d46e43c9ce36134f72cca"},{"Left":"0x2134e76ac5d21aab186c2be1dd8f84ee880a1e46eaf712f9d371b6df22191f3e"},{"Left":"0x19df90ec844ebc4ffeebd866f33859b0c051d8c958ee3aa88f8f8df3db91a5b1"},{"Left":"0x18cca2a66b5c0787981e69aefd84852d74af0e93ef4912b4648c05f722efe52b"},{"Left":"0x2388909415230d1b4d1304d2d54f473a628338f2efad83fadf05644549d2538d"},{"Left":"0x27171fb4a97b6cc0e9e8f543b5294de866a2af2c9c8d0b1d96e673e4529ed540"},{"Left":"0x2ff6650540f629fd5711a0bc74fc0d28dcb230b9392583e5f8d59696dde6ae21"},{"Left":"0x120c58f143d491e95902f7f5277778a2e0ad5168f6add75669932630ce611518"},{"Left":"0x1f21feb70d3f21b07bf853d5e5db03071ec495a0a565a21da2d665d279483795"},{"Left":"0x24be905fa71335e14c638cc0f66a8623a826e768068a9e968bb1a1dde18a72d2"},{"Left":"0x0f8666b62ed17491c50ceadead57d4cd597ef3821d65c328744c74e553dac26d"}]"#;
            let merkle_proof_str = CString::new(merkle_proof_json).unwrap().into_raw();
            deserialize_merkle_proof(merkle_proof_str)
        };

        let identity = unsafe {
            let seed = CString::new("hello_xxx").unwrap().into_raw();
            let context = CString::new("test").unwrap().into_raw();
            new_identity(seed, null())
        };

        let identity_commitment = unsafe {
            let id_comm = generate_identity_commitment(identity);
            let id_comm_ptr = CStr::from_ptr(id_comm);
            let id_comm_string = id_comm_ptr.to_str().unwrap();
            id_comm_string
        };

        println!("{}", identity_commitment);

        let external_nullifier_hash = unsafe {
            CString::new("0x0046a9ddb149db600304d000ce3a3cfabde52070ae4b77504e17af77eeb6011e")
                .unwrap()
                .into_raw()
        };

        let signal_hash = unsafe {
            let signal = CString::new("8d9a83E7654083F1ed763bBd5D76B5848b05Dc28")
                .unwrap()
                .into_raw();
            hash_bytes_to_field(signal)
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
        assert_eq!(result, 1);

        let serialized_proof = unsafe {
            let json = serialize_groth16_proof(proof);
            let json_ptr = CStr::from_ptr(json);
            let json_string = json_ptr.to_str().unwrap();
            format!("[{}]", json_string.replace("[", "").replace("]", ""))
        };

        println!(
            "id: {}\nroot: {}\nnullifierHash: {}\nproof: {}",
            identity_commitment, merkle_root_str, nullifier_str, serialized_proof
        );
    }

    #[test]
    fn e2e_test_with_context() {
        let merkle_root_str = "0x0552aa7e00eae631630067737f9f2f885918ab0029ec2f48db3af6d7967ed463";

        let merkle_root = unsafe { CString::new(merkle_root_str).unwrap().into_raw() };

        let merkle_proof = unsafe {
            let merkle_proof_json = r#"[{"Left":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"Left":"0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864"},{"Left":"0x1069673dcdb12263df301a6ff584a7ec261a44cb9dc68df067a4774460b1f1e1"},{"Left":"0x18f43331537ee2af2e3d758d50f72106467c6eea50371dd528d57eb2b856d238"},{"Left":"0x07f9d837cb17b0d36320ffe93ba52345f1b728571a568265caac97559dbc952a"},{"Left":"0x2b94cf5e8746b3f5c9631f4c5df32907a699c58c94b2ad4d7b5cec1639183f55"},{"Left":"0x2dee93c5a666459646ea7d22cca9e1bcfed71e6951b953611d11dda32ea09d78"},{"Left":"0x078295e5a22b84e982cf601eb639597b8b0515a88cb5ac7fa8a4aabe3c87349d"},{"Left":"0x2fa5e5f18f6027a6501bec864564472a616b2e274a41211a444cbe3a99f3cc61"},{"Left":"0x0e884376d0d8fd21ecb780389e941f66e45e7acce3e228ab3e2156a614fcd747"},{"Left":"0x1b7201da72494f1e28717ad1a52eb469f95892f957713533de6175e5da190af2"},{"Left":"0x1f8d8822725e36385200c0b201249819a6e6e1e4650808b5bebc6bface7d7636"},{"Left":"0x2c5d82f66c914bafb9701589ba8cfcfb6162b0a12acf88a8d0879a0471b5f85a"},{"Left":"0x14c54148a0940bb820957f5adf3fa1134ef5c4aaa113f4646458f270e0bfbfd0"},{"Left":"0x190d33b12f986f961e10c0ee44d8b9af11be25588cad89d416118e4bf4ebe80c"},{"Left":"0x22f98aa9ce704152ac17354914ad73ed1167ae6596af510aa5b3649325e06c92"},{"Left":"0x2a7c7c9b6ce5880b9f6f228d72bf6a575a526f29c66ecceef8b753d38bba7323"},{"Left":"0x2e8186e558698ec1c67af9c14d463ffc470043c9c2988b954d75dd643f36b992"},{"Left":"0x0f57c5571e9a4eab49e2c8cf050dae948aef6ead647392273546249d1c1ff10f"},{"Left":"0x1830ee67b5fb554ad5f63d4388800e1cfe78e310697d46e43c9ce36134f72cca"},{"Left":"0x2134e76ac5d21aab186c2be1dd8f84ee880a1e46eaf712f9d371b6df22191f3e"},{"Left":"0x19df90ec844ebc4ffeebd866f33859b0c051d8c958ee3aa88f8f8df3db91a5b1"},{"Left":"0x18cca2a66b5c0787981e69aefd84852d74af0e93ef4912b4648c05f722efe52b"},{"Left":"0x2388909415230d1b4d1304d2d54f473a628338f2efad83fadf05644549d2538d"},{"Left":"0x27171fb4a97b6cc0e9e8f543b5294de866a2af2c9c8d0b1d96e673e4529ed540"},{"Left":"0x2ff6650540f629fd5711a0bc74fc0d28dcb230b9392583e5f8d59696dde6ae21"},{"Left":"0x120c58f143d491e95902f7f5277778a2e0ad5168f6add75669932630ce611518"},{"Left":"0x1f21feb70d3f21b07bf853d5e5db03071ec495a0a565a21da2d665d279483795"},{"Left":"0x24be905fa71335e14c638cc0f66a8623a826e768068a9e968bb1a1dde18a72d2"},{"Left":"0x0f8666b62ed17491c50ceadead57d4cd597ef3821d65c328744c74e553dac26d"}]"#;
            let merkle_proof_str = CString::new(merkle_proof_json).unwrap().into_raw();
            deserialize_merkle_proof(merkle_proof_str)
        };

        let identity = unsafe {
            let seed = CString::new("hello_xxx").unwrap().into_raw();
            let context = CString::new("test").unwrap().into_raw();
            new_identity(seed, context)
        };

        let identity_commitment = unsafe {
            let id_comm = generate_identity_commitment(identity);
            let id_comm_ptr = CStr::from_ptr(id_comm);
            let id_comm_string = id_comm_ptr.to_str().unwrap();
            id_comm_string
        };

        println!("{}", identity_commitment);

        let external_nullifier_hash = unsafe {
            CString::new("0x0046a9ddb149db600304d000ce3a3cfabde52070ae4b77504e17af77eeb6011e")
                .unwrap()
                .into_raw()
        };

        let signal_hash = unsafe {
            let signal = CString::new("8d9a83E7654083F1ed763bBd5D76B5848b05Dc28")
                .unwrap()
                .into_raw();
            hash_bytes_to_field(signal)
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
        assert_eq!(result, 1);

        let serialized_proof = unsafe {
            let json = serialize_groth16_proof(proof);
            let json_ptr = CStr::from_ptr(json);
            let json_string = json_ptr.to_str().unwrap();
            format!("[{}]", json_string.replace("[", "").replace("]", ""))
        };

        println!(
            "id: {}\nroot: {}\nnullifierHash: {}\nproof: {}",
            identity_commitment, merkle_root_str, nullifier_str, serialized_proof
        );
    }
}
