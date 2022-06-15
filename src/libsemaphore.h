// NOTE: autogenerated code - do not modify

typedef struct CGroth16Proof CGroth16Proof;

typedef struct CIdentity CIdentity;

typedef struct CMerkleProofPoseidonHash CMerkleProofPoseidonHash;

typedef struct CPoseidonTree CPoseidonTree;

/**
 * Creates a new idenity and returns the object
 */
struct CIdentity *new_identity(const char *seed);

/**
 * Generates the identity commitment based on seed for identity
 */
char *generate_identity_commitment(struct CIdentity *identity);

/**
 * Generates nullifier hash based on identity and external nullifier
 */
char *generate_nullifier_hash(struct CIdentity *identity, const char *external_nullifier_hash);

/**
 * Generates nullifier hash based on identity and external nullifier
 */
char *hash_to_field(const char *input_str);

/**
 * Initializes new poseidon tree of given depth
 */
struct CPoseidonTree *create_poseidon_tree(int depth);

/**
 * Insert leaf into given poseidon tree
 */
void insert_leaf(struct CPoseidonTree *tree, struct CIdentity *identity);

/**
 * Returns root for given tree
 */
char *get_root(struct CPoseidonTree *tree);

/**
 * Generates merkle proof for given leaf index
 */
struct CMerkleProofPoseidonHash *get_merkle_proof(struct CPoseidonTree *tree, int leaf_idx);

/**
 * Generates semaphore proof
 */
struct CGroth16Proof *generate_proof(struct CIdentity *identity,
                                     const char *external_nullifier_hash,
                                     const char *signal_hash,
                                     struct CMerkleProofPoseidonHash *merkle_proof);

/**
 * Verifies semaphore proof
 */
int verify_proof(const char *root,
                 const char *external_nullifier_hash,
                 const char *signal_hash,
                 const char *nullifier,
                 struct CGroth16Proof *proof);

/**
 * Deserialize merkle proof
 */
struct CMerkleProofPoseidonHash *deserialize_merkle_proof(const char *json);

/**
 * Serialize groth16 proof
 */
const char *serialize_groth16_proof(struct CGroth16Proof *proof);

/**
 * Encode groth16 proof packed
 */
const char *encode_proof_packed(struct CGroth16Proof *proof);

/**
 * Initializes the witness generator path (only needed on iOS for the dylib
 * path)
 */
void init_witness_generator_path(const char *path);
