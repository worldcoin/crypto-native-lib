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
char *generate_nullifier_hash(struct CIdentity *identity, const char *external_nullifier);

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
                                     const char *external_nullifier,
                                     const char *signal,
                                     struct CMerkleProofPoseidonHash *merkle_proof,
                                     const char *zkey_path,
                                     const char *wasm_path);

/**
 * Verifies semaphore proof
 */
int verify_proof(const char *root,
                 const char *external_nullifier,
                 const char *signal,
                 const char *nullifier,
                 struct CGroth16Proof *proof,
                 const char *zkey_path,
                 const char *wasm_path);
