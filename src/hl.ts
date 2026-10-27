/**
 * The @harmoniclabs/crypto primitives the Mithril verifier uses, imported from their own modules
 * rather than the package index: the package is CommonJS, so importing the index bundles every
 * algorithm (secp256k1, VRF, KES, ...) into a browser bundle; these six modules keep it about 110 KB
 * smaller. If a future version moves these files, only this module changes.
 */

export {
    BlsG1,
    BlsG2,
    bls12_381_G1_add,
    bls12_381_G1_compress,
    bls12_381_G1_equal,
    bls12_381_G1_hashToGroup,
    bls12_381_G1_scalarMul,
    bls12_381_G1_uncompress,
    bls12_381_G2_add,
    bls12_381_G2_compress,
    bls12_381_G2_equal,
    bls12_381_G2_scalarMul,
    bls12_381_G2_uncompress,
    bls12_381_finalVerify,
    bls12_381_millerLoop,
} from "@harmoniclabs/crypto/dist/bls12_318.js";
export { blake2b, blake2b_256 } from "@harmoniclabs/crypto/dist/blake2b.js";
export { sha2_256, sha2_256_sync } from "@harmoniclabs/crypto/dist/sha2_256.js";
export { sha2_512_sync } from "@harmoniclabs/crypto/dist/sha2_512.js";
export { decodeBech32 } from "@harmoniclabs/crypto/dist/bech32.js";
export { addPointsEdwards, pointFromBytes, scalarMul, scalarMultBase, type bigpoint } from "@harmoniclabs/crypto/dist/ed25519.js";
