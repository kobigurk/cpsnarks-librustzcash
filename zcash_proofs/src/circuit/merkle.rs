//! The Sapling circuits.

use ff::{Field, PrimeField, PrimeFieldRepr};

use bellman::{Circuit, ConstraintSystem, SynthesisError};

use zcash_primitives::jubjub::{FixedGenerators, JubjubEngine};

use zcash_primitives::constants;

use zcash_primitives::primitives::{PaymentAddress, ProofGenerationKey, ValueCommitment};

use super::ecc;
use super::pedersen_hash;
use bellman::gadgets::blake2s;
use bellman::gadgets::boolean;
use bellman::gadgets::multipack;
use bellman::gadgets::num;
use bellman::gadgets::Assignment;

pub const TREE_DEPTH: usize = zcash_primitives::sapling::SAPLING_COMMITMENT_TREE_DEPTH;

/// This is an instance of the `Spend` circuit.
pub struct MerklePedersen<'a, E: JubjubEngine> {
    pub params: &'a E::Params,

    /// The leaf
    pub leaf: Option<E::Fr>,

    /// The authentication path of the commitment in the tree
    pub auth_path: Vec<Option<(E::Fr, bool)>>,

    /// The anchor; the root of the tree. If the note being
    /// spent is zero-value, this can be anything.
    pub anchor: Option<E::Fr>,
}

impl<'a, E: JubjubEngine> Circuit<E> for MerklePedersen<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {

        let cm = num::AllocatedNum::alloc(cs.namespace(|| "leaf"), || Ok(self.leaf.get()?.clone()))?;

        // This will store (least significant bit first)
        // the position of the note in the tree, for use
        // in nullifier computation.
        let mut position_bits = vec![];

        // This is an injective encoding, as cur is a
        // point in the prime order subgroup.
        let mut cur = cm.clone();

        // Ascend the merkle tree authentication path
        for (i, e) in self.auth_path.into_iter().enumerate() {
            let cs = &mut cs.namespace(|| format!("merkle tree hash {}", i));

            // Determines if the current subtree is the "right" leaf at this
            // depth of the tree.
            let cur_is_right = boolean::Boolean::from(boolean::AllocatedBit::alloc(
                cs.namespace(|| "position bit"),
                e.map(|e| e.1),
            )?);

            // Push this boolean for nullifier computation later
            position_bits.push(cur_is_right.clone());

            // Witness the authentication path element adjacent
            // at this depth.
            let path_element =
                num::AllocatedNum::alloc(cs.namespace(|| "path element"), || Ok(e.get()?.0))?;

            // Swap the two if the current subtree is on the right
            let (xl, xr) = num::AllocatedNum::conditionally_reverse(
                cs.namespace(|| "conditional reversal of preimage"),
                &cur,
                &path_element,
                &cur_is_right,
            )?;

            // We don't need to be strict, because the function is
            // collision-resistant. If the prover witnesses a congruency,
            // they will be unable to find an authentication path in the
            // tree with high probability.
            let mut preimage = vec![];
            preimage.extend(xl.to_bits_le(cs.namespace(|| "xl into bits"))?);
            preimage.extend(xr.to_bits_le(cs.namespace(|| "xr into bits"))?);

            // Compute the new subtree value
            cur = pedersen_hash::pedersen_hash(
                cs.namespace(|| "computation of pedersen hash"),
                pedersen_hash::Personalization::MerkleTree(i),
                &preimage,
                self.params,
            )?
            .get_x()
            .clone(); // Injective encoding
        }

        {
            let real_anchor_value = self.anchor;

            // Allocate the "real" anchor that will be exposed.
            let rt = num::AllocatedNum::alloc(cs.namespace(|| "conditional anchor"), || {
                Ok(*real_anchor_value.get()?)
            })?;

            // (cur - rt) * value = 0
            // if value is zero, cur and rt can be different
            // if value is nonzero, they must be equal
            cs.enforce(
                || "enforce correct root",
                |lc| lc + cur.get_variable(),
                |lc| lc + rt.get_variable(),
                |lc| lc,
            );

            // Expose the anchor
            rt.inputize(cs.namespace(|| "anchor"))?;
        }

        Ok(())
    }
}

#[test]
fn test_input_circuit_with_bls12_381() {
    use bellman::gadgets::test::*;
    use ff::{BitIterator, Field};
    use pairing::bls12_381::*;
    use rand_core::{RngCore, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use zcash_primitives::{
        jubjub::{edwards, fs, JubjubBls12},
        pedersen_hash,
        primitives::{Diversifier, Note, ProofGenerationKey},
    };

    let params = &JubjubBls12::new();
    let rng = &mut XorShiftRng::from_seed([
        0x58, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let tree_depth = 32;

    for _ in 0..10 {
        let auth_path = vec![Some((Fr::random(rng), rng.next_u32() % 2 != 0)); tree_depth];

        {
            let mut position = 0u64;
            let cm: Fr = Fr::random(rng);
            let mut cur = cm.clone();

            for (i, val) in auth_path.clone().into_iter().enumerate() {
                let (uncle, b) = val.unwrap();

                let mut lhs = cur;
                let mut rhs = uncle;

                if b {
                    ::std::mem::swap(&mut lhs, &mut rhs);
                }

                let mut lhs: Vec<bool> = BitIterator::new(lhs.into_repr()).collect();
                let mut rhs: Vec<bool> = BitIterator::new(rhs.into_repr()).collect();

                lhs.reverse();
                rhs.reverse();

                cur = pedersen_hash::pedersen_hash::<Bls12, _>(
                    pedersen_hash::Personalization::MerkleTree(i),
                    lhs.into_iter()
                        .take(Fr::NUM_BITS as usize)
                        .chain(rhs.into_iter().take(Fr::NUM_BITS as usize)),
                    params,
                )
                .to_xy()
                .0;

                if b {
                    position |= 1 << i;
                }
            }

            let mut cs = TestConstraintSystem::<Bls12>::new();

            let instance = MerklePedersen {
                params,
                leaf: Some(cm.clone()),
                auth_path: auth_path.clone(),
                anchor: Some(cur),
            };

            instance.synthesize(&mut cs).unwrap();
        }
    }
}
