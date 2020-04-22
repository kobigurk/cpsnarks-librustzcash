//! The "hybrid Sprout" circuit.
//!
//! "Hybrid Sprout" refers to the implementation of the [Sprout statement] in
//! `bellman` for [`groth16`], instead of the [original implementation][oldimpl]
//! using [`libsnark`] for [BCTV14].
//!
//! [Sprout statement]: https://zips.z.cash/protocol/protocol.pdf#joinsplitstatement
//! [`groth16`]: bellman::groth16
//! [oldimpl]: https://github.com/zcash/zcash/tree/v2.0.7/src/zcash/circuit
//! [`libsnark`]: https://github.com/scipr-lab/libsnark
//! [BCTV14]: https://eprint.iacr.org/2013/879

use bellman::gadgets::boolean::{AllocatedBit, Boolean};
use bellman::gadgets::multipack::pack_into_inputs;
use bellman::{Circuit, ConstraintSystem, LinearCombination, SynthesisError};
use bellman::gadgets::sha256::sha256_block_no_padding;
use ff::Field;
use pairing::Engine;

mod commitment;
mod input;
mod output;
mod prfs;


use self::input::*;
use self::output::*;

pub struct NoteValue {
    value: Option<u64>,
    // Least significant digit first
    bits: Vec<AllocatedBit>,
}

impl NoteValue {
    fn new<E, CS>(mut cs: CS, value: Option<u64>) -> Result<NoteValue, SynthesisError>
    where
        E: Engine,
        CS: ConstraintSystem<E>,
    {
        let mut values;
        match value {
            Some(mut val) => {
                values = vec![];
                for _ in 0..64 {
                    values.push(Some(val & 1 == 1));
                    val >>= 1;
                }
            }
            None => {
                values = vec![None; 64];
            }
        }

        let mut bits = vec![];
        for (i, value) in values.into_iter().enumerate() {
            bits.push(AllocatedBit::alloc(
                cs.namespace(|| format!("bit {}", i)),
                value,
            )?);
        }

        Ok(NoteValue { value, bits })
    }

    /// Encodes the bits of the value into little-endian
    /// byte order.
    fn bits_le(&self) -> Vec<Boolean> {
        self.bits
            .chunks(8)
            .flat_map(|v| v.iter().rev())
            .cloned()
            .map(Boolean::from)
            .collect()
    }

    /// Computes this value as a linear combination of
    /// its bits.
    fn lc<E: Engine>(&self) -> LinearCombination<E> {
        let mut tmp = LinearCombination::zero();

        let mut coeff = E::Fr::one();
        for b in &self.bits {
            tmp = tmp + (coeff, b.get_variable());
            coeff = coeff.double();
        }

        tmp
    }

    fn get_value(&self) -> Option<u64> {
        self.value
    }
}

pub struct SpendingKey(pub [u8; 32]);
pub struct PayingKey(pub [u8; 32]);
pub struct UniqueRandomness(pub [u8; 32]);
pub struct CommitmentRandomness(pub [u8; 32]);

#[derive(Clone)]
pub struct JoinSplit {
    pub inputs: Vec<JSInput>,
    pub rt: Option<[u8; 32]>,
}

#[derive(Clone)]
pub struct JSInput {
    pub leaf: Option<[u8; 32]>,
    pub auth_path: Vec<Option<([u8; 32], bool)>>,
}

impl<E: Engine> Circuit<E> for JoinSplit {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        assert_eq!(self.inputs.len(), 1);

        // Witness rt (merkle tree root)
        let rt = witness_u256(cs.namespace(|| "rt"), self.rt.as_ref().map(|v| &v[..])).unwrap();


        // Iterate over the JoinSplit inputs
        for (i, input) in self.inputs.into_iter().enumerate() {
            let cs = &mut cs.namespace(|| format!("input {}", i));
            let leaf = witness_u256(cs.namespace(|| "leaf"), input.leaf.as_ref().map(|v| &v[..])).unwrap();

            // Witness into the merkle tree
            let mut cur = leaf.clone();

            for (i, layer) in input.auth_path.iter().enumerate() {
                let cs = &mut cs.namespace(|| format!("layer {}", i));

                let cur_is_right = AllocatedBit::alloc(
                    cs.namespace(|| "cur is right"),
                    layer.as_ref().map(|&(_, p)| p),
                )?;

                let lhs = cur;
                let rhs = witness_u256(
                    cs.namespace(|| "sibling"),
                    layer.as_ref().map(|&(ref sibling, _)| &sibling[..]),
                )?;

                // Conditionally swap if cur is right
                let preimage = conditionally_swap_u256(
                    cs.namespace(|| "conditional swap"),
                    &lhs[..],
                    &rhs[..],
                    &cur_is_right,
                )?;

                cur = sha256_block_no_padding(cs.namespace(|| "hash of this layer"), &preimage)?;
            }

            /*
            for (i, (cur, rt)) in cur.into_iter().zip(rt.iter()).enumerate() {
                cs.enforce(
                    || format!("conditionally enforce correct root for bit {}", i),
                    |_| cur.lc(CS::one(), E::Fr::one()),
                    |_| rt.lc(CS::one(), E::Fr::one()),
                    |lc| lc,
                );
            }
            */
        }


        let mut public_inputs = vec![];
        public_inputs.extend(rt);

        pack_into_inputs(cs.namespace(|| "input packing"), &public_inputs)
    }
}

/// Witnesses some bytes in the constraint system,
/// skipping the first `skip_bits`.
fn witness_bits<E, CS>(
    mut cs: CS,
    value: Option<&[u8]>,
    num_bits: usize,
    skip_bits: usize,
) -> Result<Vec<Boolean>, SynthesisError>
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    let bit_values = if let Some(value) = value {
        let mut tmp = vec![];
        for b in value
            .iter()
            .flat_map(|&m| (0..8).rev().map(move |i| m >> i & 1 == 1))
            .skip(skip_bits)
        {
            tmp.push(Some(b));
        }
        tmp
    } else {
        vec![None; num_bits]
    };
    assert_eq!(bit_values.len(), num_bits);

    let mut bits = vec![];

    for (i, value) in bit_values.into_iter().enumerate() {
        bits.push(Boolean::from(AllocatedBit::alloc(
            cs.namespace(|| format!("bit {}", i)),
            value,
        )?));
    }

    Ok(bits)
}

fn witness_u256<E, CS>(cs: CS, value: Option<&[u8]>) -> Result<Vec<Boolean>, SynthesisError>
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    witness_bits(cs, value, 256, 0)
}

fn witness_u252<E, CS>(cs: CS, value: Option<&[u8]>) -> Result<Vec<Boolean>, SynthesisError>
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    witness_bits(cs, value, 252, 4)
}

#[test]
fn test_sprout_constraints() {
    use bellman::gadgets::test::*;
    use pairing::bls12_381::Bls12;

    use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

    let test_vector = include_bytes!("test_vectors.dat");
    let mut test_vector = &test_vector[..];

    fn get_u256<R: ReadBytesExt>(mut reader: R) -> [u8; 32] {
        let mut result = [0u8; 32];

        for i in 0..32 {
            result[i] = reader.read_u8().unwrap();
        }

        result
    }

    while test_vector.len() != 0 {
        let mut cs = TestConstraintSystem::<Bls12>::new();

        let phi = Some(get_u256(&mut test_vector));
        let rt = Some(get_u256(&mut test_vector));
        let h_sig = Some(get_u256(&mut test_vector));

        const TREE_DEPTH: usize = 29;

        let mut inputs = vec![];
        for i in 0..2 {
            test_vector.read_u8().unwrap();

            let mut auth_path = vec![None; TREE_DEPTH];
            for i in (0..TREE_DEPTH).rev() {
                test_vector.read_u8().unwrap();

                let sibling = get_u256(&mut test_vector);

                auth_path[i] = Some((sibling, false));
            }
            let mut position = test_vector.read_u64::<LittleEndian>().unwrap();
            for i in 0..TREE_DEPTH {
                auth_path[i].as_mut().map(|p| p.1 = (position & 1) == 1);

                position >>= 1;
            }

            // a_pk
            let _ = Some(SpendingKey(get_u256(&mut test_vector)));
            let value = Some(test_vector.read_u64::<LittleEndian>().unwrap());
            let rho = Some(UniqueRandomness(get_u256(&mut test_vector)));
            let r = Some(CommitmentRandomness(get_u256(&mut test_vector)));
            let leaf = Some(get_u256(&mut test_vector));

            if i == 0 {
                inputs.push(JSInput {
                    leaf,
                    auth_path,
                });
            }
        }

        for _ in 0..2 {
            let a_pk = Some(PayingKey(get_u256(&mut test_vector)));
            let value = Some(test_vector.read_u64::<LittleEndian>().unwrap());
            get_u256(&mut test_vector);
            let r = Some(CommitmentRandomness(get_u256(&mut test_vector)));
        }

        let vpub_old = Some(test_vector.read_u64::<LittleEndian>().unwrap());
        let vpub_new = Some(test_vector.read_u64::<LittleEndian>().unwrap());

        let nf1 = get_u256(&mut test_vector);
        let nf2 = get_u256(&mut test_vector);

        let cm1 = get_u256(&mut test_vector);
        let cm2 = get_u256(&mut test_vector);

        let mac1 = get_u256(&mut test_vector);
        let mac2 = get_u256(&mut test_vector);

        let js = JoinSplit {
            inputs,
            rt,
        };

        js.synthesize(&mut cs).unwrap();
    }
}
