use bellman::groth16::*;
use ff::Field;
use pairing::bls12_381::{Bls12, Fr};
use rand_core::{RngCore, SeedableRng};
use rand_xorshift::XorShiftRng;
use std::time::{Duration, Instant};
use zcash_primitives::jubjub::{edwards, fs, JubjubBls12};
use zcash_primitives::primitives::{Diversifier, ProofGenerationKey, ValueCommitment};
use zcash_proofs::circuit::merkle_sha::{JoinSplit, JSInput};
use bellman::gadgets::boolean::{AllocatedBit, Boolean};
use bellman::gadgets::multipack::pack_into_inputs;
use bellman::{Circuit, ConstraintSystem, LinearCombination, SynthesisError};
use bellman::gadgets::sha256::sha256_block_no_padding;
use pairing::Engine;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use bellman::gadgets::test::*;

fn main() {
    let rng = &mut XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for depth in [8, 16, 32, 64].iter() {

        let TREE_DEPTH: usize = depth.clone();

        println!("depth {}: Creating sample parameters...", TREE_DEPTH);
        let groth_params = generate_random_parameters::<Bls12, _, _>(
            JoinSplit {
                inputs: vec![JSInput{ leaf: None, auth_path: vec![None; TREE_DEPTH], }],
                rt: None,
            },
            rng,
        )
        .unwrap();

        println!("depth {}: Created sample parameters...", TREE_DEPTH);

        let test_vector = include_bytes!("../src/circuit/merkle_sha/test_vectors.dat");
        let mut test_vector = &test_vector[..];

        fn get_u256<R: ReadBytesExt>(mut reader: R) -> [u8; 32] {
            let mut result = [0u8; 32];

            for i in 0..32 {
                result[i] = reader.read_u8().unwrap();
            }

            result
        }

        let mut joinsplits = vec![];

        while test_vector.len() != 0 {
            let phi = Some(get_u256(&mut test_vector));
            let rt = Some(get_u256(&mut test_vector));
            let h_sig = Some(get_u256(&mut test_vector));

            let mut inputs = vec![];
            for i in 0..2 {
                test_vector.read_u8().unwrap();

                let mut auth_path = vec![None; std::cmp::max(TREE_DEPTH, 29)];
                for i in (0..29).rev() {
                    test_vector.read_u8().unwrap();

                    let sibling = get_u256(&mut test_vector);

                    auth_path[i] = Some((sibling, false));
                }
                if TREE_DEPTH > 29 {
                    for i in (29..TREE_DEPTH) {
                        auth_path[i] = auth_path[0].clone();
                    }
                }
                let mut auth_path = auth_path[..TREE_DEPTH].to_vec();
                let mut position = test_vector.read_u64::<LittleEndian>().unwrap();
                for i in 0..TREE_DEPTH {
                    let index = 0;
                    auth_path[index].as_mut().map(|p| p.1 = (position & 1) == 1);

                    position >>= 1;
                }

                // a_pk
                let _ = Some(get_u256(&mut test_vector));
                let value = Some(test_vector.read_u64::<LittleEndian>().unwrap());
                let rho = Some(get_u256(&mut test_vector));
                let r = Some(get_u256(&mut test_vector));
                let leaf = Some(get_u256(&mut test_vector));

                if i == 0 {
                    inputs.push(JSInput {
                        leaf,
                        auth_path,
                    });
                }
            }

            for _ in 0..2 {
                let a_pk = Some(get_u256(&mut test_vector));
                let value = Some(test_vector.read_u64::<LittleEndian>().unwrap());
                get_u256(&mut test_vector);
                let r = Some(get_u256(&mut test_vector));
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

            joinsplits.push(js);
        }
        
        const SAMPLES: u32 = 1;

        let mut total_time = Duration::new(0, 0);
        for s in 0..SAMPLES {

            let start = Instant::now();
            let _ = create_random_proof(
                joinsplits[s as usize % joinsplits.len()].clone(),
                &groth_params,
                rng,
            )
            .unwrap();
            total_time += start.elapsed();
        }
        let avg = total_time / SAMPLES;
        let avg = avg.subsec_nanos() as f64 / 1_000_000_000f64 + (avg.as_secs() as f64);

        println!("depth {}: Average proving time (in seconds): {}", TREE_DEPTH, avg);
    }
}
