use bellman::groth16::*;
use ff::Field;
use pairing::bls12_381::{Bls12, Fr};
use rand_core::{RngCore, SeedableRng};
use rand_xorshift::XorShiftRng;
use std::time::{Duration, Instant};
use zcash_primitives::jubjub::{edwards, fs, JubjubBls12};
use zcash_primitives::primitives::{Diversifier, ProofGenerationKey, ValueCommitment};
use zcash_proofs::circuit::merkle::MerklePedersen;

fn crs_size(parameters: &Parameters<Bls12>) -> (usize, usize) {

    let mut vk_accum = 0;
    // Groth16 vk
    vk_accum += 48;
    vk_accum += 96;
    vk_accum += 96;
    vk_accum += 96;
    for g in &parameters.vk.ic {
        vk_accum += 48;
    }

    let mut pk_accum = 0;
    pk_accum += 48;
    pk_accum += 48;
    pk_accum += 48;
    for g in &*parameters.a {
        pk_accum += 48;
    }
    for g in &*parameters.b_g1 {
        pk_accum += 48;
    }
    for g in &*parameters.b_g2 {
        pk_accum += 96;
    }
    for g in &*parameters.h{
        pk_accum += 48;
    }
    for g in &*parameters.l{
        pk_accum += 48;
    }

    (vk_accum, pk_accum)
}

fn main() {
    let jubjub_params = &JubjubBls12::new();
    let rng = &mut XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    


    for depth in [8, 16, 32, 64].iter() {
        let TREE_DEPTH: usize = depth.clone();

        println!("depth {}: Creating sample parameters...", TREE_DEPTH);
        let groth_params = generate_random_parameters::<Bls12, _, _>(
            MerklePedersen {
                params: jubjub_params,
                leaf: None,
                auth_path: vec![None; TREE_DEPTH],
                anchor: None,
            },
            rng,
        )
        .unwrap();
    println!("crs size: {:?}", crs_size(&groth_params));

        const SAMPLES: u32 = 50;

        let prepared_vk = prepare_verifying_key(&groth_params.vk);
        let mut total_time = Duration::new(0, 0);
        let mut total_verification_time = Duration::new(0, 0);
        for _ in 0..SAMPLES {
            let cm = Fr::random(rng);
            let auth_path = vec![Some((Fr::random(rng), rng.next_u32() % 2 != 0)); TREE_DEPTH];
            let anchor = Fr::random(rng);

            let start = Instant::now();
            let proof = create_random_proof(
                MerklePedersen {
                    params: jubjub_params,
                    leaf: Some(cm),
                    auth_path,
                    anchor: Some(anchor),
                },
                &groth_params,
                rng,
            )
            .unwrap();
            total_time += start.elapsed();
            let start_verify = Instant::now();
            assert!(verify_proof(&prepared_vk, &proof, &[anchor]).unwrap());
            total_verification_time += start_verify.elapsed();
        }
        let avg = total_time / SAMPLES;
        let avg = avg.subsec_nanos() as f64 / 1_000_000_000f64 + (avg.as_secs() as f64);
        let avg_verify = total_verification_time / SAMPLES;
        let avg_verify = avg_verify.subsec_nanos() as f64 / 1_000_000_000f64 + (avg_verify.as_secs() as f64);

        println!("depth {}: Average proving time (in seconds): {}", TREE_DEPTH, avg);
        println!("depth {}: Average verification time (in seconds): {}", TREE_DEPTH, avg_verify);
    }
}
