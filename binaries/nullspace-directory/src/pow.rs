use bytes::Bytes;
use equix::{EquiXBuilder, Solution, SolutionByteArray};
use nullspace_crypt::hash::Hash;
use nullspace_structs::directory::{DirectoryErr, PowAlgo, PowSeed, PowSolution};
use nullspace_structs::timestamp::Timestamp;
use rand::RngCore;

pub const POW_EFFORT: u64 = 1_000;
pub const SEED_TTL_SECS: u64 = 120;

pub fn new_seed() -> PowSeed {
    let mut seed_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut seed_bytes);
    PowSeed {
        algo: PowAlgo::EquiX { effort: POW_EFFORT },
        seed: Hash::from_bytes(seed_bytes),
        use_before: Timestamp(unix_time() + SEED_TTL_SECS),
    }
}

pub fn validate_solution(
    seed: &PowSeed,
    effort: u64,
    solution: &PowSolution,
) -> Result<(), DirectoryErr> {
    if seed.seed != solution.seed {
        return Err(DirectoryErr::UpdateRejected("seed mismatch".into()));
    }
    let eq = EquiXBuilder::new();
    let challenge = Hash::keyed_digest(&solution.seed.to_bytes(), &solution.nonce.to_be_bytes());
    let bytes = parse_solution_bytes(&solution.solution)?;
    eq.verify_bytes(&challenge.to_bytes(), &bytes)
        .map_err(|_| DirectoryErr::UpdateRejected("invalid equix solution".into()))?;

    let sol_hash = Hash::digest(solution.solution.as_ref());
    let mut first = [0u8; 8];
    first.copy_from_slice(&sol_hash.to_bytes()[..8]);
    let value = u64::from_be_bytes(first);
    value
        .checked_mul(effort)
        .ok_or_else(|| DirectoryErr::UpdateRejected("insufficient effort".into()))?;
    Ok(())
}

fn parse_solution_bytes(solution: &Bytes) -> Result<SolutionByteArray, DirectoryErr> {
    const SOL_LEN: usize = Solution::NUM_BYTES;
    if solution.len() != SOL_LEN {
        return Err(DirectoryErr::UpdateRejected(
            "invalid solution length".into(),
        ));
    }
    let mut buf = [0u8; SOL_LEN];
    buf.copy_from_slice(solution);
    Ok(buf)
}

fn unix_time() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
