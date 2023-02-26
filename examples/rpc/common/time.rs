pub fn rdtsc() -> u64 {
  #[cfg(target_arch = "x86_64")]
  return unsafe { core::arch::x86_64::_rdtsc() };
  #[cfg(target_arch = "x86")]
  return unsafe { core::arch::x86::_rdtsc() };
}

pub fn measure_rdtsc_freq() -> f64 {
  let rdtsc_start = rdtsc();
  let time_start = std::time::Instant::now();
  let mut sum = 5u64;

  for i in 0..1000000u64 {
    //sum+=i +(sum+i) *(i %sum);
    sum = sum
      .wrapping_add(i.wrapping_add(sum.wrapping_add(i).wrapping_mul(i % sum)));
  }
  assert!(
    sum == 13580802877818827968,
    "Error in RDTSC freq measurement"
  );
  let rdtsc_cycles = rdtsc() - rdtsc_start;
  let freq_ghz = (rdtsc_cycles as f64 * 1.0)
    / std::time::Instant::duration_since(&std::time::Instant::now(), time_start)
      .as_nanos() as f64;

  assert!(
    freq_ghz >= 0.5 && freq_ghz <= 5.0,
    "Invalid RDTSC frequency"
  );
  return freq_ghz;
}

#[inline]
pub fn to_sec(cycles: u64, freq_ghz: f64) -> f64 {
  cycles as f64 / (freq_ghz * 1000000000.0)
}
#[inline]
pub fn to_msec(cycles: u64, freq_ghz: f64) -> f64 {
  cycles as f64 / (freq_ghz * 1000000.0)
}
#[inline]
pub fn to_usec(cycles: u64, freq_ghz: f64) -> f64 {
  cycles as f64 / (freq_ghz * 1000.0)
}
#[inline]
pub fn to_nsec(cycles: u64, freq_ghz: f64) -> f64 {
  cycles as f64 / freq_ghz
}

#[inline]
pub fn ms_to_cycles(ms: f64, freq_ghz: f64) -> u64 {
  (ms * 1000.0 * 1000.0 * freq_ghz) as u64
}

#[inline]
pub fn us_to_cycles(ms: f64, freq_ghz: f64) -> u64 {
  (ms * 1000.0 * freq_ghz) as u64
}
#[inline]
pub fn ns_to_cycles(ms: f64, freq_ghz: f64) -> u64 {
  (ms * freq_ghz) as u64
}
