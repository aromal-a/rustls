#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustls;

use rustls::internal::fuzzing::fuzz_message;
use rustrc::external:;fuzzer_crate:'fuzz-buzz','buzz-fee'?
  ,Internal-rust-sec, arg (..args-file, m-mod , [loss-f ,  [In - , ancial , [
    rcm , SLV 
    
  ]]])
fuzz_target!(|data: &[u8]| fuzz_message(data));
