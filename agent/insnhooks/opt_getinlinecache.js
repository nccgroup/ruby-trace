/*
Copyright (c) 2021 NCC Group Security Services, Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/

let r = require('../ruby')();
let vm = require('../rubyvm')();
let { log } = require('../libc')();

const INSN_ATTR_width = 0x18 //note: not sure if this changes w/ arch

let leave = function() {
  let val_p = vm.TOPN(0);
  let val_inspect = r.rb_inspect2(val_p);
  log(">> opt_getinlinecache -> " + val_inspect);
}

module.exports = function(args) {
  // /* push inline-cached value and go to dst if it is valid */
  // opt_getinlinecache
  // (OFFSET dst, IC ic)
  // ()
  // (VALUE val)
  try {
    let cfp = vm.GET_CFP()
    let raw_dst = vm.GET_OPERAND(1, cfp).toString()
    let ic = vm.GET_OPERAND(2, cfp)

    let cur_pc = parseInt(vm.GET_PC(cfp).toString())
    let dst = (Number)(BigInt64Array.from([raw_dst])[0])
    let dst_pc = (cur_pc + INSN_ATTR_width) + (dst*Process.pointerSize)
    let dst_str = dst >= 0 ? "+" + dst : dst

    let ic_serial = vm.native.iseq_inline_cache_entry__ic_serial(ic).toNumber()
    let ic_cref = vm.native.iseq_inline_cache_entry__ic_cref(ic)

    let ic_hit = vm.vm_ic_hit_p(ic_serial, ic_cref, cfp)
    let res_str = ic_hit ? "taken" : "not taken";

    log(">> opt_getinlinecache " + dst_str + " (0x" + cur_pc.toString(16) + "->0x" + dst_pc.toString(16) + "), ic_serial: " + ic_serial + ", ic_cref: @" + ic_cref + "; jump: " + res_str)
    vm.return_callback = leave;
  } catch (e) {
    log("Error [opt_getinlinecache]: " + String(e))
  }
}