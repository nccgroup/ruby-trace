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

//note/TODO: i don't like pushing the logging into the leave function called
//           right before the next instruction is run (and relies on the next
//           instruction being hooked), but it's not really worth trying to
//           pre/re-generate the ic_cref (at least not right now).

let leave = function(msg, ic, val_in_inspect) {
  return function() {
    try {
      let ic_serial = vm.native.iseq_inline_cache_entry__ic_serial(ic).toNumber()
      let ic_cref = vm.native.iseq_inline_cache_entry__ic_cref(ic)
      log(">> opt_setinlinecache ic_serial: " + ic_serial + ", ic_cref: @" + ic_cref + " { " + val_in_inspect + " }")  
    } catch (e) {
      log(msg)
    }

    try {
      let val_p = vm.TOPN(0);
      let val_inspect = r.rb_inspect2(val_p);
      log(">> opt_setinlinecache -> " + val_inspect);
    } catch (e) {
      log("Error [opt_setinlinecache->leave]: " + String(e))
    }
  }
}

module.exports = function(args) {
  // /* set inline cache */
  // opt_setinlinecache
  // (IC ic)
  // (VALUE val)
  // (VALUE val)
  try {
    let cfp = vm.GET_CFP()
    let ic = vm.GET_OPERAND(1, cfp)

    let val = vm.TOPN(0);
    let val_inspect = r.rb_inspect2(val);

    let rvgcs = vm.ruby_vm_global_constant_state.readU64().toNumber();
    let rvcmc = vm.ruby_vm_const_missing_count.readU64().toNumber();    
    let ic_serial = rvgcs - rvcmc;
    let msg  = ">> opt_setinlinecache ic_serial: " + ic_serial + " { " + val_inspect + " }"

    vm.return_callback = leave(msg, ic, val_inspect);
  } catch (e) {
    log("Error [opt_setinlinecache]: " + String(e))
  }
}