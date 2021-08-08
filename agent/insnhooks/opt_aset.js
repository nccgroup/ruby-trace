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

let leave = function() {
  let val_p = vm.TOPN(0);
  let val_inspect = r.rb_inspect2(val_p);
  log(">> opt_aset -> " + val_inspect);
};

module.exports = function(args) {
  // /* recv[obj] = set */
  // opt_aset
  // (CALL_INFO ci, CALL_CACHE cc) [2.6] | (CALL_DATA cd) [2.7+]
  // (VALUE recv, VALUE obj, VALUE set)
  // (VALUE val)
  // /* This is another story than opt_aref.  When vm_opt_aset() resorts
  //  * to rb_hash_aset(), which should call #hash for `obj`. */
  // // attr bool leaf = false; /* has rb_funcall() */ /* calls #hash */
  try {
    let sp = vm.GET_SP();
    let recv = vm.TOPN(2, sp)
    let obj = vm.TOPN(1, sp)
    let set = vm.TOPN(0, sp)

    let recv_inspect = r.rb_inspect2(recv)
    let obj_inspect = r.rb_inspect2(obj)
    let set_inspect = r.rb_inspect2(set)

    if (recv_inspect.startsWith("#")) {
      recv_inspect = "(" + recv_inspect + ")"
    }

    log(">> opt_aset " + recv_inspect + "[" + obj_inspect + "] = (" + set_inspect + ")");

    let orig_sp = sp;
    vm.last_insn = ["opt_aset", orig_sp, /*expected_sp*/ vm.get_expected_sp(-2, orig_sp), /*has_simple*/ true, "[]=", /*check_fn*/ null];
    vm.return_callback = leave;
  } catch (e) {
    log("Error [opt_aset]: " + String(e))
  }
}