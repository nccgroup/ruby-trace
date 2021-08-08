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

module.exports = function(name) {
  // opt_newarray_max
  // (rb_num_t num)
  // (...)
  // (VALUE val)
  // /* This instruction typically has no funcalls.  But it compares array
  //  * contents each other by nature.  That part could call methods when
  //  * necessary.  No way to detect such method calls beforehand.  We
  //  * cannot but mark it being not leaf. */
  // // attr bool leaf = false; /* has rb_funcall() */
  // // attr rb_snum_t sp_inc = 1 - (rb_snum_t)num;

  // opt_newarray_min
  // (rb_num_t num)
  // (...)
  // (VALUE val)
  // /* Same discussion as opt_newarray_max. */
  // // attr bool leaf = false; /* has rb_funcall() */
  // // attr rb_snum_t sp_inc = 1 - (rb_snum_t)num;

  let leave = function() {
    let val_p = vm.TOPN(0);
    let val_inspect = r.rb_inspect2(val_p);
    log(">> " + name + " -> " + val_inspect);
  };

  return function(args) {
    try {
      let num = parseInt(vm.GET_OPERAND(1).toString())
  
      let sp = vm.GET_SP();
      let vals = []
      for (let i=0; i < num; i++) {
        vals.push(r.rb_inspect2(vm.TOPN(i, sp)));
      }
      vals.reverse()
      let vals_str = "[ " + vals.join(", ") + " ]";
  
      log(">> " + name + " num: " + num + ", " + vals_str + " (bottom->top)");
      vm.return_callback = leave;
    } catch (e) {
      log("Error [" + name + "]: " + String(e))
    }
  }
}