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

module.exports = function(args) {
  // /* empty current stack */
  // DEFINE_INSN
  // adjuststack
  // (rb_num_t n)
  // (...)
  // (...)
  // // attr rb_snum_t sp_inc = -(rb_snum_t)n;
  try {
    let n = parseInt(vm.GET_OPERAND(1).toString())

    // let val = vm.TOPN(n)

    let sp = vm.GET_SP();
    let vals = []
    for (let i=0; i < n+1; i++) {
      vals.push(r.rb_inspect2(vm.TOPN(i, sp)));
    }
    for (let i=0; i < n; i++) {
      vals[i] = "~" + vals[i] + "~"
    }
    let vals_str = "[ " + vals.join(", ") + " ]";

    log(">> adjuststack n: " + n + " " + vals_str + " (top->bottom)");
  } catch (e) {
    log("Error [adjuststack]: " + String(e))
  }
}