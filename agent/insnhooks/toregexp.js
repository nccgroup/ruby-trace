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
  log(">> toregexp -> " + val_inspect);
}

module.exports = function(args) {
  // /* compile str to Regexp and push it.
  //      opt is the option for the Regexp.
  //  */
  // toregexp
  // (rb_num_t opt, rb_num_t cnt)
  // (...)
  // (VALUE val)
  // // attr rb_snum_t sp_inc = 1 - (rb_snum_t)cnt;
  try {
    let opt = parseInt(vm.GET_OPERAND(1).toString())
    let cnt = parseInt(vm.GET_OPERAND(2).toString())

    let sp = vm.GET_SP();
    let vals = []
    for (let i=0; i < cnt; i++) {
      vals.push(r.rb_inspect2(vm.TOPN(i, sp)));
    }
    vals.reverse()
    let vals_str = "[ " + vals.join(", ") + " ]";

    let opt_flags = [];
    if ((opt & 16) != 0) {
      opt_flags.push("ARG_ENCODING_FIXED");
    }
    if ((opt & 32) != 0) {
      opt_flags.push("ARG_ENCODING_NONE");
    }

    if ((opt & 1) != 0) {
      opt_flags.push("ONIG_OPTION_IGNORECASE");
    }
    if ((opt & 2) != 0) {
      opt_flags.push("ONIG_OPTION_EXTEND");
    }
    if ((opt & 4) != 0) {
      opt_flags.push("ONIG_OPTION_MULTILINE");
    }

    if (opt == 0) {
      opt_flags.push("ONIG_OPTION_NONE");
    }

    let opt_str = opt_flags.join("|")
    log(">> toregexp opt: " + opt + " (" + opt_str + "), cnt: " + cnt + " " + vals_str);
    vm.return_callback = leave;
  } catch (e) {
    log("Error [toregexp]: " + String(e))
  }
}