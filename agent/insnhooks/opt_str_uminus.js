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
  log(">> opt_str_uminus -> " + val_inspect);
};

module.exports = function() {
  // opt_str_uminus
  // (VALUE str, CALL_INFO ci, CALL_CACHE cc) [2.6] | (VALUE str, CALL_DATA cd) [2.7+]
  // ()
  // (VALUE val)
  try {
    //note: opt_str_uminus is opt_str_freeze but with a different method/id

    let str = vm.GET_OPERAND(1)
    let str_inspect = r.rb_inspect2(str);
    log(">> opt_str_uminus: -" + str_inspect);

    let orig_sp = vm.GET_SP();
    vm.last_insn = ["opt_str_uminus", orig_sp, /*expected_sp*/ vm.get_expected_sp(+1, orig_sp), /*has_simple*/ true, "-@", /*check_fn*/ function() {
      let str = vm.TOPN(0);
      let is_frozen = r.ruby_call0(str, "frozen?");
      // when frozen is overridden, the rb_str_resurrect version of the string is not frozen
      return is_frozen.equals(r.Qfalse);
    }];
    vm.return_callback = leave;
  } catch (e) {
    log("Error [opt_str_uminus]: " + String(e))
  }
}