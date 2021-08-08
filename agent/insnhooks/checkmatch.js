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
  log(">> checkmatch -> " + val_inspect);
}

const vm_check_match_type = [
  "NULL",
  "VM_CHECKMATCH_TYPE_WHEN",
  "VM_CHECKMATCH_TYPE_CASE",
  "VM_CHECKMATCH_TYPE_RESCUE",
];

const VM_CHECKMATCH_TYPE_MASK = 0x03
const VM_CHECKMATCH_ARRAY = 0x04

module.exports = function(args) {
  // /* check `target' matches `pattern'.
  //      `flag & VM_CHECKMATCH_TYPE_MASK' describe how to check pattern.
  //       VM_CHECKMATCH_TYPE_WHEN: ignore target and check pattern is truthy.
  //       VM_CHECKMATCH_TYPE_CASE: check `patten === target'.
  //       VM_CHECKMATCH_TYPE_RESCUE: check `pattern.kind_op?(Module) && pattern === target'.
  //      if `flag & VM_CHECKMATCH_ARRAY' is not 0, then `patten' is array of patterns.
  //  */
  // checkmatch
  // (rb_num_t flag)
  // (VALUE target, VALUE pattern)
  // (VALUE result)
  try {
    let flag = parseInt(vm.GET_OPERAND(1).toString())    

    let pattern_str = r.rb_inspect2(vm.TOPN(0))
    let target_str = r.rb_inspect2(vm.TOPN(1))

    let flag_str = vm_check_match_type[flag & VM_CHECKMATCH_TYPE_MASK]
    if ((flag & VM_CHECKMATCH_ARRAY) != 0) {
      flag_str += "|VM_CHECKMATCH_ARRAY"
    }

    log(">> checkmatch flag: " + flag_str + ", target: " + target_str + ", pattern: " + pattern_str);
    vm.return_callback = leave;
  } catch (e) {
    log("Error [checkmatch]: " + String(e))
  }
}