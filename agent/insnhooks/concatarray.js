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
  log(">> concatarray -> " + val_inspect);
}

module.exports = function(args) {
  // /* concat two arrays */
  // concatarray
  // ()
  // (VALUE ary1, VALUE ary2)
  // (VALUE ary)
  try {
    let sp = vm.GET_SP();
    let ary2_inspect = r.rb_inspect2(vm.TOPN(0, sp))
    let ary1_inspect = r.rb_inspect2(vm.TOPN(1, sp))

    log(">> concatarray ary1: " + ary1_inspect + ", ary2: " + ary2_inspect);
    vm.return_callback = leave;
  } catch (e) {
    log("Error [concatarray]: " + String(e))
  }
}