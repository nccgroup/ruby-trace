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
  log(">> newarraykwsplat -> " + val_inspect);
}

module.exports = function(args) {
  // /* put new array initialized with num values on the stack. There
  //    should be at least one element on the stack, and the top element
  //    should be a hash.  If the top element is empty, it is not
  //    included in the array.
  //  */
  // newarraykwsplat
  // (rb_num_t num)
  // (...)
  // (VALUE val)
  // // attr rb_snum_t sp_inc = 1 - (rb_snum_t)num;
  try {
    let num = parseInt(vm.GET_OPERAND(1).toString())

    let sp = vm.GET_SP();
    let vals = []
    for (let i=0; i < num; i++) {
      vals.push(r.rb_inspect2(vm.TOPN(i, sp)));
    }
    vals.reverse()
    let vals_str = "[ " + vals.join(", ") + " ]";

    log(">> newarraykwsplat num: " + num + " " + vals_str);
    vm.return_callback = leave;
  } catch (e) {
    log("Error [newarraykwsplat]: " + String(e))
  }
}