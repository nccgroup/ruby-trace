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

  let leave = function() {
    let val_p = vm.TOPN(0);
    let val_inspect = r.rb_inspect2(val_p);
    log(">> " + name + " -> " + val_inspect);
  }

  return function(args) {
    // /* push the result of to_s. */
    // ruby 2.6-3.0
    // tostring
    // ()
    // (VALUE val, VALUE str)
    // (VALUE val)

    // /* Convert the result to string if not already a string.
    //    This is used as a backup if to_s does not return a string. */
    // ruby 3.1
    // anytostring
    // ()
    // (VALUE val, VALUE str)
    // (VALUE val)

    // ruby 3.0:
    // 0023 opt_send_without_block                 <calldata!mid:to_s, argc:0, FCALL|ARGS_SIMPLE>
    // 0025 tostring

    // ruby 3.1:
    // 0018 objtostring                            <calldata!mid:to_s, argc:0, FCALL|ARGS_SIMPLE>
    // 0020 anytostring
    try {
      let sp = vm.GET_SP();
      let val = r.rb_inspect2(vm.TOPN(1, sp))
      let str = r.rb_inspect2(vm.TOPN(0, sp))

      log(">> " + name + " val: " + val + ", str: " + str);
      vm.return_callback = leave;
    } catch (e) {
      log("Error [" + name + "]: " + String(e))
    }
  }

}
