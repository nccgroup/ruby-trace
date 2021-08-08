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
  //note: it may be the case that EC_JUMP_TAG/rb_ec_tag_jump are aggressively
  //      inlined here and can't otherwise be hooked by rb_ec_tag_jump.isra.*
  //      symbols

  // /* longjump */
  // throw
  // (rb_num_t throw_state)
  // (VALUE throwobj)
  // (VALUE val)
  // /* Same discussion as leave. */
  // // attr bool leaf = false; /* has rb_threadptr_execute_interrupts() */
  try {
    let throw_state = vm.GET_OPERAND(1)
    let throwobj = vm.TOPN(0)
    let throwobj_str = r.rb_inspect2(throwobj)
    
    log(">> throw throw_state: " + throw_state + ", throwobj: " + throwobj_str);
  } catch (e) {
    log("Error [throw]: " + String(e))
  }
}