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
  // /* put some object.
  //      i.e. Fixnum, true, false, nil, and so on.
  //  */
  // putobject
  // (VALUE val)
  // ()
  // (VALUE val)
  if (name == "putobject") {
    return function(args) {
      try {
        let val = vm.GET_OPERAND(1)
        let val_inspect = r.rb_inspect2(val);

        log(">> putobject (" + val_inspect + ")");
      } catch (e) {
        log("Error [putobject]: " + String(e))
      }
    }
  } else if (name == "putobject_INT2FIX_0_") {
    return function(args) {
      log(">> putobject_INT2FIX_0_ [putobject (0)]");
    }
  } else if (name == "putobject_INT2FIX_1_") {
    return function(args) {
      log(">> putobject_INT2FIX_1_ [putobject (1)]");
    }
  }
}