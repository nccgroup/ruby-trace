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

let leave = function(type_str) {
  return function() {
    let val_p = vm.TOPN(0);
    let val_inspect = r.rb_inspect2(val_p);
    log(">> putspecialobject " + type_str + " {" + val_inspect + "}");
  }
}

module.exports = function(args) {
  // /* put special object.  "value_type" is for expansion. */
  // ruby 2.6-3.0
  // putspecialobject
  // (rb_num_t value_type)
  // ()
  // (VALUE val)

  // ruby 3.1
  // putspecialobject
  // (rb_num_t value_type)
  // ()
  // (VALUE val)
  // // attr bool leaf = (value_type == VM_SPECIAL_OBJECT_VMCORE); /* others may raise when allocating singleton */
  try {
    let value_type = parseInt(vm.GET_OPERAND(1).toString(16))
    let type_str = String(value_type);
    switch (value_type) {
      case 1: {
        type_str += " (VM_SPECIAL_OBJECT_VMCORE)";
        break;
      }
      case 2: {
        type_str += " (VM_SPECIAL_OBJECT_CBASE)";
        break;
      }
      case 3: {
        type_str += " (VM_SPECIAL_OBJECT_CONST_BASE)";
        break;
      }
      default: {
        type_str += " (unknown)"
      }
    }

    vm.return_callback = leave(type_str);
  } catch (e) {
    log("Error [putspecialobject]: " + String(e))
  }
}