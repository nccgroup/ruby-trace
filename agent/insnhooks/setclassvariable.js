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
  // /* Set value of class variable id of klass as val. */
  // ruby 2.6-3.0
  // setclassvariable
  // (ID id)
  // (VALUE val)
  // ()

  // ruby 3.1
  // setclassvariable
  // (ID id, IVC ic)
  // (VALUE val)
  // ()

  try {
    let id = vm.GET_OPERAND(1)
    let id_str = r.rb_id2name(id).readUtf8String()

    let val_p = vm.TOPN(0)
    let val_inspect = r.rb_inspect2(val_p);

    let ep_p = vm.GET_EP();
    let cref_p = vm.vm_env_cref(ep_p)

    let klass = null;
    switch (vm.ruby_version) {
      case 26:
      case 27:
      case 30: {
        klass = vm.native.rb_cref_t__klass(cref_p);
        break;
      }
      case 31:
      default: {
        klass = vm.native.rb_cref_t__klass_or_self(cref_p);
      }
    }

    let klass_inspect = r.rb_inspect2(klass);

    log(">> setclassvariable :" + id_str + ", (" + val_inspect + ") {" + klass_inspect + "}");
  } catch (e) {
    log("Error [setclassvariable]: " + String(e))
  }
}
