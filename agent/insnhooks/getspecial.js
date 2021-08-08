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
  log(">> getspecial -> " + val_inspect);
}

module.exports = function(args) {
  // /* Get value of special local variable ($~, $_, ..). */
  // getspecial
  // (rb_num_t key, rb_num_t type)
  // ()
  // (VALUE val)
  try {
    let key = parseInt(vm.GET_OPERAND(1))
    let type = parseInt(vm.GET_OPERAND(2))

    let _k = key;
    let _t;
    if (type == 0) {
      // val = lep_svar_get(ec, lep, key)      
      switch (key) {
        case 0: {
          _k = "lastline"
          _t = "_"
          break;
        }
        case 1: {
          _k = "backref"
          _t = "~"
          break;
        }
        default: {
          _k = "flip-flop"
          _t = "N/A"
        }
      }
      log(">> getspecial key: " + _k + " (" + key + "), type: " + _t + " (" + type + ")");
    } else {
      _t = type >> 1;
      if (type & 1) {
        // should only be one of: & (last), ` (pre), ' (post), or + (last)
        // backrefs
        // VALUE backref = lep_svar_get(ec, lep, VM_SVAR_BACKREF); // 1
        _t = String.fromCharCode(_t)
      } else {
        // regex nth match
        if (_t < 10) {
          _t += 0x30; // '0'
          _t = String.fromCharCode(_t)
        } else {
          _t = parseInt(_t)
        }
      }

      switch (key) {
        case 0: {
          _k = "lastline"
          break;
        }
        case 1: {
          _k = "backref"
          break;
        }
        default: {
          _k = "flip-flop"
        }
      }

      log(">> getspecial key: " + _k + " [N/A] (" + key + "), type: $" + _t + " (" + type + ")");
    }

    vm.return_callback = leave;
  } catch (e) {
    log("Error [getspecial]: " + String(e))
  }
}
