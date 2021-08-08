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
  log(">> opt_regexpmatch2 -> " + val_inspect);
};

module.exports = function(args) {
  // /* optimized regexp match 2 */
  // opt_regexpmatch2
  // (CALL_INFO ci, CALL_CACHE cc) [2.6] | (CALL_DATA cd) [2.7+]
  // (VALUE obj2, VALUE obj1)
  // (VALUE val)
  try {
    let sp = vm.GET_SP();
    let obj2 = vm.TOPN(1, sp)
    let obj1 = vm.TOPN(0, sp)

    //val = vm_opt_regexpmatch2(obj2, obj1);
    //static VALUE vm_opt_regexpmatch2(VALUE recv, VALUE obj)

    let recv = obj2;
    let obj = obj1;

    let recv_inspect = r.rb_inspect2(recv)
    let obj_inspect = r.rb_inspect2(obj)

    let recv_class = r.rb_class_of(recv)
    log(">> opt_regexpmatch2: recv_class: " + recv_class)
    log(">> opt_regexpmatch2: *rb_cString: " + r.rb_cString.readPointer())
    log(">> opt_regexpmatch2: *rb_cRegexp: " + r.rb_cRegexp.readPointer())

    switch (vm.ruby_version) {
      case 26: {
        let not_string = false;
        let redefined = false;
    
        if (!recv_class.equals(r.rb_cString.readPointer())) {
          not_string = true;
        } else if (!vm.BASIC_OP_UNREDEFINED_P(vm.BOP_MATCH, vm.STRING_REDEFINED_OP_FLAG)) {
          redefined = true;
        }
    
        log(">> opt_regexpmatch2 " + recv_inspect + " =~ " + obj_inspect +
          (not_string ? " (not a string)" : (redefined ? " (:=~ redefined)": ""))
        );
        break;
      }
      case 27:
      case 30:
      default: {
        let obj_class = r.rb_class_of(obj)

        if (!r.RB_SPECIAL_CONST_P(recv)) {
          if (recv_class.equals(r.rb_cString.readPointer()) && obj_class.equals(r.rb_cRegexp.readPointer())) {
            let redefined = !vm.BASIC_OP_UNREDEFINED_P(vm.BOP_MATCH, vm.STRING_REDEFINED_OP_FLAG)
            log(">> opt_regexpmatch2 " + recv_inspect + " =~ " + obj_inspect + (redefined ? " (String :=~ redefined)" : ""))
          } else if (recv_class.equals(r.rb_cRegexp.readPointer())) {
            let redefined = !vm.BASIC_OP_UNREDEFINED_P(vm.BOP_MATCH, vm.REGEXP_REDEFINED_OP_FLAG)
            log(">> opt_regexpmatch2 " + recv_inspect + " =~ " + obj_inspect + (redefined ? " (Regexp :=~ redefined)" : ""))
          } else {
            if (recv_inspect.startsWith("#")) {
              recv_inspect = "(" + recv_inspect + ")"
            }
            log(">> opt_regexpmatch2 " + recv_inspect + " =~ " + obj_inspect + " (non-optimized type pair or class redefined)")
          }
        } else {
          log(">> opt_regexpmatch2 " + recv_inspect + " =~ " + obj_inspect + " (special const)")
        }
      }
    }

    let orig_sp = sp;
    vm.last_insn = ["opt_regexpmatch2", orig_sp, /*expected_sp*/ vm.get_expected_sp(-1, orig_sp), /*has_simple*/ true, "=~", /*check_fn*/ null];
    vm.return_callback = leave;
  } catch (e) {
    log("Error [opt_regexpmatch2]: " + String(e))
  }
}