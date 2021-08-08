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

let leave = function(name) {
    return function() {
    let val_p = vm.TOPN(0);
    let val_inspect = r.rb_inspect2(val_p);
    log(">> " + name + " -> " + val_inspect);
  }
}

const VM_ENV_DATA_SIZE = 3

module.exports = function(funcname, _level) {
  // /* Get local variable (pointed by `idx' and `level').
  //      'level' indicates the nesting depth from the current block.
  //  */
  // getlocal
  // (lindex_t idx, rb_num_t level)
  // ()
  // (VALUE val)

  // /* Get a block parameter. */
  // getblockparam
  // (lindex_t idx, rb_num_t level)
  // ()
  // (VALUE val)

  // /* Get special proxy object which only responds to `call` method if the block parameter
  //      represents a iseq/ifunc block. Otherwise, same as `getblockparam`.
  //  */
  // getblockparamproxy
  // (lindex_t idx, rb_num_t level)
  // ()
  // (VALUE val)
  return function(args) {
    try {
      let orig_idx = vm.GET_OPERAND(1).toInt32()
      let level = _level === undefined ? vm.GET_OPERAND(2) : ptr(_level);

      let iseq = vm.GET_ISEQ()
      let local_table_size = vm.native.get_local_table_size_at_level(iseq, level);

      //        3                 4               6
      // VM_ENV_DATA_SIZE + local_table_size - (orig_idx+1)

      // orig_idx: 6 -> ? -> idx:0 -> a 
      // orig_idx: 5 -> ? -> idx:1 -> b
      // orig_idx: 4 -> ? -> idx:2 -> c
      // orig_idx: 3 -> ? -> idx:3 -> d

      let idx =  VM_ENV_DATA_SIZE + local_table_size - (orig_idx + 1);

      // log(">> " + funcname + " iseq: " + iseq)
      // log(">> " + funcname + " idx: " + idx);
      // log(">> " + funcname + " level: " + level.toString(10));
      // log(">> " + funcname + " local_table_size: " + local_table_size);

      let lid = vm.native.local_var_id(iseq, level, idx);
      // log(">> " + funcname + " lid: " + lid)

      // VALUE name = rb_id2str(lid);
      let name = r.rb_id2str(lid);
      let name_str;
      if (name.isNull()) {
        // if (!name) {
        //     name = rb_str_new_cstr("?");
        // }
        name_str = "?";
      } else if (!r.rb_str_symname_p(name)) {
        // else if (!rb_str_symname_p(name)) {
        //     name = rb_str_inspect(name);
        // }
        name_str = r.ruby_str_to_js_str(r.rb_str_inspect(name));
      } else {
        // else {
        //     name = rb_str_dup(name);
        // }
        name_str = r.ruby_str_to_js_str(name);
      }

      // log(">> pc: " + vm.GET_PC())
      log(">> " + funcname + " " + name_str + "@idx:" + idx + "(raw:" + orig_idx + ")[" + (idx+1).toString() + "/" + (local_table_size) + "], level:" + level.toString(10));
      vm.return_callback = leave(funcname);
    } catch (e) {
      log("Error [" + funcname + "]: " + String(e))
    }
  }
}