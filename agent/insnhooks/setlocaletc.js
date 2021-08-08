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

const VM_ENV_DATA_SIZE = 3

module.exports = function(funcname, _level) {
  // /* Set a local variable (pointed to by 'idx') as val.
  //    'level' indicates the nesting depth from the current block.
  //  */
  // setlocal
  // (lindex_t idx, rb_num_t level)
  // (VALUE val)
  // ()

  // /* Set block parameter. */
  // setblockparam
  // (lindex_t idx, rb_num_t level)
  // (VALUE val)
  // ()
  return function(args) {
    try {
      let orig_idx = vm.GET_OPERAND(1).toInt32()
      let level = _level === undefined ? vm.GET_OPERAND(2) : ptr(_level);

      let iseq = vm.GET_ISEQ()
      let local_table_size = vm.native.get_local_table_size_at_level(iseq, level);

      let idx =  VM_ENV_DATA_SIZE + local_table_size - (orig_idx + 1);
      let lid = vm.native.local_var_id(iseq, level, idx);

      let name = r.rb_id2str(lid);
      let name_str;
      if (name.isNull()) {
        name_str = "?";
      } else if (!r.rb_str_symname_p(name)) {
        name_str = r.ruby_str_to_js_str(r.rb_str_inspect(name));
      } else {
        name_str = r.ruby_str_to_js_str(name);
      }

      let val_p = vm.TOPN(0)
      let val_inspect = r.rb_inspect2(val_p);

      log(">> " + funcname + " " + name_str + "@idx:" + idx + "(raw:" + orig_idx + ")[" + (idx+1).toString() + "/" + (local_table_size) + "], level:" + level.toString(10) + ", val: (" + val_inspect + ")");
    } catch (e) {
      log("Error [" + funcname + "]: " + String(e))
    }
  }
}