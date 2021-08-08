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

let indent_p = Memory.allocUtf8String("   ");
let indent_s = null;

module.exports = function(args) {
  // definesmethod
  // (ID id, ISEQ iseq)
  // (VALUE obj)
  // ()
  try {
    if (indent_s === null) {
      indent_s = r.rb_str_new_cstr(indent_p);
    }

    let id_p = vm.GET_OPERAND(1)
    let iseq_p = vm.GET_OPERAND(2)

    let obj_str = r.rb_inspect2(vm.TOPN(0))

    let id = r.rb_id2name(id_p).readUtf8String();
    
    // rb_iseq_t*
    let iseq_rstr = r.rb_iseq_disasm_recursive(iseq_p, indent_s)
    let iseq_str = r.ruby_str_to_js_str(iseq_rstr).trim()

    log(">> definesmethod id: :" + id + ", iseq: " + iseq_p + ", obj: " + obj_str + "\n" + iseq_str);
  } catch (e) {
    log("Error [definesmethod]: " + String(e))
  }
}