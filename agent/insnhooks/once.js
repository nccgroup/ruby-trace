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

//note: normally, we wouldn't get the return of iseq-calling insns outside of
//      their leave insns, but in this case, when the value is cached after the
//      first run, we need to get it from the actual insn itself b/c the iseq
//      won't actually be called again
let leave = function() {
  try {
    let val_p = vm.TOPN(0);
    let val_inspect = r.rb_inspect2(val_p);
    log(">> once -> " + val_inspect);
  } catch (e) {
    log("Error [once->leave]: " + String(e))
  }
}

module.exports = function(args) {
  // /* run iseq only once */
  // once
  // (ISEQ iseq, ISE ise)
  // ()
  // (VALUE val)
  try {
    if (indent_s === null) {
      indent_s = r.rb_str_new_cstr(indent_p);
    }

    let cfp = vm.GET_CFP()
    let iseq_p = vm.GET_OPERAND(1, cfp)
    let ise_p = vm.GET_OPERAND(2, cfp) // union iseq_inline_storage_entry

    let running_thread = vm.native.iseq_inline_storage_entry__once_running_thread(ise_p)

    let ran = false;
    if (ptr(0x1).equals(running_thread)) {
      ran = true;
    } else if (running_thread.isNull()) {
      //ran = false;
    } else {
      let ec_p = vm.GET_EC(cfp)
      let th_p = vm.native.rb_execution_context_struct__thread_ptr(ec_p);
      //log(">> once: th: " + th_p);
      if (th_p.equals(running_thread)) { //TODO: come up w/ a test case for this
        ran = false;
      } else {
        // still running, hasn't finished
        // but this is probably not the first call
        ran = true;
      }
    }

    if (ran) {
      log(">> once iseq: " + iseq_p + ", ise->once.running_thread: " + running_thread + " (already run)");
      vm.return_callback = leave;
    } else {
      // rb_iseq_t*
      let iseq_rstr = r.rb_iseq_disasm_recursive(iseq_p, indent_s)
      let iseq_str = r.ruby_str_to_js_str(iseq_rstr).trim()

      log(">> once iseq: " + iseq_p + ", ise->once.running_thread: " + running_thread + "\n" + iseq_str);
    }
  } catch (e) {
    log("Error [once]: " + String(e))
  }
}