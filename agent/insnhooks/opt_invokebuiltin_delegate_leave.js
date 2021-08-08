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
  log(">> opt_invokebuiltin_delegate_leave -> " + val_inspect);
};

//note: this should be correct, but, when tracing, ruby converts
//      opt_invokebuiltin_delegate_leave into opt_invokebuiltin_delegate
//TODO: re-add support for full trace/arbitrarily controlled trace w/o relying
//      on tracepoint/trace func infra

module.exports = function(args) {
  // /* call specific function with args (same parameters) and leave */
  // opt_invokebuiltin_delegate_leave [2.7+]
  // (RB_BUILTIN bf, rb_num_t index)
  // ()
  // (VALUE val)
  // // attr bool leaf = false; /* anything can happen inside */
  try {
    let bf = vm.GET_OPERAND(1)
    let index = vm.GET_OPERAND(2)

    let func_ptr = vm.native.rb_builtin_function__func_ptr(bf)
    let func_ptr_name = r.get_func_name(func_ptr)

    let name = vm.native.rb_builtin_function__name(bf).readUtf8String()
    
    log(">> opt_invokebuiltin_delegate_leave \"" + name + "\" (" + func_ptr_name + "), index: " + index);

    vm.return_callback = leave;
  } catch (e) {
    log("Error [opt_invokebuiltin_delegate_leave]: " + String(e))
  }
}