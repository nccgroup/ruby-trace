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

// let leave = function() {
//   let val_p = vm.TOPN(0);
//   let val_inspect = r.rb_inspect2(val_p);
//   log(">> defineclass -> " + val_inspect + " (raw: " + val_p + ")");
// }

const rb_vm_defineclass_type = {
  0x00: "VM_DEFINECLASS_TYPE_CLASS",
  0x01: "VM_DEFINECLASS_TYPE_SINGLETON_CLASS",
  0x02: "VM_DEFINECLASS_TYPE_MODULE",
  0x03: "RESERVED",
  0x04: "RESERVED",
  0x05: "RESERVED",
  0x06: "RESERVED",
  0x07: "RESERVED",
}

const VM_DEFINECLASS_TYPE_MASK = 0x07;

const VM_DEFINECLASS_FLAG_SCOPED = 0x08
const VM_DEFINECLASS_FLAG_HAS_SUPERCLASS = 0x10

let indent_p = Memory.allocUtf8String("   ");
let indent_s = null;

module.exports = function(args) {
  //note: this comment is likely wrong/outdated, it doesn't seem like super is
  //      ever Qfalse, and instead is either nil or a class type
  // /* enter class definition scope. if super is Qfalse, and class
  //    "klass" is defined, it's redefine. otherwise, define "klass" class.
  //  */
  // defineclass
  // (ID id, ISEQ class_iseq, rb_num_t flags)
  // (VALUE cbase, VALUE super)
  // (VALUE val) //
  try {
    if (indent_s === null) {
      indent_s = r.rb_str_new_cstr(indent_p);
    }

    let id_p = vm.GET_OPERAND(1)
    let class_iseq_p = vm.GET_OPERAND(2)
    // let flags = vm.GET_OPERAND(3)
    // let defineclass_type = rb_vm_defineclass_type[parseInt(flags.and(VM_DEFINECLASS_TYPE_MASK).toString())]
    let flags = parseInt(vm.GET_OPERAND(3).toString())
    let defineclass_type = rb_vm_defineclass_type[flags & VM_DEFINECLASS_TYPE_MASK]

    let specific_flags = ""

    switch (defineclass_type) {
      case "VM_DEFINECLASS_TYPE_CLASS": {
        if ((flags & VM_DEFINECLASS_FLAG_HAS_SUPERCLASS) != 0) {
          specific_flags += "|VM_DEFINECLASS_FLAG_HAS_SUPERCLASS"
        }
        if ((flags & VM_DEFINECLASS_FLAG_SCOPED) != 0) {
          specific_flags += "|VM_DEFINECLASS_FLAG_SCOPED"
        }
        break;
      }
      case "VM_DEFINECLASS_TYPE_SINGLETON_CLASS": {
        break;
      }
      case "VM_DEFINECLASS_TYPE_MODULE": {
        if ((flags & VM_DEFINECLASS_FLAG_SCOPED) != 0) {
          specific_flags += "|VM_DEFINECLASS_FLAG_SCOPED"
        }
        break;
      }
    }

    let id = r.rb_id2name(id_p).readUtf8String();

    let super_str = r.rb_inspect2(vm.TOPN(0))
    let cbase_str = r.rb_inspect2(vm.TOPN(1))
    
    // rb_iseq_t*
    let iseq_rstr = r.rb_iseq_disasm_recursive(class_iseq_p, indent_s)
    let iseq_str = r.ruby_str_to_js_str(iseq_rstr).trim()

    log(">> defineclass id: :" + id + ", class_iseq: " + class_iseq_p +
        ", flags: " + flags + " (" + defineclass_type + specific_flags +
        "), cbase: " + cbase_str + ", super: " + super_str + "\n" +
        iseq_str);
    // vm.return_callback = leave;
    //note: due to the semantics of defineclass, it doesn't itself have a
    //      return value pushed on the stack, and instead, it looks like
    //      it redirects control to the next instruction before the templated
    //      insn suffix that puts val (not even set in the code) onto the stack
  } catch (e) {
    log("Error [defineclass]: " + String(e))
  }
}