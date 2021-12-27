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
  log(">> defined -> " + val_inspect);
}

const defined_type = [
  "DEFINED_NOT_DEFINED",
  "DEFINED_NIL",
  "DEFINED_IVAR",
  "DEFINED_LVAR",
  "DEFINED_GVAR",
  "DEFINED_CVAR",
  "DEFINED_CONST",
  "DEFINED_METHOD",
  "DEFINED_YIELD",
  "DEFINED_ZSUPER",
  "DEFINED_SELF",
  "DEFINED_TRUE",
  "DEFINED_FALSE",
  "DEFINED_ASGN",
  "DEFINED_EXPR",
  "DEFINED_IVAR2",
  "DEFINED_REF",
  "DEFINED_FUNC",
  "DEFINED_CONST_FROM"
];

module.exports = function(args) {
  // /* defined? */
  // ruby 2.6-3.0
  // defined
  // (rb_num_t op_type, VALUE obj, VALUE needstr)
  // (VALUE v)
  // (VALUE val)

  // ruby 3.1
  // defined
  // (rb_num_t op_type, VALUE obj, VALUE pushval)
  // (VALUE v)
  // (VALUE val)

  //note: previously, defined/vm_defined would take a bool to determine if
  //      instead of a simple true/false, you wanted the string representation
  //      of the type in iseq terms (e.g. "constant", "instance-variable",
  //      "assignment", etc.) and it would map to it semi-statically via
  //      rb_iseq_defined_string, generating the str VALUE as needed. now,
  //      vm_defined returns a flat bool and the defined insn itself takes a
  //      string argument to return if vm_defined returns true. so while it
  //      doesn't really seem like the old vm_defined would return determine
  //      expr_types to be all that different from ob_type, that logic now is
  //      likely baked into the iseq compiler, which was arguably already doing
  //      a lot of lifting to power defined?. the problem here is that by
  //      inlining the full str VALUE into the iseq instead of what was a bool
  //      VALUE that likely needs to be its own copy, memory could get a bit
  //      bloated. it is worth noting that in the old impl,
  //      rb_iseq_defined_string did some work to make sure that, for the most
  //      part, the strings were shared frozen globals, and similarly, the str
  //      VALUEs in the new impl are frozen and share object IDs. the other
  //      difference is that true VALUE is used for cases where a string is not
  //      wanted, such as in if expressions, instead of false, because if the
  //      thing is defined you want true and if it isn't, you get nil anyway.
  //
  //      the tradeoff here seems to be doing the string lookup "once" and
  //      passing effectively a pointer to a string instead of pulling one out
  //      by index at runtime (and ignoring the weird dynamic allocation thing
  //      that probably wouldn't have worked that well anyway). so if you have
  //      a lot of define?s in your code, but rarely actually call any of them,
  //      then the old version is probably faster overall, but if you have only
  //      a few, or call them a ton from the same methods, then the new version
  //      may be faster. this probably should have been documented, especially
  //      what they used to benchmark it since this is exactly the sort of
  //      thing microbenchmarks would steer to a completely wrong conclusion.
  // ruby 3.0:
  // 0033 defined                                instance-variable, :@c, true
  // 0038 defined                                constant, :D, true
  // 0049 defined                                func, :foo, false

  // ruby 3.1:
  // 0033 defined                                instance-variable, :@c, "instance-variable"
  // 0038 defined                                constant, :D, "constant"
  // 0049 defined                                func, :foo, true
  try {
    let op_type = parseInt(vm.GET_OPERAND(1).toString())
    if (defined_type[op_type] !== undefined) {
      op_type = defined_type[op_type];
    }
    let obj = r.rb_inspect2(vm.GET_OPERAND(2))

    let needstr_pushval = r.rb_inspect2(vm.GET_OPERAND(3))

    let v = r.rb_inspect2(vm.TOPN(0))

    switch (vm.ruby_version) {
      case 26:
      case 27:
      case 30: {
        log(">> defined op_type: " + op_type + ", obj: " + obj + ", needstr: " + needstr_pushval + ", v: " + v);
        break;
      }
      case 31:
      default: {
        log(">> defined op_type: " + op_type + ", obj: " + obj + ", pushval: " + needstr_pushval + ", v: " + v);
      }
    }
    vm.return_callback = leave;
  } catch (e) {
    log("Error [defined]: " + String(e))
  }
}