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
  log(">> checktype -> " + val_inspect);
}

const ruby_value_type = {
  0x00: 'T_NONE',
  0x01: 'T_OBJECT',
  0x02: 'T_CLASS',
  0x03: 'T_MODULE',
  0x04: 'T_FLOAT',
  0x05: 'T_STRING',
  0x06: 'T_REGEXP',
  0x07: 'T_ARRAY',
  0x08: 'T_HASH',
  0x09: 'T_STRUCT',
  0x0a: 'T_BIGNUM',
  0x0b: 'T_FILE',
  0x0c: 'T_DATA',
  0x0d: 'T_MATCH',
  0x0e: 'T_COMPLEX',
  0x0f: 'T_RATIONAL',
  0x10: 'UNKNOWN',
  0x11: 'T_NIL',
  0x12: 'T_TRUE',
  0x13: 'T_FALSE',
  0x14: 'T_SYMBOL',
  0x15: 'T_FIXNUM',
  0x16: 'T_UNDEF',
  0x17: 'UNKNOWN',
  0x18: 'UNKNOWN',
  0x19: 'UNKNOWN',
  0x1a: 'T_IMEMO',
  0x1b: 'T_NODE',
  0x1c: 'T_ICLASS',
  0x1d: 'T_ZOMBIE',
  0x1e: 'T_MOVED',
  0x1f: 'UNKNOWN',
}

const T_MASK = 0x1f

module.exports = function(args) {
  // /* check if val is type. */
  // checktype
  // (rb_num_t type)
  // (VALUE val)
  // (VALUE ret)
  try {
    //note: there doesn't seem to be a simple way from this point in execution
    //      to get the actual method signature, which could be used to get the
    //      keyword name based on the keyword index
    let type = parseInt(vm.GET_OPERAND(1).toString())
    let val_str = r.rb_inspect2(vm.TOPN(0))

    let type_str = ruby_value_type[type & T_MASK];
    
    log(">> checktype type: " + type + " (" + type_str + "), val: " + val_str);
    vm.return_callback = leave;
  } catch (e) {
    log("Error [checktype]: " + String(e))
  }
}