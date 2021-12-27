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


module.exports = function(args) {
  // /* set global variable id as val. */
  // ruby 2.6-2.7
  // setglobal
  // (GENTRY entry)
  // (VALUE val)
  // ()

  // ruby 3.0
  // setglobal
  // (ID gid)
  // (VALUE val)
  // ()

  try {
    // ruby 2.6
    // SET_GLOBAL((VALUE)entry, val); // #define SET_GLOBAL(entry, val)  rb_gvar_set((struct rb_global_entry*)(entry), (val))

    // ruby 2.7 (equivalent to ruby 2.6)
    // struct rb_global_entry *gentry = (void *)entry;
    // rb_gvar_set(gentry, val);

    // ruby 3.0
    // val = rb_gvar_get(gid);

    let gid;
    switch (vm.ruby_version) {
      case 26:
      case 27: {
        let gentry_p = vm.GET_OPERAND(1)
        gid = vm.native.rb_global_entry__id(gentry_p)
        break;
      }
      case 30:
      case 31:
      default: {
        gid = vm.GET_OPERAND(1)
      }
    }
    let gid_str = r.rb_id2name(gid).readUtf8String()

    let val = vm.TOPN(0)
    let val_inspect = r.rb_inspect2(val);

    log(">> setglobal :" + gid_str + ", (" + val_inspect + ")");
  } catch (e) {
    log("Error [setglobal]: " + String(e))
  }
}