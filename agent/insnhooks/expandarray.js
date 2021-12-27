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

let leave = function(num) {
  return function() {
    let out = [] 
    let sp = vm.GET_SP();
    for (let i=0; i < num; i++) {
      let val_p = vm.TOPN(i, sp);
      let val_inspect = r.rb_inspect2(val_p);
      out.push("TOPN(" + i + "): " + val_inspect);
    }
    let out_str = ">> expandarray -> " + out.join("\n               -> ")
    log(out_str)
  }
}

module.exports = function(args) {
  // /* if TOS is an array expand, expand it to num objects.
  //    if the number of the array is less than num, push nils to fill.
  //    if it is greater than num, exceeding elements are dropped.
  //    unless TOS is an array, push num - 1 nils.
  //    if flags is non-zero, push the array of the rest elements.
  //    flag: 0x01 - rest args array // aka is_splat
  //    flag: 0x02 - for postarg
  //    flag: 0x04 - reverse?
  //  */
  // expandarray
  // (rb_num_t num, rb_num_t flag)
  // (..., VALUE ary)
  // (...)
  // // attr rb_snum_t sp_inc = (rb_snum_t)num - 1 + (flag & 1 ? 1 : 0);
  try {
    let num = parseInt(vm.GET_OPERAND(1).toString())
    let flag = parseInt(vm.GET_OPERAND(2).toString())
    let sp = vm.GET_SP();
    let ary = vm.TOPN(0, sp)

    let ptr;
    let len;
    let obj = ary;

    let flags = [];
    let is_splat = (flag & 0x01) != 0;
    if (is_splat) {
      flags.push("is_splat");
    }
    if ((flag & 0x04) != 0) {
      flags.push("reverse");
    }
    let space_size = num + (is_splat ? 1 : 0);
    // let base = sp.sub(1*Process.pointerSize);

    let b1 = false;
    if (!r.RB_TYPE_P_array(ary)) {
      ary = r.rb_check_array_type(ary);
      if (r.RB_NIL_P(ary)) {
        b1 = true;
      }
    }
    
    if (b1) {
      // log(">> b1: true path")
      ary = obj;
      ptr = Memory.alloc(1*Process.pointerSize);
      ptr.writePointer(ary);
      len = 1;
    } else {
      // log(">> b1: false path")
      ptr = r.rb_array_const_ptr_transient(ary)
      len = r.rb_array_len(ary);
    }

    let arr = [];
    let arr_inspect = null;
    if (space_size == 0) {
      log(">> space_size == 0 path")
      //note: not sure this can actually happen
      //pass
      arr_inspect = r.rb_inspect2(ary)
    } else if (flag & 0x2) { // postarg
      // in this case, num is the number of post splat args
      // log(">> space_size != 0 && flag & 0x2 path")

      /* post: ..., nil ,ary[-1], ..., ary[0..-num] # top */
      let i = 0;
      let j = 0;

      if (len < num) {
        for (; i<(num-len); i++) {
          // base.writePointer(r.Qnil);
          // base = base.add(1*Process.pointerSize);
          arr.push("nil");
        }
      }

      for (; i < num; i++, j++) {
        let v = ptr.add((len - j - 1)*Process.pointerSize).readPointer();
        // base.writePointer(v);
        // base = base.add(1*Process.pointerSize);
        arr.push(r.rb_inspect2(v));
      }

      if (is_splat) {
        let nary = r.rb_ary_new_from_values(len-j, ptr);
        //base.writePointer(nary);
        arr.push(r.rb_inspect2(nary));
      }

      flags.push("postarg");
    } else {
      // log(">> space_size != 0 && else path")
      /* normal: ary[num..-1], ary[num-2], ary[num-3], ..., ary[0] # top */
      let i = 0;
      // let bptr = base.add((space_size-1)*Process.pointerSize)
      for (; i<num; i++) {
        if (len <= i) {
          for (; i<num; i++) {
            // base.writePointer(r.Qnil);
            // base = base.sub(1*Process.pointerSize);
            arr.unshift("nil");
          }
          break;
        }
        // base.writePointer(ptr.add(i*Process.pointerSize).readPointer());
        // base = base.sub(1*Process.pointerSize);
        arr.unshift(r.rb_inspect2(ptr.add(i*Process.pointerSize).readPointer()))
      }
      if (is_splat) {
        if (num > len) {
          // bptr.writePointer(r.rb_ary_new());
          arr.unshift("[]");
        }
        else {
          let v = ptr.add(num*Process.pointerSize);
          // log(">> v: " + v.toString())
          // log(">> v: " + v.toString(16))
          let nary = r.rb_ary_new_from_values(len - num, ptr.add(num*Process.pointerSize));
          //base.writePointer(nary);
          arr.unshift(r.rb_inspect2(nary));
        }
      }
    }

    if (arr_inspect == null) {
      arr_inspect = "[ " + arr.join(', ') + " ]"
    }

    let flag_str = "";
    if (flags.length > 0) {
      flag_str = " (" + flags.join("|") + ")";
    }
    
    let ary_inspect = r.rb_inspect2(ary)
    log(">> expandarray num: " + num + ", flag: " + flag + flag_str + ", ary: " + ary_inspect + ", expansion: " + arr_inspect + " (bottom->top)");
    vm.return_callback = leave(space_size);
  } catch (e) {
    log("Error [expandarray]: " + String(e))
  }
}