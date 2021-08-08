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

const INSN_ATTR_width = 0x18 //note: not sure if this changes w/ arch

function addr_for_offset(pc, off) {
  return (pc + INSN_ATTR_width) + (off*Process.pointerSize)
}

function offset_from_addrs(orig_pc, cur_pc) {
  return (cur_pc - (orig_pc + INSN_ATTR_width)) / Process.pointerSize
}

/*
function cdhash_parse(s) {
  // {"goodbye"=>30, "hello"=>34, ",\"=>"=>38, 1=>42}

  let obj = {}

  let pos = 0, rpos = 0;
outer:
  while (true) {
    pos = s.indexOf('"', rpos+1)
    if (pos == -1) break;
    rpos = s.indexOf('"', pos+1)
    if (rpos == -1) break;

    while (s[rpos-1] == "\\") {
      rpos = s.indexOf('"', rpos+1)
      if (rpos == -1) break outer;
    }

    let key = s.slice(pos+1, rpos);

    pos = s.indexOf('=>', rpos+1)
    if (pos == -1) break;
    rpos = s.indexOf(',', pos+2)
    if (rpos == -1) {
      rpos = s.indexOf('}', pos+2)
    }
    let val = s.slice(pos+2, rpos);

    obj[key] = parseInt(val);
  }

  return obj;
}
*/

// function cdhash_to_obj(hash) {
//   let hash_ary = r.rb_hash_to_a(hash)
//   let hash_ary_inspect = r.rb_inspect2(hash_ary)
//   log(">> hash_ary_inspect: " + hash_ary_inspect)

//   let hash_ary_json = r.json_dump(hash_ary)
//   if (hash_ary_json == null) {
//     return null;
//   }
//   log(">> hash_ary_json: " + JSON.stringify(hash_ary_json))

//   let hash_ary_js = JSON.parse(hash_ary_json)

//   let obj = {};
//   for (let [k,v] of hash_ary_js) {
//     obj[k] = v;
//   }
//   return obj;
// }

function leave(log_msg, fallthrough, orig_pc, else_offset, hash_inv) {
  return function() {
    try {
      if (fallthrough) {
        log(log_msg)
        return;
      }

      let cfp = vm.GET_CFP()
      let cur_pc = parseInt(vm.GET_PC(cfp).toString())

      let actual_offset = offset_from_addrs(orig_pc, cur_pc)
      // log(">> actual_offset: " + actual_offset + ", else_offset: " + else_offset)
      if (actual_offset == else_offset) {
        log_msg += "; path taken: else"
      } else {
        let hash_inv_j = JSON.parse(hash_inv);
        log_msg += "; path taken: " + String(hash_inv_j[actual_offset]);
      }
      log_msg += " (0x" + orig_pc + "->0x" + cur_pc + ")"
      log(log_msg)
    } catch (e) {
      log(log_msg)
      log("Error [opt_case_dispatch->leave]: " + String(e))
    } 
  }
}

module.exports = function(args) {
  // /* case dispatcher, jump by table if possible */
  // DEFINE_INSN
  // opt_case_dispatch
  // (CDHASH hash, OFFSET else_offset)
  // (..., VALUE key)
  // ()
  // // attr rb_snum_t sp_inc = -1;
  try {
    let cfp = vm.GET_CFP()
    let hash = vm.GET_OPERAND(1, cfp)
    let raw_else_offset = vm.GET_OPERAND(2, cfp)
    let else_offset = (Number)(BigInt64Array.from([raw_else_offset])[0])

    let cur_pc = parseInt(vm.GET_PC(cfp).toString())

    let key = vm.TOPN(0);
    let key_inspect = r.rb_inspect2(key)

    //note: the "hash" we get here isn't a full ruby object.
    //      we can call some hash stuff on it directly, but can't go through
    //      rb_funcallv. rb_hash_dup does not give us anything useful. we
    //      could use rb_hash_to_a and then json-ify that to re-parse
    //      on the js side, but then we can't handle string/:symbol collision
    //      and large numbers. so instead, we are just going to reimplement
    //      vm_case_dispatch to set up for rb_hash_aref.
    let hash_inspect = r.ruby_str_to_js_str(r.rb_hash_inspect(hash))

    let key_type = r.RB_OBJ_BUILTIN_TYPE(key)
    // log(">> opt_case_dispatch key: " + key_inspect + " (type:" + key_type + "), hash: " + hash_inspect)

    // let alt_key_type = vm.native.rb_obj_builtin_type(key, r.USE_FLONUM ? 1 : 0);
    // log(">> opt_case_dispatch alt_key_type: " + alt_key_type)
    // log(">> opt_case_dispatch: GET_VM()->negative_cme_table offset: " + vm.native.get_offset())

    let fallthrough = false;
    let redefined = false;

    let hash_ary = r.rb_hash_to_a(hash)
    let hash_inv = r.ruby_trace_hash_inverter(hash_ary)
  
    switch (key_type) {
      case -1:
      case r.T_STRING:
      case r.T_BIGNUM:
      case r.T_SYMBOL:
      case r.T_FLOAT: { 
        if (vm.BASIC_OP_UNREDEFINED_P(vm.BOP_EQQ,
          vm.SYMBOL_REDEFINED_OP_FLAG | vm.INTEGER_REDEFINED_OP_FLAG |
          vm.FLOAT_REDEFINED_OP_FLAG | vm.NIL_REDEFINED_OP_FLAG |
          vm.TRUE_REDEFINED_OP_FLAG | vm.FALSE_REDEFINED_OP_FLAG |
          vm.STRING_REDEFINED_OP_FLAG)
        ) {
          //pass
        } else {
          redefined = true;
          fallthrough = true;
        }
        break;
      }
      default:
        fallthrough = true;
        break;
    }

    let log_msg = ">> opt_case_dispatch key: " + key_inspect + " (type:" + key_type + "), hash: " + hash_inspect;

    if (fallthrough) {
      log_msg += "; path taken: fall through" + (redefined ? " (:=== redefined)" : "");
    }
    
    vm.return_callback = leave(log_msg, fallthrough, cur_pc, else_offset, hash_inv);


    // return;
    // let path_offset = null;
    // if (key_type == r.T_STRING || key_type == r.T_SYMBOL) {
    //   // we can safely do an aref lookup to differentiate between str and :sym
    //   path_offset = r.rb_hash_aref(hash, key);
    //   if (r.RB_NIL_P(path_offset)) {
    //     path_offset = else_offset;
    //   }
    // } else {
    //   // we can jsonify regardless of str/:sym conflation
    //   let hash_js = cdhash_to_obj(hash);
    //   log(">> hash_js: " + JSON.stringify(hash_js))
    //   if (hash_js != null) {
    //     let key_json = r.json_dump(key);
    //     let key_js = JSON.parse(key_json);
  
    //     path_offset = hash_js[key_js] || else_offset;
    //   }
    // }

    // if (path_offset == null) {
    //   log(">> opt_case_dispatch key: " + key_inspect + ", hash: " + hash_inspect + ", else_offset: " + else_offset)
    // } else {
    //   if (path_offset != else_offset) {
    //     let path_pc = addr_for_offset(cur_pc, path_offset) 
    //     log(">> opt_case_dispatch key: " + key_inspect + ", hash: " + hash_inspect + ", else_offset: " + else_offset + "; path taken: when " + key_inspect + " (0x" + cur_pc + "->0x" + path_pc + ")")        
    //   } else {
    //     let else_pc = addr_for_offset(cur_pc, else_offset) 
    //     log(">> opt_case_dispatch key: " + key_inspect + ", hash: " + hash_inspect + ", else_offset: " + else_offset + "; path taken: else (0x" + cur_pc + "->0x" + else_pc + ")")
    //   }
    // }

  } catch (e) {
    log("Error [opt_case_dispatch]: " + String(e))
    let cfp = vm.GET_CFP()
    let hash = vm.GET_OPERAND(1, cfp)
    let key = vm.TOPN(0);
    let key_inspect = r.rb_inspect2(key)
    let hash_inspect = r.ruby_str_to_js_str(r.rb_hash_inspect(hash))

    log("Error [opt_case_dispatch]: " + String(e) + " for key: " + key_inspect + ", hash: " + hash_inspect)
  }
}