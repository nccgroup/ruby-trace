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

// send, opt_send_without_block, invokesuper
let call_ops = require('./call_ops')
let basic_opts = require('./basic_opts');

module.exports = {
  "nop": require("./nop"),
  "putnil": require("./putnil"),
  "putstring": require('./putstring'),
  "getinstancevariable": require("./getinstancevariable"),
  "setinstancevariable": require("./setinstancevariable"),
  "getlocal": require("./getlocaletc")("getlocal"),
  "getlocal_WC_0": require("./getlocaletc")("getlocal_WC_0", 0),
  "getlocal_WC_1": require("./getlocaletc")("getlocal_WC_1", 1),
  "getblockparam": require("./getlocaletc")("getblockparam"),
  "getblockparamproxy": require("./getlocaletc")("getblockparamproxy"),
  "setlocal": require("./setlocaletc")("setlocal"),
  "setlocal_WC_0": require("./setlocaletc")("setlocal_WC_0", 0),
  "setlocal_WC_1": require("./setlocaletc")("setlocal_WC_1", 1),
  "setblockparam": require("./setlocaletc")("setblockparam"),
  "getspecial": require("./getspecial"),
  "setspecial": require("./setspecial"),
  "getclassvariable": require("./getclassvariable"),
  "setclassvariable": require("./setclassvariable"),
  "getconstant": require("./getconstant"),
  "setconstant": require("./setconstant"),
  "getglobal": require("./getglobal"),
  "setglobal": require("./setglobal"),
  "putself": require("./putself"),
  "putobject": require("./putobject")("putobject"),
  "putobject_INT2FIX_0_": require("./putobject")("putobject_INT2FIX_0_"),
  "putobject_INT2FIX_1_": require("./putobject")("putobject_INT2FIX_1_"),
  "putspecialobject": require("./putspecialobject"),
  "putiseq": require("./putiseq"),
  "concatstrings": require("./concatstrings"),
  "tostring": require("./tostring")("tostring"),
  "anytostring": require("./tostring")("anytostring"),
  "objtostring": require("./objtostring"),
  "freezestring": require("./freezestring"),
  "toregexp": require("./toregexp"),
  "intern": require("./intern"),
  "newarray": require("./newarray"),
  "newarraykwsplat": require("./newarraykwsplat"),
  "duparray": require("./duparray"),
  "duphash": require("./duphash"),
  "expandarray": require("./expandarray"),
  "concatarray": require("./concatarray"),
  "splatarray": require("./splatarray"),
  "newhash": require("./newhash"),
  "newrange": require("./newrange"),
  "pop": require("./pop"),
  "dup": require("./dup"),
  "dupn": require("./dupn"),
  "swap": require("./swap"),
  "reverse": require("./reverse"),
  "reput": require("./reput"),
  "topn": require("./topn"),
  "setn": require("./setn"),
  "adjuststack": require("./adjuststack"),
  "defined": require("./defined"),
  "checkmatch": require("./checkmatch"),
  "checkkeyword": require("./checkkeyword"),
  "checktype": require("./checktype"),
  "defineclass": require("./defineclass"),
  "definemethod": require("./definemethod"),
  "definesmethod": require("./definesmethod"),
  "send": call_ops("send"),
  "opt_send_without_block": call_ops("opt_send_without_block"),
  "opt_str_freeze": require("./opt_str_freeze"),
  "opt_nil_p": require("./opt_nil_p"),
  "opt_str_uminus": require("./opt_str_uminus"),
  "opt_newarray_max": require("./opt_newarray_minmax")("opt_newarray_max"),
  "opt_newarray_min": require("./opt_newarray_minmax")("opt_newarray_min"),
  "invokesuper": call_ops("invokesuper"),
  "invokeblock": call_ops("invokeblock"),
  "leave": require("./leave"),
  "throw": require("./throw"),
  "jump": require("./jump"),
  "branchif": require("./branchif"),
  "branchunless": require("./branchunless"),
  "branchnil": require("./branchnil"),
  "opt_getinlinecache": require("./opt_getinlinecache"),
  "opt_setinlinecache": require("./opt_setinlinecache"),
  "once": require("./once"),
  "opt_case_dispatch": require("./opt_case_dispatch"),

  "opt_plus": basic_opts("opt_plus", "+"),
  "opt_minus": basic_opts("opt_minus", "-"),
  "opt_mult": basic_opts("opt_mult", "*"),
  "opt_div": basic_opts("opt_dif", "/"),
  "opt_mod": basic_opts("opt_mod", "%"),
  "opt_eq": basic_opts("opt_eq", "=="),
  "opt_neq": basic_opts("opt_neq", "!="),
  "opt_lt": basic_opts("opt_lt", "<"),
  "opt_le": basic_opts("opt_le", "<="),
  "opt_gt": basic_opts("opt_gt", ">"),
  "opt_ge": basic_opts("opt_ge", ">="),
  "opt_ltlt": basic_opts("opt_ltlt", "<<"),
  "opt_and": basic_opts("opt_and", "&"),
  "opt_or": basic_opts("opt_or", "|"),
  "opt_aref": require("./opt_aref"),
  "opt_aset": require("./opt_aset"),
  "opt_aref_with": require("./opt_aref_with"),
  "opt_aset_with": require("./opt_aset_with"),
  "opt_length": require("./opt_name")("opt_length", "length"),
  "opt_size": require("./opt_name")("opt_size", "size"),
  "opt_empty_p": require("./opt_name")("opt_empty_p", "empty?"),
  "opt_succ": require("./opt_name")("opt_succ", "succ"),
  "opt_not": require("./opt_name")("opt_not", "!"),
  "opt_regexpmatch1": require("./opt_regexpmatch1"),
  "opt_regexpmatch2": require("./opt_regexpmatch2"),
  "opt_call_c_function": require("./opt_call_c_function"),

  "bitblt": require("./bitblt"),
  "answer": require("./answer"),

  "invokebuiltin": require("./invokebuiltin"),
  "opt_invokebuiltin_delegate": require("./opt_invokebuiltin_delegate"),
  "opt_invokebuiltin_delegate_leave": require("./opt_invokebuiltin_delegate_leave"),
}