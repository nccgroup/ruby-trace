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

let libc = require('./libc')()
let { log } = libc

const VALUE = 'pointer';
const VALUE_ptr = 'pointer';
const ID = 'pointer';

const eval_p = Memory.allocUtf8String("eval");
const puts_p = Memory.allocUtf8String("puts");
const to_s_p = Memory.allocUtf8String("to_s");
const inspect_p = Memory.allocUtf8String("inspect");
const cause_p = Memory.allocUtf8String("cause");
const dump_p = Memory.allocUtf8String("dump");
const json_p = Memory.allocUtf8String("JSON");
const __ruby_trace_inspect_p = Memory.allocUtf8String("__ruby_trace_inspect");
const __ruby_trace_hash_inverter_p = Memory.allocUtf8String("__ruby_trace_hash_inverter");

const hash_inspect_exclusion = new Set([
  "rb_hash_aref"
]);

const static_inspect_exclusion = new Set([
  "thread_s_current",
  "nil_to_h"
]);

class Ruby {
  constructor (libruby) {
    let self = this;
    libc.r = this;
    this.libruby = libruby;
    this.vm = null;
    this.hooks = null;
    this.rb_define_method_metadatas = {}
    this.rb_define_module_function_metadatas = {}
    this.funcall_enabled = true;
    this.funcall_tripwire = false;
    this.runtime_init_funcs = []
    this.dyn_inspecting = false;

    this.sym_to_addr_map = {};
    this.addr_to_sym_map = {};
    this.insns_address_table = null;
    this.rb_ec_tag_jump_list = []
    this.vm_sendish = null;

    this.inspect_map = {}
    this.to_s_map = {}
    this.to_s_list = []
    this.inspect_alias_list = []

    this.Qtrue = null;
    this.Qfalse = null;
    this.USE_FLONUM = null;
    this.Qnil = null;
    this.Qundef = null;
    this.RUBY_IMMEDIATE_MASK = null;
    this.RUBY_FIXNUM_FLAG = null;
    this.RUBY_FLONUM_MASK = null;
    this.RUBY_FLONUM_FLAG = null;
    this.RUBY_SYMBOL_FLAG = null;
    this.RUBY_SPECIAL_SHIFT = 8;

    this.T_NONE = 0x0
    this.T_OBJECT = 0x1
    this.T_CLASS = 0x2
    this.T_MODULE = 0x3
    this.T_FLOAT = 0x4
    this.T_STRING = 0x5
    this.T_REGEXP = 0x6
    this.T_ARRAY = 0x7
    this.T_HASH = 0x8
    this.T_STRUCT = 0x9
    this.T_BIGNUM = 0xa
    this.T_FILE = 0xb
    this.T_DATA = 0xc
    this.T_MATCH = 0xd
    this.T_COMPLEX = 0xe
    this.T_RATIONAL = 0xf
    this.T_NIL = 0x11
    this.T_TRUE = 0x12
    this.T_FALSE = 0x13
    this.T_SYMBOL = 0x14
    this.T_FIXNUM = 0x15
    this.T_UNDEF = 0x16

    this.T_IMEMO = 0x1a
    this.T_NODE = 0x1b
    this.T_ICLASS = 0x1c
    this.T_ZOMBIE = 0x1d
    this.T_MOVED = 0x1e

    this.T_MASK = 0x1f

    this.RUBY_FL_USHIFT = 12
    //#define RUBY_FL_USER_N(n) RUBY_FL_USER##n = (1<<(RUBY_FL_USHIFT+n))
    //ROBJECT_EMBED = RUBY_FL_USER1
    //RARRAY_EMBED_FLAG = RUBY_FL_USER1
    this.ROBJECT_EMBED = (1<<(this.RUBY_FL_USHIFT+1));
    this.RARRAY_EMBED_FLAG = (1<<(this.RUBY_FL_USHIFT+1));
    //RARRAY_EMBED_LEN_SHIFT = (RUBY_FL_USHIFT+3)
    this.RARRAY_EMBED_LEN_SHIFT = this.RUBY_FL_USHIFT+3;
    //RARRAY_EMBED_LEN_MASK = (RUBY_FL_USER4|RUBY_FL_USER3)
    this.RARRAY_EMBED_LEN_MASK = (1<<(this.RUBY_FL_USHIFT+4))|(1<<(this.RUBY_FL_USHIFT+3));

    this.code = `
    #include <stddef.h>
    #include <stdint.h>
    typedef size_t VALUE;

    struct /*RUBY_ALIGNAS(SIZEOF_VALUE)*/ RBasic {
      VALUE flags;
      const VALUE klass;
    };

    #define RARRAY_EMBED_LEN_MAX 3

    struct RArray {
      struct RBasic basic;
      union {
        struct {
          long len;
          union {
            long capa;
            VALUE shared;
          } aux;
          const VALUE *ptr;
        } heap;
        const VALUE ary[RARRAY_EMBED_LEN_MAX];
      } as;
    };

    VALUE RBasic__flags(VALUE obj) {
      return ((struct RBasic*)obj)->flags;
    }

    size_t RArray__as_heap_len(VALUE obj) {
      return (size_t)(((struct RArray*)obj)->as.heap.len);
    }

    const VALUE* RArray__as_ary(VALUE obj) {
      return ((struct RArray*)obj)->as.ary;
    }

    const VALUE* RArray__as_heap_ptr(VALUE obj) {
      return ((struct RArray*)obj)->as.heap.ptr;
    }
    `;
    this.cm = new CModule(this.code);
    this.RBasic__flags = new NativeFunction(this.cm.RBasic__flags, VALUE, [VALUE]);
    this.RArray__as_heap_len = new NativeFunction(this.cm.RArray__as_heap_len, 'size_t', [VALUE]);
    this.RArray__as_ary = new NativeFunction(this.cm.RArray__as_ary, 'pointer', [VALUE]);
    this.RArray__as_heap_ptr = new NativeFunction(this.cm.RArray__as_heap_ptr, 'pointer', [VALUE]);

    var syms = libruby.enumerateSymbols()
    for (var i = 0; i < syms.length ; i++) {
      if (ptr(0x0).equals(syms[i].address)) {
        // console.log(">>>> " + syms[i].name + " has address of 0")
        continue
      }
      this.sym_to_addr_map[syms[i].name] = syms[i];
      this.addr_to_sym_map[syms[i].address] = syms[i];
      if (syms[i].name.startsWith("rb_ec_tag_jump")) {
        this.rb_ec_tag_jump_list.push(syms[i])
      } else if (syms[i].name.startsWith("vm_sendish")) {
        this.vm_sendish = syms[i]
      }
    }

    this.eval_sym = null;
    this.puts_sym = null;
    this.to_s_sym = null;
    this.dump_sym = null;
    this.json_sym = null;

    this.cause_id = null;
    this.loaded = false;

    //this.rb_funcallv_ptr = libruby.getExportByName('rb_funcallv')
    this.rb_funcallv_ptr = this.sym_to_addr_map['rb_funcallv'].address
    // console.log("by name: " + libruby.getExportByName('rb_funcallv').toString())
    // console.log("by symbol: " + this.sym_to_addr_map['rb_funcallv'].address.toString())
    this.rb_funcallv = new NativeFunction(this.rb_funcallv_ptr, VALUE, [VALUE, ID, 'int', VALUE]);
    // this.rb_bug_ptr = this.sym_to_addr_map['rb_bug'].address;
    // this.rb_bug = new NativeFunction(this.rb_bug_ptr, 'void', ['pointer']);
    // this.rb_bug_context_ptr = this.sym_to_addr_map['rb_bug_context'].address;
    // this.rb_bug_context = new NativeFunction(this.rb_bug_context_ptr, 'void', ['pointer', 'pointer']);
    // this.abort_ptr = libc.libc.getExportByName('abort');

    // this.rb_funcallv = new NativeFunction(this.rb_funcallv_ptr, VALUE, [VALUE, ID, 'int', VALUE]);
    this.iterate_method_addr = this.sym_to_addr_map['iterate_method'].address;
    this.rb_define_module_function = new NativeFunction(libruby.getExportByName('rb_define_module_function'), 'void', [VALUE, 'pointer', 'pointer', 'int']);

    this.rb_str_new_cstr = new NativeFunction(libruby.getExportByName('rb_str_new_cstr'), VALUE, ['pointer']);
    this.rb_str_empty = new NativeFunction(this.sym_to_addr_map['rb_str_empty'].address, VALUE, [VALUE]);
    this.rb_type = new NativeFunction(this.sym_to_addr_map['rb_type'].address, 'int', [VALUE]);
    this.rb_class_of = new NativeFunction(this.sym_to_addr_map['rb_class_of'].address, VALUE, [VALUE]);
    this.rb_class_inherited_p = new NativeFunction(libruby.getExportByName('rb_class_inherited_p'), VALUE, [VALUE, VALUE]);
    this.rb_obj_is_kind_of = new NativeFunction(libruby.getExportByName('rb_obj_is_kind_of'), VALUE, [VALUE, VALUE]);

    this.rb_intern = new NativeFunction(libruby.getExportByName('rb_intern'), ID, ['pointer']);
    this.rb_string_value_cstr = new NativeFunction(libruby.getExportByName('rb_string_value_cstr'), 'pointer', [VALUE_ptr]);
    this.rb_sym2str = new NativeFunction(libruby.getExportByName('rb_sym2str'), VALUE, [VALUE]);
    this.rb_marshal_dump = new NativeFunction(libruby.getExportByName('rb_marshal_dump'), VALUE, [VALUE, /*VALUE*/'int']);

    this.rb_const_get = new NativeFunction(libruby.getExportByName('rb_const_get'), VALUE, [VALUE, ID]);

    this.rb_obj_class = new NativeFunction(libruby.getExportByName('rb_obj_class'), VALUE, [VALUE]);
    this.rb_obj_id = new NativeFunction(libruby.getExportByName('rb_obj_id'), VALUE, [VALUE]);
    this.rb_obj_is_proc = new NativeFunction(libruby.getExportByName('rb_obj_is_proc'), VALUE, [VALUE])
    this.rb_id2str = new NativeFunction(libruby.getExportByName('rb_id2str'), VALUE, [ID]);
    this.rb_str_symname_p = new NativeFunction(this.sym_to_addr_map['rb_str_symname_p'].address, 'int', [VALUE]);
    this.rb_id2name = new NativeFunction(libruby.getExportByName('rb_id2name'), 'pointer', [ID]);
    this.rb_any_to_s = new NativeFunction(libruby.getExportByName('rb_any_to_s'), VALUE, [VALUE]);
    this.rb_num2ull = new NativeFunction(libruby.getExportByName('rb_num2ull'), 'pointer', [VALUE]);
    this.rb_inspect_p = libruby.getExportByName('rb_inspect')
    this.rb_inspect = new NativeFunction(libruby.getExportByName('rb_inspect'), VALUE, [VALUE]);
    this.rb_obj_inspect = new NativeFunction(this.sym_to_addr_map['rb_obj_inspect'].address, VALUE, [VALUE]);
    this.rb_reg_inspect = new NativeFunction(this.sym_to_addr_map['rb_reg_inspect'].address, VALUE, [VALUE]);
    this.rb_ary_inspect = new NativeFunction(this.sym_to_addr_map['rb_ary_inspect'].address, VALUE, [VALUE]);
    this.rb_int2str = new NativeFunction(this.sym_to_addr_map['rb_int2str'].address, VALUE, [VALUE, 'int']);
    this.rb_struct_inspect = new NativeFunction(this.sym_to_addr_map['rb_struct_inspect'].address, VALUE, [VALUE]);
    this.flo_to_s = new NativeFunction(this.sym_to_addr_map['flo_to_s'].address, VALUE, [VALUE]);
    this.rb_hash_dup = new NativeFunction(libruby.getExportByName('rb_hash_dup'), VALUE, [VALUE]);
    this.rb_hash_to_a = new NativeFunction(this.sym_to_addr_map['rb_hash_to_a'].address, VALUE, [VALUE]);
    this.rb_hash_aref = new NativeFunction(libruby.getExportByName('rb_hash_aref'), VALUE, [VALUE, VALUE]);

    this.rb_check_array_type = new NativeFunction(libruby.getExportByName('rb_check_array_type'), VALUE, [VALUE]);
    this.rb_ary_new_from_values = new NativeFunction(libruby.getExportByName('rb_ary_new_from_values'), VALUE, ['long', 'pointer']);
    this.rb_ary_new = new NativeFunction(libruby.getExportByName('rb_ary_new'), VALUE, []);
    this.rb_hash_inspect = new NativeFunction(this.sym_to_addr_map['rb_hash_inspect'].address, VALUE, [VALUE]);
    this.rb_mod_name = new NativeFunction(libruby.getExportByName('rb_mod_name'), VALUE, [VALUE]);
    this.rb_mod_to_s = new NativeFunction(this.sym_to_addr_map['rb_mod_to_s'].address, VALUE, [VALUE]);
    this.rb_attr_get = new NativeFunction(libruby.getExportByName('rb_attr_get'), VALUE, [VALUE, ID])

    this.rb_iseq_disasm = new NativeFunction(libruby.getExportByName('rb_iseq_disasm'), VALUE, ['pointer']);
    this.rb_iseq_disasm_recursive = new NativeFunction(this.sym_to_addr_map['rb_iseq_disasm_recursive'].address, VALUE, ['pointer', VALUE]);

    this.rb_require = new NativeFunction(libruby.getExportByName('rb_require'), VALUE, ['pointer'])

    this.rb_errinfo = new NativeFunction(libruby.getExportByName('rb_errinfo'), VALUE, [])
    this.rb_set_errinfo = new NativeFunction(libruby.getExportByName('rb_set_errinfo'), 'void', [VALUE])

    this.rb_rescue = new NativeFunction(libruby.getExportByName('rb_rescue'), VALUE, ['pointer', VALUE, 'pointer', VALUE])
    this.rb_rescue2 = new NativeFunction(libruby.getExportByName('rb_rescue2'), VALUE, ['pointer', VALUE, 'pointer', VALUE, '...', VALUE, 'int'])
    //this.rb_rescue2 = new NativeFunction(libruby.getExportByName('rb_rescue2'), VALUE, ['pointer', VALUE, 'pointer', VALUE, VALUE, 'int'])
    this.rescue_func = new NativeCallback((obj/*, ex*/) => {
      log(">> Error [caught in rescue_func]: "/* + ex*/)
      return self.Qnil;
    }, VALUE, [VALUE/*, VALUE*/])
    this.rescue_func2 = new NativeCallback((obj, ex) => {
      log(">> Error [caught in rescue_func2]")
      return self.Qnil;
    }, VALUE, [VALUE, VALUE])
    this.funcallv_wrapper = new NativeCallback((obj) => {
      let arg0 = obj.readPointer();
      let arg1 = obj.add(1 * Process.pointerSize).readPointer()
      let arg2 = obj.add(2 * Process.pointerSize).readInt()
      let arg3 = obj.add(3 * Process.pointerSize).readPointer()

      return self.rb_funcallv(arg0, arg1, arg2, arg3);
    }, VALUE, ['pointer'])
    this.rb_funcallv2 = function(arg0, arg1, arg2, arg3) {
      let arr = Memory.alloc(4*Process.pointerSize);
      arr.writePointer(arg0);
      arr.add(1 * Process.pointerSize).writePointer(arg1);
      arr.add(2 * Process.pointerSize).writeInt(arg2);
      arr.add(3 * Process.pointerSize).writePointer(arg3);

      //return self.rb_rescue2(self.funcallv_wrapper, arr, self.rescue_func, arr, self.rb_cObject, 0);
      return self.rb_rescue(self.funcallv_wrapper, arr, self.rescue_func, arr);
    }
    this.rb_inspect_r = function(obj) {
      let ret = self.rb_rescue2(self.rb_inspect_p, obj, self.rescue_func, obj, self.rb_cObject, 0);
      //let ret = self.rb_rescue2(self.rb_inspect_p, obj, self.rescue_func, obj, self.rb_eException, 0);
      //let ret = self.rb_rescue(self.rb_inspect_p, obj, self.rescue_func, obj);
      log(">> rb_inspect_r: ret: " + self.ruby_str_to_js_str(ret))
      return ret;
    }

    this.rb_str_inspect = new NativeFunction(libruby.getExportByName('rb_str_inspect'), VALUE, [VALUE]);
    this.rb_gc_disable = new NativeFunction(libruby.getExportByName('rb_gc_disable'), VALUE, []);
    this.rb_gc_enable = new NativeFunction(libruby.getExportByName('rb_gc_enable'), VALUE, []);

    try {
      this.rb_ractor_main_p_ = new NativeFunction(libruby.getExportByName('rb_ractor_main_p_'), 'bool', []);
      this.ruby_single_main_ractor = new NativePointer(libruby.getExportByName('ruby_single_main_ractor'));
    } catch (e) {
      this.rb_ractor_main_p_ = null
      this.ruby_single_main_ractor = null
    }


    this.rb_mKernel = new NativePointer(libruby.getExportByName('rb_mKernel'));
    this.rb_cObject = new NativePointer(libruby.getExportByName('rb_cObject'));
    this.rb_cString = new NativePointer(libruby.getExportByName('rb_cString'));
    this.rb_cRegexp = new NativePointer(libruby.getExportByName('rb_cRegexp'));
    this.rb_eException = new NativePointer(libruby.getExportByName('rb_eException'));

    //this.vm_ci_dump = new NativeFunction(this.sym_to_addr_map['vm_ci_dump'].address, 'void', ['pointer']);

  
    //note: because of the way ruby loads, we can't just hook the return to
    //      ruby_setup/ruby_init to init ourselves, as, by that point,
    //      rb_define_method will have been called for all the core classes.
    //      instead, we hook the entry of Init_Object, which is the first
    //      higher-level init function after the lower level init functions are
    //      called to start of the core of ruby vm/runtime. Since our own init
    //      only really needs rb_intern, we could hook the return of Init_sym,
    //      which initializes ID handling for ruby, or the entry/exit of
    //      Init_var_tables, which is the last low level init function before
    //      Init_Object, but given that Init_Object is a seemingly stable point
    //      in the ruby startup flow, we use that as our anchor point for our
    //      core setup.
    let ruby_setup_hook = Interceptor.attach(self.sym_to_addr_map['Init_Object'].address, function(args) {
      // log(">> Init_Object hit")
      for (let runtime_init_func of self.runtime_init_funcs) {
        try {
          runtime_init_func()
        } catch (e) {
          log("Error: runtime_init_func: " + String(e))
        }
      }
    })
    
    // let rb_hash_stlike_lookup_hook = Interceptor.attach(libruby.getExportByName('rb_hash_stlike_lookup'), function(args) {
    //   log(">> rb_hash_stlike_lookup called!")
    // })

    this.runtime_init_funcs.push(function() {
      // log(">> ruby.js runtime_init_func")

      self.eval_sym = self.rb_intern(eval_p);
      self.puts_sym = self.rb_intern(puts_p);
      self.to_s_sym = self.rb_intern(to_s_p);
      self.inspect_sym = self.rb_intern(inspect_p);
      self.cause_sym = self.rb_intern(cause_p)
      self.dump_sym = self.rb_intern(dump_p);
      self.json_sym = self.rb_intern(json_p);
      self.__ruby_trace_inspect_sym = self.rb_intern(__ruby_trace_inspect_p);
      self.__ruby_trace_hash_inverter_sym = self.rb_intern(__ruby_trace_hash_inverter_p);

      self.loaded = true;
  
      let empty_str_p = Memory.allocUtf8String("")
      let empty_rb_str = self.rb_str_new_cstr(empty_str_p);
      let nonempty_str_p = Memory.allocUtf8String("_")
      let nonempty_rb_str = self.rb_str_new_cstr(nonempty_str_p);   
      self.Qtrue = self.rb_str_empty(empty_rb_str)
      self.Qfalse = self.rb_str_empty(nonempty_rb_str)

      // let code = `
      // #include <stdint.h>
      // #include <stdio.h>
      // int flonum_test(void* _rb_float_new_inline) {
      //   size_t (*rb_float_new_inline)(double) = _rb_float_new_inline;
  
      //   union {
      //     double d;
      //     size_t v;
      //   } t;
      //   t.v = 0;
      //   if (rb_float_new_inline(t.d) == 0x8000000000000002) {
      //     return 1;
      //   } else {
      //     return 0;
      //   }
      // }
      // `;
      // this.cm = new CModule(code);
      // let flonum_test = new NativeFunction(this.cm.flonum_test, 'int', ['pointer']);
      // self.USE_FLONUM = flonum_test(self.sym_to_addr_map['rb_float_new_inline'].address) == 1;
      self.USE_FLONUM = self.Qtrue.equals(ptr(0x14))
      if (self.USE_FLONUM) {
        self.Qnil = ptr(0x8);
        self.Qundef = ptr(0x34)
        self.RUBY_IMMEDIATE_MASK = 0x7;
        self.RUBY_FIXNUM_FLAG = 0x1;
        self.RUBY_FLONUM_MASK = 0x3;
        self.RUBY_FLONUM_FLAG = 0x2;
        self.RUBY_SYMBOL_FLAG = 0xc;
      } else {
        self.Qnil = ptr(4);
        self.Qundef = ptr(6);
        self.RUBY_IMMEDIATE_MASK = 0x3;
        self.RUBY_FIXNUM_FLAG = 0x1;
        self.RUBY_FLONUM_MASK = 0x0;
        self.RUBY_FLONUM_FLAG = 0x2;
        self.RUBY_SYMBOL_FLAG = 0xe;        
      }

      //note: there is a bit of overhead to having to do such a roundabout
      //      way of mapping inspect aliases, but for whatever reason, the
      //      env doesn't appear to be brought up fully enough by the time of
      //      some of the to_s methods being defined that are then aliased
      //      for inspect. this prevents us from getting the class names at
      //      that point in time, so we save the klass VALUEs until we can.
      //
      //      arrays are currently used instead of maps to prevent frida from
      //      stringifying the NativePointer klass.
      //
      //      we could handle things other than to_s, but the problem is that
      //      we would need to hold on to every single one of them waiting
      //      for the alias function to be called.
      // let to_s_map = {}
      // for (let [k, v] of self.to_s_list) {
      //   let klass_inspect = self.ruby_str_to_js_str(self.ruby_inspect(k))
      //   let klass_str = self.get_class_name(k)
      //   if (klass_inspect != klass_str) {
      //     console.log("[ruby_setup]: klass_inspect != klass_str: '" + klass_inspect + "' != '" + klass_str + "'")
      //   }
      //   to_s_map[klass_str] = v;
      // }

      // for (let k of self.inspect_alias_list) {
      //   let klass_str = self.get_class_name(k);
      //   self.inspect_map[klass_str] = to_s_map[klass_str];
      // }
      //note: the above was happening too late after the change to Init_Object.
      //      the pieces are now moved into the hooks for rb_define_method and
      //      rb_define_alias.

      // should free up some space
      self.to_s_list = []
      self.inspect_alias_list = []

      // note: we hook rb_funcallv with Interceptor.replace so that we can
      //       bail out safely by returning nil in the event that it is
      //       called during a critical region (i.e. rb_vm_call0) wherein
      //       the ruby send infra can't be called into safely. we track this
      //       region with funcall_enabled (set by disable_funcall()/enable_funcall()).
      Interceptor.replace(self.rb_funcallv_ptr, new NativeCallback((recv, mid, argc, argv) => {
        if (self.funcall_enabled) {
          //log(">> mod rb_funcallv called -> call real");
          return self.rb_funcallv(recv, mid, argc, argv);
        } else {
          //log(">> mod rb_funcallv called -> return nil");
          self.set_funcall_tripwire();
          return self.Qnil;
        }
      }, VALUE, [VALUE, ID, 'int', VALUE]));
      // Interceptor.replace(self.rb_bug_ptr, new NativeCallback((fmt) => {
      //   let fmt_str = Memory.readUtf8String(fmt);
      //   console.log('>> caught rb_bug: "' + fmt_str + '"');
      // }, 'void', ['pointer']));
      // Interceptor.replace(self.rb_bug_context_ptr, new NativeCallback((ctx, fmt) => {
      //   let fmt_str = Memory.readUtf8String(fmt);
      //   console.log('>> caught rb_bug_context: "' + fmt_str + '"');
      // }, 'void', ['pointer', 'pointer']));
      // Interceptor.replace(self.abort_ptr, new NativeCallback(() => {
      //   console.log('>> caught abort()');
      // }, 'void', []));

      ruby_setup_hook.detach();
    })

    let rb_define_method_hook = Interceptor.attach(libruby.getExportByName('rb_define_method'), function(args) {
      // void rb_define_method(VALUE klass, const char *name, VALUE (*func)(ANYARGS), int argc)
      // if (!self.load_stuff()) {
      //   log(">> rb_define_method_hook called load_stuff out of order")
      // }

      let name = args[1].readUtf8String();
      let klass = args[0];
      // let klass_str = self.get_class_name(klass);

      let func_p = args[2];
      let argc = args[3].toInt32()

      if (name == "inspect" || name == "to_s") {
        if (name == "to_s") {
          // note: all inspect methods have arity 0 (at least for now).
          //       however, to_s for some classes takes args, such as Integer
          //       for its base
          let func;
          if (argc == -1) {
            // int argc, VALUE *argv, VALUE x
            func = new NativeFunction(args[2], VALUE, ['int', VALUE, VALUE]);
          } else if (argc == -2) {
            // VALUE argf, VALUE argv
            // not used for to_s (at least for now)
            func = new NativeFunction(args[2], VALUE, [VALUE, VALUE]);
          } else {
            func = new NativeFunction(args[2], VALUE, [VALUE]);
          }

          self.to_s_list.push([klass, {argc, func}]);

          // let klass_inspect = self.rb_inspect2(klass)
          try {
            let klass_str = self.get_class_name_safe(klass)
            self.to_s_map[klass_str] = {argc, func};
          } catch (e) {
            log("Error [rb_define_method_hook]: " + String(e))
          }
          // if (klass_inspect != klass_str) {
          //   console.log("[ruby_setup]: klass_inspect != klass_str: '" + klass_inspect + "' != '" + klass_str + "'")
          // }
          // self.to_s_map[klass_str] = {argc, func};
        } else {
          let klass_str = self.get_class_name_safe(klass);
          //console.log("[rb_define_method]: " + klass_str + ".inspect")
          let func = new NativeFunction(args[2], VALUE, [VALUE]);
          self.inspect_map[klass_str] = { argc, func };  
        }
      }

      //note: hooking all of these results in extremely verbose output
      //TODO: implement a flag to enable/disable such hooking. in the case
      //      of disable, remove cfunc hooks after they return so they are
      //      only hooked on each instance of the ruby->c transition
      //return;

      if (!(func_p in self.rb_define_method_metadatas)) {
        let func_s = self.get_func_name(func_p);

        let metadata = {
          method: {
            mid: name,
          },
          cfunc: {
            func_p,
            func_s,
            def_argc: argc, // actually the one used to register the cfunc
            rt_argc: /*call_info_orig_argc*/ null // runtime argc // we special case this on null
          }
        };
        self.rb_define_method_metadatas[func_p] = metadata
        if (self.hooks !== null) {
          if (func_p in self.hooks.cfunc_hooks_metadatas) {
            delete self.hooks.cfunc_hooks_metadatas[func_p]
          }

          if (self.hooks.tracing()) {
            // log(">> hooking cfunc via rb_define_method_hook")
            self.hooks.hook_cfunc(metadata);
          }
        }
      }
    });

    let rb_define_module_function_hook = Interceptor.attach(libruby.getExportByName('rb_define_module_function'), function(args) {
      // void rb_define_module_function(VALUE module, const char *name, VALUE (*func)(ANYARGS), int argc)

      let name = args[1].readUtf8String();
      //let module = args[0];

      let func_p = args[2];
      let argc = args[3].toInt32()

      // if (!(func_p in hooks.cfunc_hooks_metadatas)
      //     && !(func_p in r.rb_define_method_metadatas)
      //     && !(func_p in r.rb_define_module_function_metadatas)) {
      if (!(func_p in self.rb_define_module_function_metadatas)) {
        let func_s = self.get_func_name(func_p);
        // log(">> rb_define_module_function: name: " + name + ", func_s: " + func_s)

        let metadata = {
          method: {
            mid: name,
          },
          cfunc: {
            func_p,
            func_s,
            def_argc: argc, // actually the one used to register the cfunc
            rt_argc: /*call_info_orig_argc*/ null // runtime argc // we special case this on null
          }
        };
        self.rb_define_module_function_metadatas[func_p] = metadata
        if (self.hooks !== null) {
          if (func_p in self.hooks.cfunc_hooks_metadatas) {
            delete self.hooks.cfunc_hooks_metadatas[func_p]
          }

          if (self.hooks.tracing()) {
            // log(">> hooking cfunc " + func_s + " via rb_define_module_function_hook in ruby.js")
            self.hooks.hook_cfunc(metadata);
          }
        }
      } else {
        // let func_s = self.get_func_name(func_p);
        // log(">> wat: " + func_s)
      }
    });

    let rb_define_alias_hook = Interceptor.attach(libruby.getExportByName('rb_define_alias'), function(args) {
      // void rb_define_alias(VALUE klass, const char *name1, const char *name2)
      // if (!self.load_stuff()) {
      //   log(">> rb_define_alias_hook called load_stuff out of order")
      // }

      let name1 = args[1].readUtf8String();
      if (name1 != "inspect") {
        return;
      }

      let name2 = args[2].readUtf8String();
      if (name2 != "to_s") {
        return;
      }

      let klass = args[0];
      self.inspect_alias_list.push(klass)

      let klass_str = self.get_class_name_safe(klass);
      self.inspect_map[klass_str] = self.to_s_map[klass_str];
    });

    
    // let rb_f_require_hook = Interceptor.attach(libruby.getExportByName('rb_f_require'), function(args) {

    //   let fname = args[1];
    //   let fname_str = self.ruby_str_to_js_str(fname);

    //   log(">> rb_f_require: fname: " + fname_str)
    // });

    // let rb_imemo_new_hook = Interceptor.attach(libruby.getExportByName('rb_imemo_new'), {
    //   onEnter: function(args) {
    //     try {
    //       let v1 = args[1]
    //       let v1_str;
    //       if (v1.isNull()) {
    //         return;
    //         // v1_str = "NULL";
    //       } else {
    //         v1_str = self.dyn_inspect(v1);
    //       }
    //       log(">> rb_imemo_new(..., " + v1_str + ", ...)")
    //     } catch (e) {
    //       console.error("Error [rb_imemo_new.onEnter]: " + String(e))
    //     }
    //   },
    //   onLeave: function(retval) {
    //     try {
    //       log(">> rb_imemo_new -> " + retval + ": " + self.rb_inspect2(retval))
    //     } catch (e) {
    //       console.error("Error [rb_imemo_new.onLeave]: " + String(e))
    //     }
    //   }['onEnter']
    // })

  }

  load_stuff() {
    if (!this.loaded) {
      log(">> out of order load")
      //throw "out of order load";
      return false;
    } else {
      return true;
    }
    return;
    if (this.loaded) {
      return;
    }
    this.eval_sym = this.rb_intern(eval_p);
    this.puts_sym = this.rb_intern(puts_p);
    this.to_s_sym = this.rb_intern(to_s_p);
    this.inspect_sym = this.rb_intern(inspect_p);
    this.cause_sym = this.rb_intern(cause_p)
    this.loaded = true;
  }

  disable_funcall() {
    if (!this.funcall_enabled) {
      log("[ruby] disable_funcall() called when funcall_enabled is false");
    }
    this.funcall_enabled = false;
  }

  clear_funcall_tripwire() {
    this.funcall_tripwire = false;
  }
  set_funcall_tripwire() {
    this.funcall_tripwire = true;
  }
  did_funcall_trip() {
    return this.funcall_tripwire;
  }

  enable_funcall() {
    if (this.funcall_enabled) {
      log("[ruby] enable_funcall() called when funcall_enabled is true");
    }
    this.funcall_enabled = true;
  }

  get_class_name(klass) {
    this.inspecting = true;
    try {
      let klass_str = this.ruby_str_to_js_str(this.ruby_to_s(klass))
      if (klass_str.startsWith("#<Class:#")) {
        //pass
      } else if (klass_str.startsWith("#<Class:") && !klass_str.startsWith("#<Class:0x")) {
        //pass
      } else if (klass_str.startsWith("#")) {
        klass_str = this.ruby_str_to_js_str(this.rb_mod_name(klass))
      }
      return klass_str;
    } finally {
      this.inspecting = false;
    }
  }

  get_class_name_safe(klass) {
    this.inspecting = true;
    try {
      let klass_str = this.ruby_str_to_js_str(this.rb_mod_to_s(klass))
      if (klass_str.startsWith("#<Class:#")) {
        //pass
      } else if (klass_str.startsWith("#<Class:") && !klass_str.startsWith("#<Class:0x")) {
        //pass
      } else if (klass_str.startsWith("#")) {
        klass_str = this.ruby_str_to_js_str(this.rb_mod_name(klass))
      }
      return klass_str;
    } finally {
      this.inspecting = false;
    }
  }

  static_inspect(obj, from_dyn_inspect=false, context=null) {
    if (!from_dyn_inspect) {
      this.inspecting = true;
    }
    let type_guess = "";
    try {
      // log(">> static_inspect: obj: " + obj);
  
      // if (obj.equals(ptr(0x1))) {
      //   let t = this.rb_inspect2(obj)
      //   log(">> t: " + t);
      //   return null;
      // }
  
      // if (!this.RB_TEST(obj)) {
      //   //log(">> RB_TEST -> false")
      //   return null;
      // }

      if (context != null && static_inspect_exclusion.has(context)) {
        return "<uninspectable:" + context + "() arg>"
      }

      let ret = null;
      if (!this.RB_SPECIAL_CONST_P(obj)) {
        let type = this.RB_BUILTIN_TYPE(obj);
        // log(">> static_inspect: type: " + type);
        switch (type) {
          case this.T_STRING:
            type_guess = "string";
            ret = this.rb_str_inspect(obj);
            break;
          case this.T_FIXNUM:
          case this.T_BIGNUM:
            type_guess = "fixnum|bignum"
            ret = this.rb_int2str(obj, 10);
            break;
          case this.T_CLASS:
          case this.T_MODULE:
            type_guess = "class|module"
            ret = this.rb_mod_to_s(obj);
            break;
          case this.T_SYMBOL:
            type_guess = "symbol"
            ret = this.rb_sym2str(obj);
            break;
          case this.T_ARRAY: {
            type_guess = "array"
            let klass = this.rb_class_of(obj);
            if (!klass.isNull()) {
              ret = this.rb_ary_inspect(obj);
            } else {
              throw "hidden_object"
            }
            break;
          }
          case this.T_HASH: {
            type_guess = "hash"
            let klass = this.rb_class_of(obj);
            if (!klass.isNull()) {
              if (context != null && hash_inspect_exclusion.has(context)) {
                obj = this.rb_hash_dup(obj)
              }
              ret = this.rb_hash_inspect(obj);  
            } else {
              throw "hidden_object"
            }
            break;
          }
          case this.T_REGEXP:
            type_guess = "regexp"
            ret = this.rb_reg_inspect(obj);
            break;
          case this.T_STRUCT:
            type_guess = "struct"
            ret = this.rb_struct_inspect(obj);
            break;
          case this.T_FLOAT:
            type_guess = "float"
            ret = this.flo_to_s(obj);
            break;
          default:
            type_guess = "unknown_const"
            throw "unknown_const"
            return null;
        }  
      } else if (obj.equals(this.Qfalse)) {
        return "false";
      } else if (obj.equals(this.Qnil)) {
        return "nil";
      } else if (obj.equals(this.Qtrue)) {
        return "true";
      } else if (obj.equals(this.Qundef)) {
        return "<undef>";
      } else if (this.RB_FIXNUM_P(obj)) {
        type_guess = "fixnum"
        ret = this.rb_int2str(obj, 10);
      } else if (this.RB_STATIC_SYM_P(obj)) {
        type_guess = "static_symbol"
        ret = this.rb_sym2str(obj);
      } else if (this.RB_FLONUM_P(obj)) {
        type_guess = "flonum"
        ret = this.flo_to_s(obj);
      } else {
        type_guess = "unknown"
        throw "unknown"
        return null;
      }
  
      //log(">> RB_BUILTIN_TYPE: " + type);
  
      let ret2 = this.ruby_str_to_js_str(ret);
      // log(">> static_inspect -> " + ret2)
      return ret2;
  
    } catch (e) {
      if (from_dyn_inspect) {
        log("Error [static_inspect (from dyn_inspect)]: " + String(e) + " for " + type_guess + ":" + obj)
      } else {
        // log("Error [static_inspect]: " + String(e) + " for " + type_guess + ":" + obj)
      }

      if ((typeof e) != "string") {
        log("Error [static_inspect]: " + String(e) + " for " + type_guess + ":" + obj)
      }
      return "<uninspectable:" + obj + ":type_guess=" + type_guess + ">"; 
      // return -1;
    } finally {
      if (!from_dyn_inspect) {
        this.inspecting = false;
      }
    }
  }

  dyn_inspect(obj) {
    if (obj.equals(this.Qnil)) {
      // log(">> [dyn_inspect]: got nil")
      return "nil";
    }

    this.inspecting = true; //failsafe to prevent weird recursive hooks
    try {
      // let static = this.static_inspect(obj);
      // if (static != null) {
      //   return static;
      // }

      let klass = this.rb_class_of(obj);
      let mod_name = this.rb_mod_name(klass);
      if (mod_name.equals(this.Qnil)) {
        // log(">> dyn_inspect: nod_name nill")
        return this.ruby_str_to_js_str(this.inspect_map["Kernel"]['func'](obj))
      }

      let klass_str = this.ruby_str_to_js_str(mod_name)
      // log(">> dyn_inspect: klass_str: " + klass_str);

      let o = this.inspect_map[klass_str];
      if (o === undefined) {
        // if (this.Qtrue.equals(this.rb_obj_is_kind_of(obj, this.rb_eException.readPointer()))) {
        //   o = this.inspect_map['Exception'];
        // }

        //note: exc_inspect seems to be a problem, so we just recreate what exc_inspect does with
        //      exc_to_s.
        if (this.Qtrue.equals(this.rb_class_inherited_p(klass, this.rb_eException.readPointer()))) {
          let exc_to_s = this.to_s_map['Exception'];

          let msg = exc_to_s['func'](obj)
          return "<#" + this.ruby_str_to_js_str(mod_name) + ": " + this.ruby_str_to_js_str(msg) + ">";
        }
      }

      if (o === undefined) {
        if (["Enumerator", "Range", "Proc", "Integer"].includes(klass_str)) {
          // log(">> dyn_inspect: EPI")
          return this.ruby_str_to_js_str(this.rb_any_to_s(obj))
        }
  
        if (klass_str.startsWith("Enumerator::")) {
          // log(">> dyn_inspect: E::")
          // note: the rb_exec_recursive() call from Enumerator.inspect likely
          //       causes problems for the vm_call context
          return this.ruby_str_to_js_str(this.rb_any_to_s(obj))
        }
  
        // log("[dyn_inspect]: unknown klass_str: " + klass_str);
        return "?:" + this.ruby_str_to_js_str(this.rb_any_to_s(obj))
      }

      switch (this.vm.ruby_version) {
        case null: // if not initialized yet, assume worst case
        case 27: {
          //note: Range are seemingly all sorts of trouble from w/in rb_vm_call0,
          //      but Enumerator and Array causes issues in 2.7 (but not 2.6).
          //
          //      if something breaks in 2.7 where the output is different, look
          //      for calls to rb_vm_call0 and try adding the type of the object
          //      being dyn_inspect-ed here. it's just a super buggy version of
          //      ruby (part of the issue could be that our funcall_tripwire
          //      simply doesn't work for 2.7). 
          if (["Range", "Enumerator", "Array"].includes(klass_str)) {
            return this.ruby_str_to_js_str(this.rb_any_to_s(obj))
          }
        }
        default: {
          if (["Range"].includes(klass_str)) {
            return this.ruby_str_to_js_str(this.rb_any_to_s(obj))
          }
        }
      }

      this.clear_funcall_tripwire()
      let ret;
      // log(">> dyn_inspect: o: " + JSON.stringify(o))
      // log(">> dyn_inspect: " + JSON.stringify(this.addr_to_sym_map[o['func']]))
      if (o['argc'] == -1) {
        // int argc, VALUE *argv, VALUE x
        ret = o['func'](0, ptr(0), obj);
      } else {
        ret = o['func'](obj)
      }
      if (ret.isNull()) {
        return "??:" + klass_str
      } else if (ret.equals(this.Qnil)) {
        return this.ruby_str_to_js_str(this.rb_any_to_s(obj));
      } else if (this.did_funcall_trip()) {
        // log(">> dyn_inspect: funcall tripped")
        return this.ruby_str_to_js_str(this.rb_any_to_s(obj));
      }

      return this.ruby_str_to_js_str(ret)
    } finally {
      this.inspecting = false;
    }
  }

  // ruby_version() { // broken
  //   let id = this.rb_str_new_cstr(Memory.allocUtf8String("RUBY_VERSION"));  
  //   return this.ruby_str_to_js_str(this.rb_inspect(this.rb_const_get(this.rb_cObject, id)))
  // }

  get_sym_name(func_p) {
    let func_sym = this.addr_to_sym_map[func_p];
    if (func_sym !== undefined) {
      return func_sym.name;
    } else {
      return "<unknown>";
    }
  }

  get_func_name(func_p) {
    //TODO: handle symbol aliases
    return this.get_sym_name(func_p) + "[@" + func_p + "]";
  }
  
  ruby_puts(val) {
    if (this.puts_sym == null) {
      console.log("puts_sym: not set up");
      return;
    }
    if (val == null) { return null; }
    let arr = Memory.alloc(Process.pointerSize);
    arr.writePointer(val);
    this.rb_funcallv(this.rb_mKernel, this.puts_sym, 1, arr);
  }

  ruby_call0(obj, id_str) {
    const id_p = Memory.allocUtf8String(id_str);
    let id = this.rb_intern(id_p)
    return this.rb_funcallv(obj, id, 0, ptr(0));
  }

  ruby_inspect(obj) {
    if (this.inspect_sym == null) {
      console.log("inspect_sym: not set up");
      return;
    }
    if (obj == null) { return null; }
    return this.rb_funcallv(obj, this.inspect_sym, 0, ptr(0));
  }

  ruby_trace_inspect(obj) {
    if (this.__ruby_trace_inspect_sym == null) {
      console.log("__ruby_trace_inspect_sym: not set up");
      return;
    }
    if (obj == null) { return null; }
    let arr = Memory.alloc(Process.pointerSize);
    arr.writePointer(obj);
    //libc.puts(">> ruby_trace_inspect() stack: " + (new Error()).stack)
    return this.rb_funcallv(this.rb_mKernel, this.__ruby_trace_inspect_sym, 1, arr);
    //return this.Qnil;
  }

  ruby_trace_hash_inverter(obj) {
    if (this.__ruby_trace_hash_inverter_sym == null) {
      console.log("__ruby_trace_hash_inverter_sym: not set up");
      return;
    }
    if (obj == null) { return null; }
    let arr = Memory.alloc(Process.pointerSize);
    arr.writePointer(obj);
    let val = this.rb_funcallv(this.rb_mKernel, this.__ruby_trace_hash_inverter_sym, 1, arr);
    return this.ruby_str_to_js_str(val);
  }

  rb_inspect2(obj, force=false) {
    //note: rb_inspect uses rb_funcallv internally
    let already_exception = false;
    let ex = this.rb_errinfo();
    if (!ex.isNull() && !ex.equals(this.Qnil)) {
      already_exception = true;
    }

    let klass = this.rb_class_of(obj);
    if (!klass.isNull() || force) {
      let inspect;
      try {
        //inspect = this.rb_inspect(obj)
        //inspect = this.rb_inspect_r(obj)
        // log(">> calling ruby_trace_inspect")
        inspect = this.ruby_trace_inspect(obj)
        //return "TKTK"
      } catch (e) {
        //return "<uncallable>";
        log(">> Error [rb_inspect2]: " + String(e))
        return "<uninspectable of type " + this.rb_inspect3(klass) + ">";
      }
      if (!already_exception) {
        let ex = this.rb_errinfo()
        if (!ex.isNull() && !ex.equals(this.Qnil)) {
          let ex_inspect = this.static_inspect(ex)
          log(">> Error [[rb_inspect]]: Exception raised: " + ex_inspect + " (" + ex + "), inspect ret: " + this.ruby_str_to_js_str(inspect) + " (" + inspect + ")")
          this.rb_set_errinfo(this.Qnil); //note: may need to remove this. unclear...
          // if (inspect != null && !ptr(0).equals(inspect) && !this.Qnil.equals(inspect)) {
          //   return this.ruby_str_to_js_str(inspect);
          // }
          return "<uninspectable of type " + this.rb_inspect3(klass) + ">";
        }  
      }
      return this.ruby_str_to_js_str(inspect)
    } else {
      return "<uncallable (class:null)>";
    }
  }

  rb_inspect3(obj) {
    //note: rb_inspect uses rb_funcallv internally
    let klass = this.rb_class_of(obj);
    if (!klass.isNull()) {
      try {
        return this.ruby_str_to_js_str(this.rb_inspect(obj))
      } catch (e) {
        log(">> Error [rb_inspect3]: " + String(e))
        return "<uninspectable>";
      }
    } else {
      return "<uncallable (class:null) [rb_inspect3]>";
    }
  }

  ruby_to_s(val) {
    if (this.to_s_sym == null) {
      console.log("to_s_sym: not set up");
      return;
    }
    if (val == null) { return null; }
    return this.rb_funcallv(val, this.to_s_sym, 0, ptr(0));
  }
  
  load_json() {
    if (this.json_mod != null) {
      return;
    }
    try {
      let json_req = Memory.allocUtf8String('json');
      this.rb_require(json_req);
      this.json_mod = this.rb_const_get(this.rb_cObject, this.json_sym);
    } catch (e) {
      console.log("[load_json] error: " + String(e))
    }
  }

  json_dump(val) {
    if (this.dump_sym == null) {
      console.log("dump_sym: not set up");
      return;
    }
    this.load_json()
    // if (this.json_mod == null) {
    //   console.log("json_mod: not set up");
    //   return;
    // }
    if (val == null) { return null; }

    let gc_status = this.rb_gc_disable();
    try {
      let arr = Memory.alloc(Process.pointerSize);
      arr.writePointer(val);
      let obj = this.rb_funcallv(this.json_mod, this.dump_sym, 1, arr);
      return this.ruby_str_to_js_str(obj);
    } catch (e) {
      console.log("[json_dump] error: " + String(e))
    } finally {
      if (gc_status.equals(this.Qfalse)) {
        this.rb_gc_enable();
      }
    }
  }

  ruby_str_to_js_str(val) {
    if (val == null) {
      return null;
    } else if (this.Qnil != null && this.Qnil.equals(val)) {
      return null;
    }
    let arr = Memory.alloc(Process.pointerSize);
    arr.writePointer(val);
    let cstr = this.rb_string_value_cstr(arr);
    return cstr.readUtf8String();
  }
  
  ruby_eval(eval_str) {
    if (this.eval_sym == null) {
      console.log("eval_sym: not set up");
      return;
    }
  
    let eval_str_p = Memory.allocUtf8String(eval_str);
    let eval_str_s = this.rb_str_new_cstr(eval_str_p);
  
    let arr = Memory.alloc(Process.pointerSize);
    arr.writePointer(eval_str_s);
  
    let gc_status = this.rb_gc_disable();
    let ret = null;
    try {
      ret = this.rb_funcallv(this.rb_mKernel, this.eval_sym, 1, arr);
    } catch(e) {
      console.log(e);
    }
    if (gc_status.equals(this.Qfalse)) {
      this.rb_gc_enable();
    }
    return ret;
  }

  RB_IMMEDIATE_P(obj) {
    return !obj.and(ptr(this.RUBY_IMMEDIATE_MASK)).isNull();
  }

  RB_TEST(obj) {
    //note: this needs to be done w/ frida's NativePointer
    //      b/c it otherwise requires JS BigInt since the values get truncated
    return !(obj.and(this.Qnil.not()).equals(ptr(0)))
  }

  RB_SPECIAL_CONST_P(obj) {
    // log("RB_IMMEDIATE_P(obj): " + this.RB_IMMEDIATE_P(obj))
    // log("RB_TEST(obj): " + this.RB_TEST(obj))
    return this.RB_IMMEDIATE_P(obj) || !this.RB_TEST(obj);
  }

  RB_FIXNUM_P(obj) {
    return obj.and(this.RUBY_FIXNUM_FLAG);
  }

  RB_FLONUM_P(obj) {
    if (this.USE_FLONUM) {
      return obj.and(this.RUBY_FLONUM_MASK).equals(ptr(this.RUBY_FLONUM_FLAG));
    } else {
      return false;
    }
  }

  RB_BUILTIN_TYPE(obj) {
    //(int)(((struct RBasic*)(x))->flags & RUBY_T_MASK
    let flags = parseInt(this.RBasic__flags(obj).toString());
    return flags & this.T_MASK;
  }

  RB_OBJ_BUILTIN_TYPE(obj) {
    // log(">> RB_OBJ_BUILTIN_TYPE 1: obj: " + obj)
    if (this.RB_SPECIAL_CONST_P(obj)) {
      // log(">> RB_OBJ_BUILTIN_TYPE 2: is special")
      return -1;
    }
    return this.RB_BUILTIN_TYPE(obj);
    // log(">> RB_OBJ_BUILTIN_TYPE 3")
    // let ret = this.RB_BUILTIN_TYPE(obj);
    // log(">> RB_OBJ_BUILTIN_TYPE 4: ret: " + ret)
    // return ret;
    // return this.RB_SPECIAL_CONST_P(obj) ? -1 : this.RB_BUILTIN_TYPE(obj);
  }

  RB_TYPE_P_array(obj) {
    return !this.RB_SPECIAL_CONST_P(obj) && (this.RB_BUILTIN_TYPE(obj) == (this.T_ARRAY));
  }

  rb_array_const_ptr_transient(a) {
    // return FIX_CONST_VALUE_PTR((RBASIC(a)->flags & RARRAY_EMBED_FLAG) ?
    //                            RARRAY(a)->as.ary : RARRAY(a)->as.heap.ptr);
    let flags = this.RBasic__flags(a);
    if (flags & this.RARRAY_EMBED_FLAG) {
      //log(">> rb_array_const_ptr_transient -> RARRAY_EMBED_FLAG");
      return this.RArray__as_ary(a);
    } else {
      //log(">> rb_array_const_ptr_transient -> !RARRAY_EMBED_FLAG");
      return this.RArray__as_heap_ptr(a);
    }
  }

  RARRAY_EMBED_LEN(a, _flags = null) {
    //#define RARRAY_EMBED_LEN(a) \
    //(long)((RBASIC(a)->flags >> RARRAY_EMBED_LEN_SHIFT) & \
    //(RARRAY_EMBED_LEN_MASK >> RARRAY_EMBED_LEN_SHIFT))
    let flags = _flags || this.RBasic__flags(a);
    return (flags >> this.RARRAY_EMBED_LEN_SHIFT) & (this.RARRAY_EMBED_LEN_MASK >> this.RARRAY_EMBED_LEN_SHIFT);
  }

  rb_array_len(a) {
    // return (RBASIC(a)->flags & RARRAY_EMBED_FLAG) ? RARRAY_EMBED_LEN(a) : RARRAY(a)->as.heap.len;
    let flags = this.RBasic__flags(a);
    if (flags & this.RARRAY_EMBED_FLAG) {
      return this.RARRAY_EMBED_LEN(a, flags);
    } else {
      return this.RArray__as_heap_len(a);
    }
  }

  RB_NIL_P(v) {
    //!((VALUE)(v) != RUBY_Qnil)
    return this.Qnil.equals(v);
  }

  RB_STATIC_SYM_P(obj) {
    //(((VALUE)(x)&~((~(VALUE)0)<<RUBY_SPECIAL_SHIFT)) == RUBY_SYMBOL_FLAG)
    //const VALUE mask = ~(RBIMPL_VALUE_FULL << RUBY_SPECIAL_SHIFT);
    const mask = ptr(0x0).not().shl(this.RUBY_SPECIAL_SHIFT).not();    
    //return (obj & mask) == RUBY_SYMBOL_FLAG;
    return (obj.and(mask).equals(ptr(this.RUBY_SYMBOL_FLAG)))
  }

  RB_DYNAMIC_SYM_P(obj) {
    //(!RB_SPECIAL_CONST_P(x) && RB_BUILTIN_TYPE(x) == (RUBY_T_SYMBOL))
    /*
    if (RB_SPECIAL_CONST_P(obj)) {
        return false;
    }
    else {
        return RB_BUILTIN_TYPE(obj) == RUBY_T_SYMBOL;
    }
    */
    return !this.RB_SPECIAL_CONST_P(obj) && (this.RB_BUILTIN_TYPE(obj) == this.T_SYMBOL)
  }

  RB_SYMBOL_P(obj) {
    // log(">> RB_SYMBOL_P: " + obj)
    return this.RB_STATIC_SYM_P(obj) || this.RB_DYNAMIC_SYM_P(obj);
  }

  RB_TYPE_P(obj, t) {
    return this.rb_type(obj) == t
  }

  RB_FLOAT_TYPE_P(obj) {
    if (this.RB_FLONUM_P(obj)) {
      return true;
    } else if (this.RB_SPECIAL_CONST_P(obj)) {
      return false;
    } else {
      return this.RB_BUILTIN_TYPE(obj) == this.T_FLOAT;
    }
  }

  rb_ractor_main_p() {
    if (this.ruby_single_main_ractor == null) {
      return true;
    }
    if (!this.ruby_single_main_ractor.readPointer().isNull()) {
      return true;
    }
    return this.rb_ractor_main_p_();
  }

}

let singleton = null;

module.exports = function (libruby) {
  if (singleton === null) {
    singleton = new Ruby(libruby);
  }

  if (libruby === undefined) {
    return singleton;
  }

  if (singleton.libruby !== libruby) {
    return new Ruby(libruby);
  }

  return singleton;
}
