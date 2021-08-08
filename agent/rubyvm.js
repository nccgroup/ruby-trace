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

let r = require('./ruby')();
let libc = require('./libc')()
let { log } = libc

const OPT_DIRECT_THREADED_CODE = "direct threaded code";
const OPT_TOKEN_THREADED_CODE = "token threaded code";
const OPT_CALL_THREADED_CODE = "call threaded code";
const OPT_STACK_CACHING = "stack caching";
const OPT_OPERANDS_UNIFICATION = "operands unification";
const OPT_INSTRUCTIONS_UNIFICATION = "instructions unification";
const OPT_INLINE_METHOD_CACHE = "inline method cache";
const OPT_BLOCKINLINING = "block inlining";

const OPTS = {
  OPT_DIRECT_THREADED_CODE,
  OPT_TOKEN_THREADED_CODE,
  OPT_CALL_THREADED_CODE,
  OPT_STACK_CACHING,
  OPT_OPERANDS_UNIFICATION,
  OPT_INSTRUCTIONS_UNIFICATION,
  OPT_INLINE_METHOD_CACHE,
  OPT_BLOCKINLINING,
};

const OPTS_INV = (() => {
  let ret = {};
  for (const [k,v] of Object.entries(OPTS)) {
    ret[v] = k;
  }
  return ret;
})()

function get_opt_ifdef(opt) {
  //console.log(opt)
  return OPTS_INV[opt];
}

const VM_CALL_FLAGS = [
  "ARGS_SPLAT",
  "ARGS_BLOCKARG",
  "FCALL",
  "VCALL",
  "ARGS_SIMPLE",
  "BLOCKISEQ",
  "KWARG",
  "KW_SPLAT",
  "TAILCALL",
  "SUPER",
  "ZSUPER",
  "OPT_SEND",
];

const VALUE = 'pointer';
const ID = 'pointer';

class RubyVM {
  constructor (callback) {
    this.callback = callback;
    this.runtime_init_funcs = []

    this.ec_p = null;
    this.insns_address_table = null;
    this.OPTS = {};
    this.INSTRUCTION_NAMES = [];
    this.INSTRUCTIONS = {};
    this.ruby_version_str = null;
    this.ruby_version = -1;
    this.native = null;
    this.return_callback = null;
    this.last_insn = null;

    this.BOP_PLUS = 0x0
    this.BOP_MINUS = 0x1
    this.BOP_MULT = 0x2
    this.BOP_DIV = 0x3
    this.BOP_MOD = 0x4
    this.BOP_EQ = 0x5
    this.BOP_EQQ = 0x6
    this.BOP_LT = 0x7
    this.BOP_LE = 0x8
    this.BOP_LTLT = 0x9
    this.BOP_AREF = 0xa
    this.BOP_ASET = 0xb
    this.BOP_LENGTH = 0xc
    this.BOP_SIZE = 0xd
    this.BOP_EMPTY_P = 0xe
    this.BOP_SUCC = 0xf
    this.BOP_GT = 0x10
    this.BOP_GE = 0x11
    this.BOP_NOT = 0x12
    this.BOP_NEQ = 0x13
    this.BOP_MATCH = 0x14
    this.BOP_FREEZE = 0x15
    this.BOP_UMINUS = 0x16
    this.BOP_MAX = 0x17
    this.BOP_MIN = 0x18
    this.BOP_CALL = 0x19
    this.BOP_AND = 0x1a
    this.BOP_OR = 0x1b

    this.INTEGER_REDEFINED_OP_FLAG = 0x0001
    this.FLOAT_REDEFINED_OP_FLAG   = 0x0002
    this.STRING_REDEFINED_OP_FLAG  = 0x0004
    this.ARRAY_REDEFINED_OP_FLAG   = 0x0008
    this.HASH_REDEFINED_OP_FLAG    = 0x0010
    this.SYMBOL_REDEFINED_OP_FLAG  = 0x0040
    this.TIME_REDEFINED_OP_FLAG    = 0x0080
    this.REGEXP_REDEFINED_OP_FLAG  = 0x0100
    this.NIL_REDEFINED_OP_FLAG     = 0x0200
    this.TRUE_REDEFINED_OP_FLAG    = 0x0400
    this.FALSE_REDEFINED_OP_FLAG   = 0x0800
    this.PROC_REDEFINED_OP_FLAG    = 0x1000
    

    this.ruby_current_ec_name = null;
    this.ruby_current_ec_addr = null;
    this.GET_EC_tls_key = null;

    this.USE_SIGALTSTACK = null;

    this.ruby_vm_global_constant_state = new NativePointer(r.libruby.getExportByName('ruby_vm_global_constant_state'));
    this.ruby_vm_const_missing_count = new NativePointer(r.libruby.getExportByName('ruby_vm_const_missing_count'));

    this.rb_vm_get_insns_address_table = new NativeFunction(r.sym_to_addr_map['rb_vm_get_insns_address_table'].address, 'pointer', []);
    this.vm_env_cref = new NativeFunction(r.sym_to_addr_map['vm_env_cref'].address, 'pointer', ['pointer']);

    this.ruby_current_vm_ptr = new NativeFunction(r.libruby.getExportByName('ruby_current_vm_ptr'), 'pointer', []);

    let self = this;

    let vm_exec_core = null;
    vm_exec_core = Interceptor.attach(r.sym_to_addr_map['vm_exec_core'].address, function(args){
      // static VALUE
      // vm_exec_core(rb_execution_context_t *ec, VALUE initial)
      //log("vm_exec_core hit: " + args[0]);
      if (!args[0].isNull()) {
        self.ec_p = args[0];
        vm_exec_core.detach();
      }
    });


    try {
      // 3.0+
      r.libruby.getExportByName('ruby_current_ec')
      this.ruby_current_ec_name = "ruby_current_ec"
    } catch (e) {
      try {
        // 2.6-2.7
        r.libruby.getExportByName('ruby_current_execution_context_ptr')
        this.ruby_current_ec_name = 'ruby_current_execution_context_ptr'
      } catch (e) {}
    }

    if (r.sym_to_addr_map['rb_allocate_sigaltstack'] != undefined) {
      this.USE_SIGALTSTACK = "USE_SIGALTSTACK";
    } else {
      this.USE_SIGALTSTACK = "NOT_USING_SIGALTSTACK";
    }

    // log(">> this.USE_SIGALTSTACK: " + this.USE_SIGALTSTACK);

    if (this.ruby_current_ec_name == 'ruby_current_ec') {
      let __tls_get_addr_hook = Interceptor.attach(libc.libc.getExportByName('__tls_get_addr'), {
        onEnter: function(args) {
          this.key = args[0]
        },
        onLeave: function(retval) {
          if (retval.isNull() || retval.readPointer().isNull()) {
            return;
          }
  
          let ec_p = retval.readPointer()
          let ruby_current_ec = r.libruby.getExportByName('ruby_current_ec').readPointer();
  
          if (ruby_current_ec.equals(ec_p)) {
            self.GET_EC_tls_key = this.key;
            __tls_get_addr_hook.detach();
          }
        }
      });  
    }



    // let rb_singleton_class = null;
    // rb_singleton_class = Interceptor.attach(r.sym_to_addr_map['rb_singleton_class'].address, {
    //   onLeave: function(retval) {
    //     log(">> rb_singleton_class -> " + r.rb_inspect2(retval));
    //   }
    // })

    this.local_var_name = new NativeFunction(r.sym_to_addr_map['local_var_name'].address, 'pointer', ['pointer', VALUE, VALUE]);

    // Interceptor.attach(r.sym_to_addr_map['local_var_name'].address, function(args){
    //   // static VALUE
    //   // local_var_name(const rb_iseq_t *diseq, VALUE level, VALUE op)
    //   let diseq_p = args[0];
    //   let level = args[1];
    //   let op = args[2];
    //   let res = self.local_var_name(diseq_p, level, op)
    //   log("====> local_var_name(" + diseq_p + ", " + level.toString(10) + ", " + op.toString(10) + ") -> " + r.rb_inspect2(res))

    //   let local_table_size = self.native.get_local_table_size(diseq_p);
    //   log("======> local_table_size: " + local_table_size)
    //   let idx = self.native.local_var_idx(diseq_p, level, op);
    //   let lid = self.native.local_var_id(diseq_p, level, idx);
    //   let name = r.rb_id2str(lid);
    //   log("======> local_var_id(" + diseq_p + ", level:" + level.toString(10) + ", idx:" + idx + ") -> " + lid + " -> " + r.rb_inspect2(name))
    // });

    let ruby_run_node_hit = false;
    let ruby_run_node_hook = Interceptor.attach(r.libruby.getExportByName('ruby_run_node'), function(args) {
      //note: initially, this was just to see if this gets called for ractors in ruby 3+.
      //      eventually, should probably detach this after it finishes.
      //      while it would have been nice to do Interceptor.detachAll()
      //      after it returns, something about top level execption unwinding
      //      (ie uncaught exceptions) causes the onEnter/onLeave handling
      //      to break resulting in segfaults.

      // log(">> ruby_run_node hit")
      if (ruby_run_node_hit) {
        return;
      }
      ruby_run_node_hit = true;

      for (let runtime_init_func of self.runtime_init_funcs) {
        //console.log(">> runtime_init_func: " + runtime_init_func)
        runtime_init_func()
      }
    })

    this.runtime_init_funcs.push(function() {
      try {
        self.ruby_version_str = r.ruby_str_to_js_str(r.ruby_eval("RUBY_VERSION"))
        let [major, minor] = self.ruby_version_str.split('.')
        self.ruby_version = parseInt(major + minor)
        console.log("vm.ruby_version: " + self.ruby_version)

        self.INSTRUCTION_NAMES = JSON.parse(r.ruby_str_to_js_str(r.ruby_eval("require 'json'; RubyVM::INSTRUCTION_NAMES.to_json")))
        // let req_json = r.ruby_eval("require 'json'; RubyVM::OPTS.to_json")
        // let req_json_str = r.ruby_str_to_js_str(req_json)
        // log(">> req_json_str: " + req_json_str)
        // let opts = JSON.parse(req_json_str)
        // log(">> opts: " + opts)
        let opts = JSON.parse(r.ruby_str_to_js_str(r.ruby_eval("require 'json'; RubyVM::OPTS.to_json")))

        r.ruby_eval(`
        require 'json'
        def __ruby_trace_inspect(obj)
          begin
            obj.inspect
          rescue =>e
            "<uninspectable of type " + obj.class.to_s + ":" + e.inspect + ">"
          end
        end

        def __ruby_trace_hash_inverter(ha)
          ret = {}
          ha.each do |kv|
            ret[kv[1]] = kv[0].inspect
          end
          JSON.dump(ret)
        end
        `)

        for (let o of opts) {
          self.OPTS[o] = true;
        }
        console.log("OPTS: " + JSON.stringify(Object.entries(self.OPTS).map((kv) => { return get_opt_ifdef(kv[0]) })))
        //console.log(JSON.stringify(self.OPTS))

        self.insns_address_table = self.rb_vm_get_insns_address_table();

        for (const [i, v] of self.INSTRUCTION_NAMES.entries()) {
          self.INSTRUCTIONS[v] = self.insns_address_table.add(i * Process.pointerSize).readPointer()
        }

        if (self.native === null) {
          switch (self.ruby_version) {
            case 26: {
              self.native = require('./ruby26/native')(self);
              break;
            }
            case 27: {
              self.native = require('./ruby27/native')(self);
              break;
            }
            case 30: {
              self.native = require('./ruby30/native')(self);
              break;
            }
            default: {
              console.log("unknown ruby version")
              self.native = require('./ruby30/native')(self);
            }
          }
        }
        //console.log("self.native: " + JSON.stringify(self.native))
        self.callback()
      } catch (e) {
        log("Error[ruby_run_node.onEnter]: " + String(e))
      }
    })

    // r.runtime_init_funcs.push(runtime_init)
  }
  //     /*,
  //     onLeave: function(retval) {
  //       try {
  //         Interceptor.detachAll()
  //       } catch(e) {
  //         console.log("Error[ruby_run_node.onLeave]: " + String(e))
  //       }
  //     }
  //   }*/);
  // }

  has_opt(opt) {
    return this.OPTS[opt] !== undefined ? true : false;
  }

  OPT_INLINE_METHOD_CACHE() {
    return this.has_opt(OPT_INLINE_METHOD_CACHE)
  }

  has_flag(flag_val, flag) {
    let bin = flag_val.toString(2).split('').reverse().join('');
    let flag_bit = VM_CALL_FLAGS.indexOf(flag);
    if (flag_bit === -1) {
      return false;
    }
    if (flag_bit >= bin.length) {
      return false;
    }
    return bin[flag_bit] == '1';
  }
  
  flag_pp(flag) {
  //   enum vm_call_flag_bits {
  //     VM_CALL_ARGS_SPLAT_bit,     /* m(*args) */
  //     VM_CALL_ARGS_BLOCKARG_bit,  /* m(&block) */
  //     VM_CALL_FCALL_bit,          /* m(...) */
  //     VM_CALL_VCALL_bit,          /* m */
  //     VM_CALL_ARGS_SIMPLE_bit,    /* (ci->flag & (SPLAT|BLOCKARG)) && blockiseq == NULL && ci->kw_arg == NULL */
  //     VM_CALL_BLOCKISEQ_bit,      /* has blockiseq */
  //     VM_CALL_KWARG_bit,          /* has kwarg */
  //     VM_CALL_KW_SPLAT_bit,       /* m(**opts) */
  //     VM_CALL_TAILCALL_bit,       /* located at tail position */
  //     VM_CALL_SUPER_bit,          /* super */
  //     VM_CALL_ZSUPER_bit,         /* zsuper */
  //     VM_CALL_OPT_SEND_bit,       /* internal flag */
  //     VM_CALL__END
  // };
  
    let ret = [];
    let bin = flag.toString(2).split('').reverse().join('');
    for (let i=0; i < bin.length; i++) {
      if (bin[i] == '1') {
        ret.push(VM_CALL_FLAGS[i]);
      }
    }
    return ret.join('|');
  }
  
  GET_EC() {
    if (this.ruby_current_ec_name == 'ruby_current_execution_context_ptr') {
      if (this.ruby_current_ec_addr == null) {
        this.ruby_current_ec_addr = r.libruby.getExportByName(this.ruby_current_ec_name)
      }
      return this.ruby_current_ec_addr.readPointer()
    }

    if (this.GET_EC_tls_key == null) {
      return null;
    }
    return libc.__tls_get_addr(this.GET_EC_tls_key).readPointer();
  }

  GET_CFP() {
    if (this.ec_p === null || this.ec_p.isNull()) {
      return null;
    }
    return this.native.rb_execution_context_struct__cfp(this.ec_p);

    //note: doing this completely fixes the fiber behavior, but I want to hold
    //      off on making this change until we can make GET_EC have less
    //      overhead
    //TODO: this
    // let ec = this.GET_EC()
    // if (ec == null || ec.isNull()) {
    //   return null;
    // }
    // return this.native.rb_execution_context_struct__cfp(ec);

    //return this.ec_p.add(2*Process.pointerSize).readPointer();
  }
  
  GET_PC(_cfp = null) {
    let cfp = _cfp !== null ? _cfp : this.GET_CFP();
    if (cfp === null || cfp.isNull()) {
      return null;
    }
    return this.native.rb_control_frame_t__pc(cfp);
    //return cfp.add(0*Process.pointerSize).readPointer();
  }
  
  GET_SP(_cfp = null) {
    let cfp = _cfp !== null ? _cfp : this.GET_CFP();
    if (cfp === null || cfp.isNull()) {
      return null;
    }
    return this.native.rb_control_frame_t__sp(cfp);
    //return cfp.add(1*Process.pointerSize).readPointer();
  }

  get_expected_sp(i, _sp = null, _cfp = null) {
    let sp = _sp !== null ? _sp : this.GET_SP(_cfp);
    if (sp === null || sp.isNull()) {
      return null;
    }
    return sp.add(i*Process.pointerSize);  
  }


  GET_ISEQ(_cfp = null) {
    let cfp = _cfp !== null ? _cfp : this.GET_CFP();
    if (cfp === null || cfp.isNull()) {
      return null;
    }
    return this.native.rb_control_frame_t__iseq(cfp);
  }
  
  GET_SELF(_cfp = null) {
    let cfp = _cfp !== null ? _cfp : this.GET_CFP();
    if (cfp === null || cfp.isNull()) {
      return null;
    }
    return this.native.rb_control_frame_t__self(cfp);
    //return cfp.add(3*Process.pointerSize).readPointer();
  }

  GET_EP(_cfp = null) {
    let cfp = _cfp !== null ? _cfp : this.GET_CFP();
    if (cfp === null || cfp.isNull()) {
      return null;
    }
    return this.native.rb_control_frame_t__ep(cfp);
  }

  GET_LEP(_cfp = null) { // (VM_EP_LEP(GET_EP()))
    let cfp = _cfp !== null ? _cfp : this.GET_CFP();
    if (cfp === null || cfp.isNull()) {
      return null;
    }
    return this.native.VM_EP_LEP(this.GET_EP(cfp))
  }

  TOPN(n, _sp = null, _cfp = null) {
    //#define TOPN(n) (*(GET_SP()-(n)-1))
    let sp = _sp !== null ? _sp : this.GET_SP(_cfp);
    if (sp === null || sp.isNull()) {
      return null;
    }
    return sp.sub(n*Process.pointerSize).sub(1*Process.pointerSize).readPointer();  
  }
  
  GET_OPERAND(n, _cfp = null) {
    //#define GET_OPERAND(n)     (GET_PC()[(n)])
    // log(">> GET_OPERAND 1")
    // let cfp = this.GET_CFP();
    // log(">> GET_OPERAND 1b: cfp: " + cfp)

    let pc = this.GET_PC(_cfp);
    // log(">> GET_OPERAND 2: pc: " + pc)
    if (pc === null || pc.isNull()) {
      return null;
    }
    // log(">> GET_OPERAND 3")
    return pc.add(n*Process.pointerSize).readPointer();
  }
  
  VM_CF_BLOCK_HANDLER(_cfp = null) {
    let cfp = _cfp !== null ? _cfp : this.GET_CFP();
    if (cfp === null || cfp.isNull()) {
      return null;
    }
    //const VALUE *ep = VM_CF_LEP(cfp);
    // VM_CF_LEP -> VM_EP_LEP(cfp->ep)
    let ep = this.GET_LEP(cfp)

    //return VM_ENV_BLOCK_HANDLER(ep);
    //VM_ENV_BLOCK_HANDLER -> ep[VM_ENV_DATA_INDEX_SPECVAL];
    //#define VM_ENV_DATA_INDEX_SPECVAL    (-1) /* ep[-1] */
    let block_handler = ep.add(-1*Process.pointerSize).readPointer()
    return block_handler;
  }

  VM_BH_ISEQ_BLOCK_P(block_handler_p) {
    // log(">> VM_BH_ISEQ_BLOCK_P: " + block_handler_p)
    return block_handler_p.and(0x03).equals(ptr(0x1))
  }

  VM_BH_IFUNC_P(block_handler_p) {
    // log(">> VM_BH_IFUNC_P: " + block_handler_p)
    return block_handler_p.and(0x03).equals(ptr(0x3))
  }

  vm_ic_hit_p(ic_serial, ic_cref, _cfp = null) {
    let cfp = _cfp !== null ? _cfp : this.GET_CFP();
    if (cfp === null || cfp.isNull()) {
      return null;
    }
    let ep = this.GET_LEP(cfp)

    let rvgcs = this.ruby_vm_global_constant_state.readU64().toNumber();

    // log("ic_serial: " + ic_serial)
    // log("rvgcs: " + rvgcs)
    // log(">> typeof(ic_serial): " + typeof(ic_serial))
    // log(">> typeof(rvgcs): " + typeof(rvgcs))    
    // log("r.rb_ractor_main_p(): " + r.rb_ractor_main_p())

    if (rvgcs == ic_serial && r.rb_ractor_main_p()) {
      if (ic_cref.isNull()) {
        return true;
      }
      let cref = this.vm_env_cref(ep);
      // log("ic_cref: " + ic_cref)
      // log("cref: " + cref);
      return ic_cref.equals(cref);
    }
    return false;
  }

  GET_VM() {
    return this.ruby_current_vm_ptr.readPointer();
  }

  BASIC_OP_UNREDEFINED_P(op, klass) {
    // (LIKELY((GET_VM()->redefined_flag[(op)]&(klass)) == 0))

    // (GET_VM()->redefined_flag[op] & klass) == 0

    let vm = this.GET_VM();

    // log(">> BASIC_OP_UNREDEFINED_P(op: " + op + " (" + (typeof op) + "), klass: " + klass + "): vm: " + (typeof vm))
    let flag = this.native.rb_vm_struct__redefined_flag(vm, op);
    // log(">> BASIC_OP_UNREDEFINED_P: GET_VM()->redefined_flag: " + flag + " (" + (typeof flag) + ")")

    return (flag & klass) == 0;
  }

}

let singleton = null;

module.exports = function (callback) {
  if (singleton === null) {
    singleton = new RubyVM(callback);
  }

  return singleton;
}
