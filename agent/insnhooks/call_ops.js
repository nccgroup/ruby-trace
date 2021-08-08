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

let indent_p = Memory.allocUtf8String("");
let indent_s = null;

function indent(str) {
  let lines = str.split("\n")
  for (let i=0; i<lines.length; i++) {
    lines[i] = "  " + lines[i]
  }
  return lines.join("\n")
}

module.exports = function(name) {
  // /* invoke method. */
  // send
  // (CALL_INFO ci, CALL_CACHE cc, ISEQ blockiseq)
  // (...)
  // (VALUE val)
  // // attr rb_snum_t sp_inc = - (int)(ci->orig_argc + ((ci->flag & VM_CALL_ARGS_BLOCKARG) ? 1 : 0));

  // /* Invoke method without block */
  // opt_send_without_block
  // (CALL_INFO ci, CALL_CACHE cc)
  // (...)
  // (VALUE val)
  // // attr bool handles_sp = true;
  // // attr rb_snum_t sp_inc = -ci->orig_argc;

  // /* super(args) # args.size => num */
  // invokesuper
  // (CALL_INFO ci, CALL_CACHE cc, ISEQ blockiseq)
  // (...)
  // (VALUE val)
  // // attr rb_snum_t sp_inc = - (int)(ci->orig_argc + ((ci->flag & VM_CALL_ARGS_BLOCKARG) ? 1 : 0));
  return function(args, last_simple_insn, last_insn_cb) {
    try {
      if (indent_s === null) {
        indent_s = r.rb_str_new_cstr(indent_p);
      }

      let cfp = vm.GET_CFP();
      let sp = vm.GET_SP(cfp);

      // ruby 2.6
      //   send(CALL_INFO ci, CALL_CACHE cc, ISEQ blockiseq)(...)(VALUE val)
      //   opt_send_without_block(CALL_INFO ci, CALL_CACHE cc)(...)(VALUE val)
      //   invokesuper(CALL_INFO ci, CALL_CACHE cc, ISEQ blockiseq)(...)(VALUE val)

      // ruby 2.7-3.0
      //   send(CALL_DATA cd, ISEQ blockiseq)(...)(VALUE val)
      //   opt_send_without_block(CALL_DATA cd)(...)(VALUE val)
      //   invokesuper(CALL_DATA cd, ISEQ blockiseq)(...)(VALUE val)

      let ci_p;
      // let cc_p;
      let blockiseq_p;
      let block_handler_p;
      let block_handler_type = null;

      switch (vm.ruby_version) {
        case 26: {
          ci_p = vm.GET_OPERAND(1, cfp)
          // cc_p = vm.GET_OPERAND(2, cfp)
          switch (name) {
            case 'send':
            case 'invokesuper': {
              blockiseq_p = vm.GET_OPERAND(3)
              if (ptr(0x0).equals(blockiseq_p)) {
                blockiseq_p = null;
              }
              break;
            }
            default: {
              blockiseq_p = null;
            }
          }
          break;
        }
        case 27:
        case 30:
        default: {
          // vm_sendish
          let cd_p = vm.GET_OPERAND(1, cfp)
          ci_p = vm.native.rb_call_data__ci(cd_p)
          // cc_p = vm.native.rb_call_data__cc(cd_p)
          switch (name) {
            case 'send':
            case 'invokesuper': {
              blockiseq_p = vm.GET_OPERAND(2)
              if (ptr(0x0).equals(blockiseq_p)) {
                blockiseq_p = null;
              }
              break;
            }
            default: {
              blockiseq_p = null;
            }
          }
        }
      }

      switch (name) {
        case 'invokeblock': {
          block_handler_p = vm.VM_CF_BLOCK_HANDLER(cfp)
          // log(">> " + name + " block_handler_p: " + block_handler_p)
          if (ptr(0x0).equals(block_handler_p)) {
            block_handler_type = "NONE"
          } else {
            if (vm.VM_BH_ISEQ_BLOCK_P(block_handler_p)) {
              block_handler_type = "iseq"
            } else if (vm.VM_BH_IFUNC_P(block_handler_p)) {
              block_handler_type = "ifunc"
            } else if (r.RB_SYMBOL_P(block_handler_p)) {
              block_handler_type = "symbol" // + ":" +  r.ruby_str_to_js_str(r.rb_sym2str(block_handler_p)) +")"
            } else {
              let is_proc = false;
              try {
                is_proc = r.rb_obj_is_proc(block_handler_p).equals(r.Qtrue);
              } catch (e) {}
              if (is_proc) {
                block_handler_type = "proc"
              } else {
                block_handler_type = "unknown:" + block_handler_p.toString()
              }
            }
          }
          // log(">> " + name + " block_handler_type: " + block_handler_type)
          break;
        }
        default: {
          block_handler_p = null;
        }
      }

      // log(">> " + name + " blockiseq_p: " + blockiseq_p)
      let mid = "TKTK"
      let mid_p = ptr(0);
      let flag = null;
      let orig_argc = -42;
      switch (vm.ruby_version) {
        case 26:
        case 27: {
          switch (name) {
            case 'invokeblock': {
              break;
            }
            default: {
              mid_p = vm.native.rb_call_info__mid(ci_p);
            }
          }
          orig_argc = vm.native.rb_call_info__orig_argc(ci_p);
          flag = vm.native.rb_call_info__flag(ci_p);
          break;
        }
        case 30:
        default: {
          switch (name) {
            case 'invokeblock': {
              break;
            }
            default: {
              mid_p = vm.native.rb_callinfo__mid(ci_p);
            }
          }
          orig_argc = vm.native.rb_callinfo__argc(ci_p);
          flag = vm.native.rb_callinfo__flag(ci_p);
        }
      }
      if (mid_p != ptr(0)) {
        mid = r.rb_id2name(mid_p).readUtf8String();
      }

      if (last_simple_insn !== undefined) {
        let operator = last_simple_insn[4];
        if (operator == mid) {
          let last_insn_name = last_simple_insn[0];
          log(">> " + last_insn_name + " -> CALL_SIMPLE_METHOD()");

          //note: vm.return_callback won't work b/c it will fire on the next
          //      insn, not on return from the called method.
          //      this should be handled by the leave insn hook
          //      or by a return callback from a cfunc hook
          //vm.return_callback = last_insn_cb;
        } else {
          last_insn_cb();
        }
      }

      let recv_p;
      let recv_inspect;
      switch (name) {
        case 'invokeblock': {
          recv_p = null;
          recv_inspect = "";
          break;
        }
        default: {
          recv_p = vm.TOPN(orig_argc, sp);
          // log(">> " + name + " recv_p: " + recv_p);
          recv_inspect = r.rb_inspect2(recv_p);
        }
      }

      let flag_s = vm.flag_pp(flag);

      let call_args = [];
      let kw_args = [];
      for (let i=orig_argc-1; i >= 0; i--) {
        //let topn_i = vm.TOPN(i, sp)

        // note: in ruby 2.6 this can happen:
        //       "method `inspect' called on unexpected T_IMEMO object (0x0000562a31a19008 flags=0x18701a)"
        // 
        //       it appears that the issue is partially constructed classes are
        //       a thing in ruby 2.6. the normal rb_type check is insufficient
        //       here. but we can reuse the CLASS_OF -> null check.
        //       to save us the trouble, we'll make a safer inspect wrapper

        // let type = parseInt(r.rb_type(topn_i).toString(16));
        // log(">> type: " + type);
        // let topn_i_inspect;
        // switch(type) {
        //   case r.T_UNDEF: {
        //     topn_i_inspect = "<undef>";
        //     break;
        //   }
        //   case r.T_IMEMO: {
        //     topn_i_inspect = "<imemo>";
        //     break;
        //   }
        //   default: {
        //     log(">> topn_i: " + topn_i);
        //     //let klass = r.get_class_name(r.ruby_call0(topn_i, "class"))
        //     log(">> class: " + klass)
        //   }
        // }

        call_args.push(r.rb_inspect2(vm.TOPN(i, sp)));
      }

      // ruby 2.6-2.7
      //   if (ci->flag & VM_CALL_KWARG) {
      //     struct rb_call_info_kw_arg *kw_args = ((struct rb_call_info_with_kwarg *)ci)->kw_arg;
      //     VALUE kw_ary = rb_ary_new_from_values(kw_args->keyword_len, kw_args->keywords);
      //     rb_ary_push(ary, rb_sprintf("kw:[%"PRIsVALUE"]", rb_ary_join(kw_ary, rb_str_new2(","))));
      //   }

      // ruby 3.0
      //   if (vm_ci_flag(ci) & VM_CALL_KWARG) {
      //     const struct rb_callinfo_kwarg *kw_args = vm_ci_kwarg(ci);
      //     VALUE kw_ary = rb_ary_new_from_values(kw_args->keyword_len, kw_args->keywords);
      //     rb_ary_push(ary, rb_sprintf("kw:[%"PRIsVALUE"]", rb_ary_join(kw_ary, rb_str_new2(","))));
      //   }

      if (vm.has_flag(flag, "KWARG")) {
        let kw_args_p;
        let keyword_len;
        let keywords_p;
        switch (vm.ruby_version) {
          case 26:
          case 27: {
            kw_args_p = vm.native.rb_call_info_with_kwarg__kw_arg(ci_p)
            keyword_len = vm.native.rb_call_info_kw_arg__keyword_len(kw_args_p)
            keywords_p = vm.native.rb_call_info_kw_arg__keywords(kw_args_p)
            break;
          }
          case 30:
          default: {
            kw_args_p = vm.native.rb_callinfo__kwarg(ci_p)
            if (kw_args_p != ptr(0)) {
              keyword_len = vm.native.rb_callinfo_kwarg__keyword_len(kw_args_p)
              keywords_p = vm.native.rb_callinfo_kwarg__keywords(kw_args_p)
            }
          }
        }

        if (kw_args_p != ptr(0)) {
          let keywords = [];

          for (let i=0; i < keyword_len; i++) {
            let keyword_p = keywords_p.add(i*Process.pointerSize).readPointer();
            let keyword_s = r.ruby_str_to_js_str(r.rb_sym2str(keyword_p));
            keywords.push(keyword_s);
          }
          for (let i=0; i < keyword_len; i++) {
            kw_args.push(keywords.pop() + ": " + call_args.pop())
          }
          for (let i=keyword_len-1; i >= 0; i--) {
            call_args.push(kw_args[i])
          }
        }
      }

      // note: fundamentally, while you can call `def thing1(a, b, *c, **kw)` with
      //       `thing1(c[1], b, a, c[0], **kw, **{:d => "lol"})`, the way
      //       it actually works is that the kwargs get merged into one.
      //       they are then always represented in a single hash object
      //       as the last arg w/ the KW_SPLAT flag set. from this pov,
      //       we can't know what the actually call really looked like,
      //       but we can emulate an equivalent of the call from the
      //       receiver's pov here. it is worth noting that side effects
      //       can be smuggled in invisibly w/ something like:
      //       `thing1(c[1], b, a, c[0], **kw, **{:d => puts("lol")}, **{:d => "lol"})`,
      //       but this is fundamentally the same issue as with ruby's
      //       semi-colon-based comma operator.

      if (vm.has_flag(flag, "KW_SPLAT")) {
        call_args[call_args.length-1] = "**" + call_args[call_args.length-1]
      }

      let args_s = call_args.join(', ');

      let iseq_str = "";
      if (blockiseq_p !== null) {
        let iseq_rstr = r.rb_iseq_disasm_recursive(blockiseq_p, indent_s)
        iseq_str = indent(r.ruby_str_to_js_str(iseq_rstr).trim())
      }

      if (flag_s == "") {
        flag_s = "NONE"
      }

      switch(name) {
        case 'invokeblock': {
          if (args_s != "") {
            args_s = " " + args_s
          }

          let block_handler_str;
          switch (block_handler_type) {
            case 'iseq': {
              block_handler_str = "iseq:" + r.rb_inspect2(block_handler_p)
              break;
            }
            case 'symbol': {
              block_handler_str = ":" + r.ruby_str_to_js_str(r.rb_sym2str(block_handler_p))
              break;
            }
            default: {
              block_handler_str = r.rb_inspect2(block_handler_p)
            }
          }

          log(">> " + name + ": yield" + args_s + " [" +
            (block_handler_type != "" ? ("type:" + block_handler_type) : "") +
            (flag_s != "" ? (", flags:" + flag_s) : "") +
            "] {" + block_handler_str + "}"
          )
          break;
        }
        default: {
          if (mid == "[]") {
            log(">> " + name + ": (" + recv_inspect + ").[" + args_s + "]" +
              (flag_s != "" ? (" [flags:" + flag_s + "]") : "") +
              (blockiseq_p !== null ? (" {\n" + iseq_str + "\n}") : "")
            )
          } else if (mid == "[]=") {
            let arr_args = call_args.slice(0,2).join(', ');
      
            log(">> " + name + ": (" + recv_inspect + ").[" + arr_args + "] = " + call_args[2] +
              (flag_s != "" ? (" [flags:" + flag_s + "]") : "") +
              (blockiseq_p !== null ? (" {\n" + iseq_str + "\n}") : "")
            )
          } else if (mid == "!") {
            if (recv_inspect.startsWith("#")) {
              recv_inspect = "(" + recv_inspect + ")"
            }

            log(">> " + name + ": !" + recv_inspect + 
              (flag_s != "" ? (" [flags:" + flag_s + "]") : "") +
              (blockiseq_p !== null ? (" {\n" + iseq_str + "\n}") : "")
            )
          } else {
            if (call_args.length > 1) {
              args_s = "(" + args_s + ")"
            }
      
            if (call_args.length == 1) {
              args_s = " " + args_s
            }
            log(">> " + name + ": (" + recv_inspect + ")." + mid + args_s + 
              (flag_s != "" ? (" [flags:" + flag_s + "]") : "") +
              (blockiseq_p !== null ? (" {\n" + iseq_str + "\n}") : "")
            )
          }
        }
      }

    } catch (e) {
      //vm.return_callback = null;
      log("Error [call_ops:" + name + "]: " + String(e))
    }
  }
}