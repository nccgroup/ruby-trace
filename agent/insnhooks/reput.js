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
  log(">> reput -> TOPN(0): " + val_inspect);
}

module.exports = function(args) {
  // DEFINE_INSN_IF(STACK_CACHING)
  // /* for stack caching. */
  // reput
  // ()
  // (..., VALUE val)
  // (VALUE val)
  // // attr rb_snum_t sp_inc = 0;
  try {
    //note: This instruction is cursed. It relies on some sort of antiquated
    //      YARV optimization (OPT_STACK_CACHING) that was seemingly never
    //      turned on when YARV was merged into CRuby 1.9.x, nor any time
    //      after. It's not even clear if it was ever actually used for real in
    //      YARV prior to the merge, since (like most of CRuby) there's no
    //      documentation on it. The only mention of it is in the YARV research
    //      paper, which dedicates one sentence to state that YARV implements
    //      the optimization, which then references a 1995 paper that talks
    //      about "Prolog, Forth and APL" as the only examples of interpreted
    //      "general-purpose" languages. I realize it was 1995, but Austria had
    //      joined the EU by the time this paper was published so the author
    //      could have at least mentioned Tcl, Python, or _PERL_. However, the
    //      reason for such omissions is probably that the author's technique
    //      only ever applied to toy-like interpreted stack-based virtual
    //      machines and the only people foolish enough to be working on such,
    //      by then, already outmoded technology in the 90s were Sun. RIP.
    //
    //      Anyway, a quick skim of the remaining code makes it seem like this
    //      feature might only be 10-25% implemented in the current CRuby
    //      codebase and CRuby outright refuses to even compile if the .h
    //      #define-based "compile option" is turned on. Most of the relevant
    //      code is in compile.c, and what it does doesn't seem to be used by
    //      much of anything. The only interesting thing that the code does is
    //      wire up metadata associated with jump and branch instructions with
    //      a state machine that is used to determine if certain instructions
    //      can otherwise be elided; however, in the case of certain nop
    //      instructions, it will convert them into reput instructions, which
    //      otherwise are never emitted naturally, based on the state. Assuming
    //      that the runtime part of the optimization was actually implemented,
    //      it looks like this instruction might exist to refresh the register
    //      version of the stack with the actual stack, or vice versa; it's
    //      unclear which one would be stale.
    //
    //      Well friends, someone apparently noticed this cruft in 2019 and
    //      decided that instead of removing the partially implemented, broken
    //      code that had been dead for at least 12 years, they would make the
    //      related YARV instruction's inclusion dependent on if the
    //      aforementioned "option" was enabled. They could have at least left
    //      a note. So as of Ruby 2.7.x, it is mostly impossible to test this
    //      instruction. But there's a big difference between mostly impossible
    //      and actually impossible. Mostly impossible is slightly possible.
    //      Because we already support Ruby 2.6.x, the 2.6.x-specific
    //      test/reput.rb test code will compile normal Ruby code that will
    //      emit a nop instruction, extract the bytecode for it, patch it to
    //      convert the nop into a reput, load the modified bytecode, and then
    //      execute it under trace. As the code body for the reput instruction
    //      doesn't actually do anything (so the `...` in the pop values of the
    //      instruction definition is probably wrong), the trace hook is fairly
    //      simple.
    
    let val_inspect = r.rb_inspect2(vm.TOPN(0));

    log(">> reput [" + val_inspect + "] (bottom->top)");
    vm.return_callback = leave;
  } catch (e) {
    log("Error [reput]: " + String(e))
  }
}