# Copyright (c) 2021 NCC Group Security Services, Inc. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

def trace
  t = TracePoint.new(:call) { |tp| }
  t.enable
  yield
ensure
  t.disable
end

if !RUBY_VERSION.start_with?('2.6.')
  exit
end

# note: in ruby 2.6, which appears to tolerate the existence of reput
#       instructions by default, reput is insn 40 (0x28). if it were possible
#       to actually compile ruby w/ OPT_STACK_CACHING, then nop insns (0x0)
#       would seemingly be converted into reput insns. so we will try to test
#       reput by patching the bytecode to replace nop insns with reput insns.
code = '0x41414141 rescue true'

iseq = RubyVM::InstructionSequence.compile(code)
puts iseq.to_a.inspect

b = iseq.to_binary

i = b.index("\x39".b) # leave
#b[i] = "\x28".b
b[i-8] = "\x28".b # nop -> reput

iseq2 = RubyVM::InstructionSequence.load_from_binary(b)
puts iseq2.to_a.inspect
puts RubyVM::InstructionSequence.disasm(iseq2)
puts (trace { iseq2.eval }).inspect


