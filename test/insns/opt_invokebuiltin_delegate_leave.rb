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

#note: opt_invokebuiltin_delegate_leave is used to call builtins
#      however, there is some magic in ruby where opt_invokebuiltin_delegate is
#      used in place of opt_invokebuiltin_delegate_leave when actually
#      executing if TracePoint is enabled. so to get around this, we use a
#      custom trigger symbol to enable ruby-trace tracing, obj_to_enum, which
#      Kernel#to_enum is mapped to.
#
#      ruby-trace -s obj_to_enum -- ruby opt_invokebuiltin_delegate_leave.rb 

U = "\x00".method(:unpack)
is = RubyVM::InstructionSequence.of(U)
STDERR.puts is.disasm

D = GC.method(:disable)
is2 = RubyVM::InstructionSequence.of(D)
STDERR.puts is2.disasm

t = TracePoint.new(:call) { |tp| }
x = "".to_enum

a = "\\x00".unpack('C')
b = "\\x00".method(:unpack).call('C')
c = U.call('C')
GC.disable

t.disable
puts "result: " + [a, b, c].inspect

