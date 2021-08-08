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
  mytracepoint = TracePoint.new(:call) { |tp| }
  mytracepoint.enable
  yield
ensure
  mytracepoint.disable
end

code = "#{<<~"begin;"}\n#{<<~"end;"}"
begin;
  hash = { 1 => 2 }
  arr = [ 1, 2, 3 ]

  obj = Object.new
  def obj.[]=(h, v=-1, val)
    if h.instance_of? String
      "no ret2"
    else
      "no ret1"
    end
  end

  puts arr.inspect

  block = proc { |h, v|
    case h
    when Hash
      h[41] = v
    else
      [h[41] = v, "h"[0] = v.to_s, ((h["43"] = v) rescue nil), h[44.0] = v, h[45, 1] = [v, v]]
    end
  }

  a = block.call(hash, 1)
  b = block.call(arr, 2)
  c = block.call(obj, 3)
  c = block.call(obj, [3,3])
  [a, b, c]
end;

iseq = RubyVM::InstructionSequence.compile(code)
puts iseq.inspect
puts RubyVM::InstructionSequence.disasm(iseq)

puts (trace { iseq.eval }).inspect
