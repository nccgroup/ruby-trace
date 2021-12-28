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

code = "#{<<~"begin;"}\n#{<<~"end;"}"
begin;
  a = ["hello", "world", "!"]
  arr = [0, 1, 2]

  w = case a[0]
  when 0..20
    "0"
  when /hello2/
    "1"
  when "world"
    "2"
  when *arr
    "wat2"
  else
    "3"
  end

  x = case
  when 1, 2, *[]
    "a"
  else
    "b"
  end

  y = begin
    raise Exception.new "foo"
  rescue Exception => e
    e
  end

  z = case a
  in ["hello", v, "!"]
    v
  else
    "miss"
  end

  [w, x, y, z]
end;

iseq = RubyVM::InstructionSequence.compile(code)

puts (trace { iseq.eval }).inspect

puts RubyVM::InstructionSequence.disasm(iseq)
