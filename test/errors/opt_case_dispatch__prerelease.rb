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
  require 'bigdecimal'

  def foo(x)
    case x
    when 'goodbye'
      'moon'
    when 'hello'
      'world'
    when ',"=>'
      'misc'
    when 1
      "num"
    when 2147483648
      "bignum"
    when 3.0
      "float"
    when true
      "bool"
    when nil
      "nil"
    when :foo
      "symbol"
    when "foo"
      "string"
    #when 0..20
    #  'num'
    #when /hello2/
    #  'world2'
    #when 1, 2, *[]
    #  'arr'
    end
  end
  [foo('hello'), foo(1), foo(2.0 + 1.0), foo(BigDecimal("3.0")), foo('wat'), foo(:foo), foo("foo"), foo(2147483648)]
end;

iseq = RubyVM::InstructionSequence.compile(code)
puts iseq.inspect
puts RubyVM::InstructionSequence.disasm(iseq)

puts (trace { iseq.eval }).inspect
