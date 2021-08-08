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

def foobar(a, b)
  yield a + b + "_top"
end

code = "#{<<~"begin;"}\n#{<<~"end;"}"
begin;
  class A
    def aaa(a, b, c)
      yield (a + b + c), "Aaaa"
    end
    def bbb(b, c)
      b + c
    end
    def ccc(c)
      c
    end
  end

  class B < A
    def aaa(a, b, c)
      super {|d, e|
        d + "_" + e + "2"
      }
    end

    def bbb(b, c)
      super + "2"
    end
    def ccc(c)
      super(c + "3") + "2"
    end
  end

  def foo
    "foo"
  end

  def bar
  end

  a = 1.times do |i|
    i
  end

  b = 1.times.map {
    def method_definition
      'hello'
    end

    def self.smethod_definition
      'world'
    end

    method_definition + smethod_definition
  }.join

  def foobar2(a, b)
    yield a + b
  end

  c = A.new.aaa("a","b","c") {|r1, r2|
    r1 + r2 + "1"
  }
  d = B.new.aaa("a","b","c")
  e = B.new.bbb("b","c")
  f = B.new.ccc("c")

  g = foobar("foo","bar") {|result|
    result
  }
  h = foobar2("foo","bar") {|result|
    result
  }

  [a, b, c, d, e, f, g, h]
end;

iseq = RubyVM::InstructionSequence.compile(code)
puts iseq.inspect

puts (trace { iseq.eval }).inspect

puts RubyVM::InstructionSequence.disasm(iseq)
