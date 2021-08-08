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
  class A
    def aaa(a, b, c)
      a + b + c + "1"
    end
    class AA
    end
  end

  class A
    def aaa(a, b, c)
      a + b + c + "2"
    end
  end

  class ::B < A
    def bbb(b, c, d)
      b + c + d
    end
  end

  class C < B
    def aaa(a, b, c, d)
      super(a, b, c) + d
    end

    def ccc(c, d)
      c + d
    end
  end

  class C
    def ccc(c, d)
      c + d + "2"
    end
  end

  c3 = C.new
  def c3.ccc(c, d)
    c + d + "3"
  end

  c4 = C.new
  class << c4
    def ccc(c, d)
      c + d + "4"
    end
  end

  class D
    def foo
    end
  end
  Object.send(:remove_const, :D)
  class D
    def ddd(d)
      d + "2"
    end
  end


  module E
    def eee(e)
      e + "1"
    end
  end

  module ::F
    def F.fff(f)
      f + "2"
    end
    include E
  end

  class ::G
    include E
  end

  class H
    include F
  end

  [
    A.new.aaa("a", "b", "c"),
    B.new.aaa("a", "b", "c"),
    B.new.bbb("b", "c", "d"),
    C.new.aaa("a", "b", "c", "d"),
    C.new.bbb("b", "c", "d"),
    C.new.ccc("c", "d"),
    c3.ccc("c", "d"),
    c4.ccc("c", "d"),
    D.new.ddd("d"),
    F.fff("f"),
    G.new.eee("e"),
    H.new.eee("e"),
  ]
end;

iseq = RubyVM::InstructionSequence.compile(code)

puts (trace { iseq.eval }).inspect

puts RubyVM::InstructionSequence.disasm(iseq)
