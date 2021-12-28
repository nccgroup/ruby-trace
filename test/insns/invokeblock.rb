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

class A
  def aaa(a, b, c)
    yield (a + b + c), "Aaaa"
  end
end

class B < A
  def aaa(a, b, c)
    super {|d, e|
      d + "_" + e + "2"
    }
  end
end

def foo(&block)
  if block.arity == 1
    block.call "foo"
  elsif block.arity == -2
    block.call nil, "foo"
  else
    "wat"
  end
end

def bar
  yield "bar"
end

def bar2
  x = nil
  class << x
    def get_result(result)
      result + "_inner_gotten"
    end
  end
  yield x, "bar2"
end

def baz
  a = foo {|n|
    n
  }
  b = bar {|n|
    n
  }
  [a, b]
end

a = 1.times do |i|
  i
end

b = 2.times.map {
  def hello
    'hello'
  end
  hello + " world"
}.join(",")

c = A.new.aaa("a","b","c") {|r1, r2|
  r1 + r2 + "1"
}
d = B.new.aaa("a","b","c")

e = baz

p1 = Proc.new {|result|
  result + "_p1"
}
p2 = proc {|result|
  result + "_p2"
}

def get_result(result)
  result + "_gotten"
end

f = foo &p1
g = foo &p2
h = foo &:get_result

i = bar &p1
j = bar &p2
k = bar2 &:get_result

l = [123].group_by {|a|
  a
}

def proc_ret
  p = Proc.new { return "early" }
  p.call
  "end"
end

m = proc_ret

n = (1..4).collect {|i|
  "abcde"[i]
}

[a, b, c, d, e, f, g, h, i, j, k, l, m, n]
