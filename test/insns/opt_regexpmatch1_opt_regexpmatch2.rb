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

#note: opt_regexpmatch1 was removed in 2.7

r1 = /true/

O = []
def output(msg)
  O.append(msg)
end

r2 = /true/.dup
def r2.=~(obj)
  output "r2.=~"
  nil
end  

r3 = /true/.dup
def r3.!(obj)
  nil
end  

a = /true/ =~ 'true'
b = 'true' =~ /true/
c = 5 =~ /5/
d = Object.new =~ /Object/

e = r1 =~ 'true'
f = 'true' =~ r1

g = r2 =~ 'truetrue'
h = 'truetrue' =~ r2

i = r3 =~ 'falsefalse'
j = 'falsefalse' =~ r3

class String
  def =~(obj)
    output "String.=~"
    nil
  end
end

k = 'true' =~ r1

l = /true/ =~ 'true'
m = 'true' =~ /true/

class Regexp
  def =~(obj)
    output "Regexp.=~"
    nil
  end
end

n = /true/ =~ 'true'
o = 'true' =~ /true/

[O, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o]
