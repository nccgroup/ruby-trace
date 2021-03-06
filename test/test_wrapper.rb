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

code = File.read(ARGV[0])

prelude, code = code.split("########")
if code == nil
  code = prelude
  prelude = ""
end

def to_s_addr_fix(obj)
  os = Kernel.instance_method(:to_s).bind(obj).call()
  prefix = os.chomp(">")
  addr = os.split(':')[1].chomp(">")
  nprefix = prefix.sub(":" + addr, ":0x" + ('X'*(addr.length-2)))
  s = obj.to_s
  s.sub(prefix, nprefix)
end

def inspect_addr_fix(obj)
  os = Kernel.instance_method(:to_s).bind(obj).call()
  prefix = os.chomp(">")
  addr = os.split(':')[1].chomp(">")
  nprefix = prefix.sub(":" + addr, ":0x" + ('X'*(addr.length-2)))
  s = obj.inspect
  s.sub(prefix, nprefix)
end

pre = eval(prelude)
if pre.class == RubyVM::InstructionSequence
  STDERR.puts pre.disasm
elsif pre.class == [].class && pre.length > 0 && pre[0].class == RubyVM::InstructionSequence
  pre.each{ |is|
    STDERR.puts is.disasm
  }
end

iseq = RubyVM::InstructionSequence.compile(code)

print "result: "
puts (trace { iseq.eval }).inspect

STDERR.puts RubyVM::InstructionSequence.disasm(iseq)
