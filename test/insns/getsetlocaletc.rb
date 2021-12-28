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


def start_trace
  trace = TracePoint.new(:call) { |tp| }
  trace.enable
  yield
ensure
  trace.disable
end

def block_yield
  yield
end

def block_pass &b
  puts b.to_s
  block_yield(&b)
end

def f(&b)
  a = b
  b = 2
  a.call + 2
end

module Foo
  @@a = "hello"

  def self.foo
    a = nil
    y = "test"
    y = @@a + 5.to_s
    begin
      a = y
    end
    puts "a: #{a}"

    #[1, 2, 3].each do |n|
    #  puts "Number #{n}"
    #end

    a += "0"
    pr = proc do
      a += "1"
      1.times do
        a += "2"
      end
    end
    pr.call
    puts "a: #{a}"

    block_pass{}
    puts f { 1 }
  end
end

start_trace { 
  Foo::foo()
}

puts RubyVM::InstructionSequence.disasm(Foo.method(:foo))
puts RubyVM::InstructionSequence.disasm(method(:block_pass))
puts RubyVM::InstructionSequence.disasm(method(:f))
