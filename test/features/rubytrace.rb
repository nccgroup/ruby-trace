
module Foo
end

begin 
  #RubyTrace__.set_callbacks("foo", "bar")
  a = RubyTrace__.enable
  b = RubyTrace__.enable
  r = 42+42
  c = RubyTrace__.disable
  d = RubyTrace__.disable
  [a, b, r, c, d]
rescue NameError
  "nope"
end
