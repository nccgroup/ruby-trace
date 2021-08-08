# ruby-trace

ruby-trace is a frida-based tracer for (c)[ruby](https://github.com/ruby/ruby).
It currently supports ruby 2.6-3.0.

# Install

```
$ sudo npm install -g --unsafe-perm ruby-trace
```

***Note:*** `--unsafe-perm` appears to be necessary when installing as root due
            to how the `frida` depdendency builds during install.

# Building from Source

```
$ git clone https://github.com/nccgroup/ruby-trace
$ cd ruby-trace
$ npm install
$ npm run compile-agent
$ sudo npm install -g
```

# Usage

ruby-trace uses Ruby's tracing infrastructure to enable/disable its own
tracing. If you want to trace against an entire program, you can do something
like the following:

```
$ ruby-trace -- ruby -e 'TracePoint.new(:call) { |tp| }.enable' -e "$(cat test/readme.rb)"
```

Alternatively, for more fine-grained tracing, you would write something like
the following:

```
def ruby_trace
  t = TracePoint.new(:call) { |tp| }
  t.enable
  yield
ensure
  t.disable
end

...

ruby_trace {
  ...
}

...
```

```
$ ruby-trace -- ruby /path/to/file.rb
```

# License

ruby-trace is licensed under the 2-clause BSD License and the Ruby License.
