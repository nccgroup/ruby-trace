/*
Copyright (c) 2021 NCC Group Security Services, Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/

// root@e28bd82cc250:/ruby-trace# ./node_modules/.bin/frida-compile agent/index.js -o assets/_agent.js -c
// or root@e28bd82cc250:/ruby-trace# npm run compile-agent
// ~/.local/bin/frida --file /usr/local/bin/ruby -l assets/_agent.js -P '{"ruby_script": "test/scan2.rb"}' --runtime v8 --no-pause 2>&1

function setup(parameters) {

  let libruby = null;
  let ruby = null;
  let libc = null;

  Process.enumerateModulesSync().forEach(function(m) {
    if (m.name.indexOf("libruby") != -1) {
      libruby = m;
    } else if (m.name.indexOf("ruby") != -1) {
      ruby = m;
    } else if (m.name.indexOf("libc") != -1) {
      libc = m;
    }
  })

  let { log } = require('./libc')(libc, parameters)

  //note: ruby.js finishes initializing on the return from ruby_setup
  //      rubyvm.js finishes initialization on the entry to ruby_run_node.
  //      the latter shouldn't actually be necessary, and we should be able to
  //      load it on return from ruby_init as well.
  // let r = require('./ruby')(libruby);
  // let vm = require('./rubyvm')()
  //
  //      going forward, we will use callbacks and have ruby.js load rubyvm.js
  //      after it has finished loading, and then rubyvm.js load hooks.js in
  //      same manner.
  //      pre-resume:
  //      - setup ruby_setup/ruby_run_node hooks
  //      - setup main hook
  //      post-resume:
  //      - main hook hit, fixes cli args
  //      - ruby_setup/ruby_run_node hooks hit, inits the rest of ruby-trace and
  //        sets up all tracer hooks by requiring hooks.js
  
  //      we will take advantage of the fact that rubyvm.js requires ruby.js
  //      to register its runtime_init() function to be called by ruby.js's
  //      post ruby_setup hook. however, we will require ruby.js here for
  //      clarity. for some reason, it turns out that we can't run ruby's eval
  //      from the return of ruby_setup or ruby_init, so we will keep rubyvm's
  //      runtime_init tied to ruby_run_node.
  let r = require('./ruby')(libruby)
  let vm = require('./rubyvm')(function() {
    require('./hooks')(parameters)
  })

  let main = null;
  for (let sym of ruby.enumerateSymbols()) {
    if (sym.name == "main") {
      main = sym;
      break;
    }
  }

  if (parameters['client'] !== "ruby-trace" || parameters['ruby_script'] !== undefined) {
    Interceptor.attach(main.address, function(args) {
      let ruby_script = parameters['ruby_script'] !== undefined ? parameters['ruby_script'] : "scan-tpex2.rb";
      args[0] = ptr(2)
      let nargv_buf_sz = Process.pointerSize * (2+1)
      let nargv_buf = Memory.alloc(nargv_buf_sz)
      nargv_buf.writePointer(args[1].readPointer())
      nargv_buf.add(Process.pointerSize*1).writePointer(Memory.allocUtf8String(ruby_script))
      nargv_buf.add(Process.pointerSize*2).writePointer(ptr(0))
      args[1] = nargv_buf
    });
  }

  // require('./hooks')()
  send('setup_done');
}

let run_once = false;

rpc.exports = {
  init: function(stage, parameters) {
    if (!run_once) {
      run_once = true;
      setup(parameters)
    }
  }
};
