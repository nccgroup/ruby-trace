#!/usr/bin/env node

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

const { promisify } = require('util');
const { execFile } = require('child_process');
const pExecFile = promisify(execFile);

const program = require('commander');
const version = require('../package.json').version;

const hook = require('../lib/hook');

main().catch((err)=>{
  console.error(err);
  process.exit(1);
});



async function main() {
  program
    .version(version)
    .usage('[options] -- <ruby> [args...] ')
    //.option('-o, --output <logfile>', 'File path for logging output')
    .option('-s, --trace-symbols <symbol,symbol,...>', 'Custom libruby.so symbols to enable tracing on')
    .parse(process.argv);

  program.args = program.args || [];

  let argc = process.argv.length
  let c = 0;
  for (let arg of process.argv) {
    if (arg == "--") {
      break;
    }
    c += 1;
  }

  let ruby_argv = process.argv.slice(c+1);

  if (program.args.length == 0 || ruby_argv.length == 0) {
    console.error("Error: must include in a ruby command")
    program.help();
  }

  let argv0 = (await pExecFile("which", [ruby_argv[0]])).stdout.trim();
  ruby_argv[0] = argv0;

  //console.log(JSON.stringify(program.opts()))

  await hook.run(program.opts(), ruby_argv);
  //process.exit(0);
}
