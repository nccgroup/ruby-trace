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

const frida = require('frida');
const { genScriptCode } = require('./script');
const { attach } = require('./attach');
const os = require('os');
const fs = require('fs');

let log = console.log;

function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

// let finder = (e,i,a)=>(e === 0 && a.length > i+2 && a[i+1] === 8)

function onOutput(pid, fd, data) {
  let description;
  if (data.length > 0) {
    let pos = data.indexOf('\x00\b');
    //let pos = data.findIndex(finder);

    //console.log(data.toString())
    if (pos === -1) {
      description = data.toString().split('\n').map((l)=>`[${pid}]{${fd}} ${l}`).join('\n');
    } else {
      //console.log(Object.prototype.toString.call(data))
      // need to separate out out logs
      let output = [];
      let i = 0;
      do {
        if (pos > i) {
          output.push({ type: "stdout", data: data.slice(i, pos)});
        }
        let msg_len;
        try {
          if (os.endianness == 'LE') {
            msg_len = data.readUInt32LE(pos+2)
          } else {
            msg_len = data.readUInt32BE(pos+2)
          }
        } catch (e) {
          output.push({type: "wat", data: data.slice(pos)})
          break;
        }
        i = pos+10+msg_len;
        let msg = data.slice(pos+10, i);
        output.push({ type: "log", data: msg});
        pos = data.indexOf('\x00\b', i);
      } while (pos !== -1)

      description = '';
      for (let o of output) {
        //console.log(JSON.stringify(o))
        let lines = o.data.toString().split('\n');
        
        if (lines[lines.length-1] === '') {
          lines = lines.slice(0,lines.length-1)
        }
        if (o.type == 'stdout') {
          description += lines.map((l)=>`[${pid}]{${fd}} ${l}`).join('\n') + "\n"
          //description += `[${pid}]{${fd}} ${o.data.toString()}`
        } else if (o.type == 'log') {
          description += lines.map((l)=>`[${pid}]{L} ${l}`).join('\n') + "\n"
          //description += `[${pid}]{log} ${o.data.toString()}`
        }
        //description += '\n'
      }
      //description = data.toString().split('\n').map((l)=>`[${pid}]{${fd}} ${l}`).join('\n');
    }
  } else {
    description = `[${pid}]{${fd} -> EOF}`;
  }
  log(description.trim());
}

function onChildRemoved(child) {
  log('[*] onChildRemoved:', child);
}

async function run(opts, ruby_argv) {
  let fd = null;

  // if (opts.output !== undefined) {
  //   fd = fs.openSync(opts.output, 'w');
  //   log = function(text) {
  //     fs.writeSync(fd, text + "\n");
  //     fd.sync();
  //   }
  // }

  let device = await frida.getLocalDevice();
  device.output.connect(onOutput);
  //device.childRemoved.connect(onChildRemoved);

  let pid;
  try {
    pid = await frida.spawn(ruby_argv, { stdio: 'pipe' /*, aslr: 'disable'*/ });
  } catch (err) {
    throw err;
  }

  let session;
  try {
    session = await frida.attach(pid);
    session.detached.connect((reason)=>{
      log(`[*] onChildDetached(reason='${reason}')`);
      device.output.disconnect(onOutput);
    });
  } catch (err) {
    throw err;
  }

  let scriptCode = await genScriptCode();

  //let { arg0, arg1, arg2 } = args;
  //let async_load_agent_caller = async function(load_agent) {
  //  await load_agent(arg0, arg1, arg2);
  //}
  await attach(pid, session, scriptCode, opts);

  //await session.detach();

  await frida.resume(pid);

  if (fd !== null) {
    fs.closeSync(fd);
  }
}

module.exports = {
  "run": run
};
