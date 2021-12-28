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


async function attach(pid, session, scriptCode, opts) {
  const script = await session.createScript(scriptCode);

  let finish = new Promise((res,rej)=>{
    script.message.connect((message) => {
      if (message.type == "send" && message.payload == 'setup_done') {
        res(null);
      } else if (message.type == "error") {
        // console.error("message: " + JSON.stringify(Object.getOwnPropertyNames(message)))
        let lines;
        if (message.stack != undefined) {
          lines = message.stack.split('\n');
        } else {
          lines = message.description.split('\n');
        }
        if (lines[lines.length-1] === '') {
          lines = lines.slice(0,lines.length-1)
        }
        let out = lines.map((l)=>`[ruby-trace]{JSError} ${l}`).join('\n')
        console.log(out)
      }
    });
  });

  script.logHandler = (level, text) => {
    console.log(`[ruby-trace]{${level}} ${text}`)
  };


  await script.load();

  let init_args = {'client': 'ruby-trace'};
  Object.assign(init_args, opts);
  
  await script.exports.init('early', init_args);
  await finish;
}

module.exports = {
  "attach": attach
};
