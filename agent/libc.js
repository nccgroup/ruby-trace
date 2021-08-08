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

class Libc {
  constructor (libc, parameters) {
    this.libc = libc;
    this.r = null;
    this.client = parameters['client'];
    
    this.fflush = new NativeFunction(libc.getExportByName('fflush'), 'int', ['pointer']);
    this.write = new NativeFunction(libc.getExportByName('write'), 'ssize_t', ['int', 'pointer', 'size_t']);

    this.fputs = new NativeFunction(libc.getExportByName('fputs'), 'int', ['pointer', 'pointer']);

    this.fdopen = new NativeFunction(libc.getExportByName('fdopen'), 'pointer', ['int', 'pointer']);
    this.stdout = libc.getExportByName('stdout').readPointer();

    this.__tls_get_addr = new NativeFunction(libc.getExportByName('__tls_get_addr'), 'pointer', ['pointer'])

    let self = this;
    // let __tls_get_addr_hook = Interceptor.attach(libc.getExportByName('__tls_get_addr'), {
    //   onEnter: function(args) {
    //     this.arg0 = args[0]
    //     self.log(">> __tls_get_addr(" + args[0] + ")")

    //     let ruby_current_ec = self.r.libruby.getExportByName('ruby_current_ec');
    //     self.log(">> *ruby_current_ec (pre):           " + ruby_current_ec.readPointer())
    //   },
    //   onLeave: function(retval) {
    //     self.log(">> __tls_get_addr(" + this.arg0 + ") -> " + retval + "[0]: " + retval.readPointer())
    //     let ruby_current_ec = self.r.libruby.getExportByName('ruby_current_ec');
    //     self.log(">> *ruby_current_ec (post):          " + ruby_current_ec.readPointer())
    //   }
    // });


  }

  log = (msg) => {
    //note: due to the potential for newlines and ansi escapes in the raw size,
    //      which cannot be fixed w/ \b, the right way to handle this for dual
    //      rendering is to use base64, for which 32 bit values will encode to
    //      8 byte strings (sans NUL), which would then require another 8 \b
    //      chars. as of right now, we could just drop most of the encoding
    //      scheme since it's only being used for the client, which only needs
    //      the 00 0b signalling, but we'll leave it as-is for now.

    // we need to make sure that anything ruby has printed but not yet flushed
    // will be printed before our log msg to ensure correct ordering of events
    this.fflush(this.stdout);

    if (this.client !== undefined) {
      let log_buf = Memory.allocUtf8String("\b".repeat(2 + 8) + msg + "\n");
      log_buf.writeU8(0);
      log_buf.add(2).writeU32(msg.length + 1)
      this.write(1, log_buf, 10 + msg.length + 1)  
    } else {
      let log_buf = Memory.allocUtf8String(msg + "\n");
      this.write(1, log_buf, msg.length + 1)  
    }
  }

}

let singleton = null;

module.exports = function (libc, parameters) {
  if (singleton === null) {
    singleton = new Libc(libc, parameters);
  }

  if (libc === undefined) {
    return singleton;
  }

  if (singleton.libc !== libc) {
    return new Libc(libc, parameters);
  }

  return singleton;
}
