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

import sys
import argparse
import subprocess
import re

# run normal ruby, check disasm, stash result
# run ruby-trace ruby, check executed insns, compare result

def run(trace_opts, wrapper, script, _disasm_insns, _expected_insns, output=print):
  ruby_command = ["ruby"]
  if wrapper != None:
    ruby_command.append(wrapper)
  ruby_command.append(script)

  ruby_trace_command = ["ruby-trace"]
  if trace_opts != None:
    ruby_trace_command += trace_opts.split(" ")
  ruby_trace_command.append("--")
  ruby_trace_command += ruby_command

  r = subprocess.run(ruby_command, capture_output=True)
  result = None
  if r.stdout.startswith(b'result: '):
    result = r.stdout[len(b'result: '):].strip()
  else:
    output("result not found for script")
    output(r.stdout)
    return 1

  if b'\n' in result:
    output("unexpected multiline result")
    output(r.stdout)
    return 1

  #expected_insns = set([i.encode() for i in _expected_insns])
  #expected_insns_found = set()

  expected_insns_matchers = {}
  for i in _disasm_insns:
    expected_insns_matchers[i] = re.compile(b"^[ |]*[0-9]{4} " + re.escape(i).encode() + b"( .+)?$")

  rl = r.stderr.split(b'\n')
  for line in rl:
    for i in expected_insns_matchers.keys():
      im = expected_insns_matchers[i].match(line)
      if im != None:
        del expected_insns_matchers[i]
        break

    #for i in expected_insns:
    #  if (b' ' + i + b' ') in line:
    #    expected_insns_found.add(i)
    #    expected_insns.remove(i)
    #    break
    if len(expected_insns_matchers) == 0:
      break

  if len(expected_insns_matchers) > 0:
    #output("expected insns not found in ruby output:", ','.join([i.decode('utf-8') for i in expected_insns_matchers.keys()]))
    output("expected insns not found in ruby output:", ', '.join(expected_insns_matchers.keys()))
    output("--------")
    rse = r.stderr.decode('utf-8')
    output(rse)
    return 1

  rt = subprocess.run(ruby_trace_command, capture_output=True)
  rt_result = None
  errors = []
  failed = False


  result_matcher = re.compile(b"^\[[0-9]+\]\{1\} result: (.+)$")
  error_matcher = re.compile(b"^\[[0-9]+\]\{L\} (Error \[.+)$")

  expected_insns_matchers = {}
  for i in _expected_insns:
    expected_insns_matchers[i] = re.compile(b"^\[[0-9]+\]\{L\} >> " + re.escape(i).encode() + b"([ :].+|)$")

  rt_sol = rt.stdout.split(b'\n')

  for line in rt_sol:
    if rt_result == None:
      rm = result_matcher.match(line)
      if rm != None:
        rt_result = rm.groups()[0]

    for i in expected_insns_matchers.keys():
      im = expected_insns_matchers[i].match(line)
      if im != None:
        del expected_insns_matchers[i]
        break

    em = error_matcher.match(line)
    if em != None:
      errors.append(em.groups()[0])


  if rt_result == None:
    output("result not found in ruby-trace output")
    failed = True
  else:
    if rt_result != result:
      output("result from ruby-trace output differs from ruby output")
      output("ruby       result: " + result.decode('utf-8'))
      output("ruby-trace result: " + rt_result.decode('utf-8'))
      failed = True

  if len(expected_insns_matchers.keys()) > 0:
    output("expected insns not found in ruby-trace output:", ', '.join(expected_insns_matchers.keys()))
    #for key in expected_insns_matchers.keys():
    #  output("  " + str(expected_insns_matchers[key]))
    failed = True

  if len(errors) > 0:
    output("ruby-trace output contained errors:")
    for error in errors:
      output(error)
    failed = True

  if failed:
    output("--------")
    try:
      output(rt.stdout.decode('utf-8', errors="ignore"))
    except:
      output(rt.stdout)
    return 1
  return 0

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument("-t", "--trace-opts", help="ruby-trace options string")
  parser.add_argument("-w", "--wrapper", help="test wrapper")
  parser.add_argument("script", help="test script")
  parser.add_argument('expected_insns', nargs=argparse.REMAINDER)
  args = parser.parse_args()

  disasm_insns = args.expected_insns
  expected_insns = args.expected_insns
  pos = args.expected_insns.index("--")
  if pos != -1:
    disasm_insns = args.expected_insns[:pos]
    expected_insns = args.expected_insns[pos+1:]

  sys.exit(run(args.trace_opts, args.wrapper, args.script, disasm_insns, expected_insns, print))

if __name__ == '__main__':
  main()

__all__ = ["run", "main"]
