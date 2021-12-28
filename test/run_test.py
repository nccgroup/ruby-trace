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
parser = argparse.ArgumentParser()
parser.add_argument("-t", "--trace-opts", help="ruby-trace options string")
parser.add_argument("-w", "--wrapper", help="test wrapper")
parser.add_argument("script", help="test script")
parser.add_argument('expected_insns', nargs=argparse.REMAINDER)
args = parser.parse_args()

# run normal ruby, check disasm, stash result
# run ruby-trace ruby, check executed insns, compare result

ruby_command = ["ruby"]
if args.wrapper != None:
  ruby_command.append(args.wrapper)
ruby_command.append(args.script)

ruby_trace_command = ["ruby-trace"]
if args.trace_opts != None:
  ruby_trace_command += args.trace_opts.split(" ")
ruby_trace_command.append("--")
ruby_trace_command += ruby_command

r = subprocess.run(ruby_command, capture_output=True)
result = None
if r.stdout.startswith(b'result: '):
  result = r.stdout[len(b'result: '):].strip()
else:
  print("result not found for script")
  print(r.stdout)
  sys.exit(1)

if b'\n' in result:
  print("unexpected multiline result")
  print(r.stdout)
  sys.exit(1)


expected_insns = set([i.encode() for i in args.expected_insns])
expected_insns_found = set()

rl = r.stderr.split(b'\n')
for line in rl:
  for i in expected_insns:
    if (b' ' + i + b' ') in line:
      expected_insns_found.add(i)
      expected_insns.remove(i)
      break
  if len(expected_insns) == 0:
    break

if len(expected_insns) > 0:
  print("expected insns not found in ruby output:", ','.join([i.decode('utf-8') for i in expected_insns]))
  print("--------")
  rse = r.stderr.decode('utf-8')
  print(rse)
  sys.exit(1)

rt = subprocess.run(ruby_trace_command, capture_output=True)
rt_result = None
errors = []
failed = False


result_matcher = re.compile(b"^\[[0-9]+\]\{1\} result: (.+)$")
error_matcher = re.compile(b"^\[[0-9]+\]\{L\} (Error \[.+)$")

expected_insns_matchers = {}
for i in args.expected_insns:
  expected_insns_matchers[i] = re.compile(b"^\[[0-9]+\]\{L\} >> " + re.escape(i).encode())

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
  print("result not found in ruby-trace output")
  failed = True
else:
  if rt_result != result:
    print("result from ruby-trace output differs from ruby output")
    print("ruby       result: " + result.decode('utf-8'))
    print("ruby-trace result: " + rt_result.decode('utf-8'))
    failed = True

if len(expected_insns_matchers.keys()) > 0:
  print("expected insns not found in ruby-trace output:", ','.join(expected_insns_matchers.keys()))
  failed = True

if len(errors) > 0:
  print("ruby-trace output contained errors:")
  for error in errors:
    print(error)
  failed = True

if failed:
  print("--------")
  try:
    print(rt.stdout.decode('utf-8'))
  except:
    print(rt.stdout)
  sys.exit(1)

