import sys
import json
import subprocess
import traceback
import run_test


o = []
def output(*parts):
  global o
  if len(parts) > 0:
    if type(parts[0]) == bytes:
      o.append(b' '.join(parts).decode('utf-8', errors="ignore"))
    else:
      o.append(' '.join(parts))

def main():
  global o
  if len(sys.argv) != 2:
    print("usage: {} <test_map.json>".format(sys.argv[0]))
    sys.exit(1)

  ruby = subprocess.run(['ruby', '-e', 'puts RUBY_VERSION.split(".")[0..1].join("")'], capture_output=True)
  ruby_version = ruby.stdout.decode('utf-8').strip()
  print("detected ruby version: " + repr(ruby_version))

  tests = json.loads(open(sys.argv[1], 'r').read())['tests']

  failed = False

  for key in tests.keys():
    test = tests[key]
    versions = test["v"]
    if "all" not in versions and ruby_version not in versions:
      print("[-] skipping " + key)
      continue

    trace_opts = test.get("t")
    wrapper = test.get("w")
    script = key
    if "s" in test:
      script = test["s"]
    expected_insns = test["insns"]
    disasm_insns = test.get("disasm_insns", expected_insns)
    r = None
    e = None
    try:
      r = run_test.run(trace_opts, wrapper, script, disasm_insns, expected_insns, output)
    except Exception:
      r = 2
      e = traceback.format_exc()
    if r == 0:
      print("[✓] " + key)
    else:
      failed = True
      print("[✗] " + key)
      if r == 2:
        print(e)
      for line in o:
        for subline in line.split("\n"):
          print("    " + subline)
    o.clear()

  print("--------")
  if failed:
    print("[✗] Some tests failed.")
    sys.exit(1)
  else:
    print("[✓] All tests passed.")
    sys.exit(0)

if __name__ == '__main__':
  main()
