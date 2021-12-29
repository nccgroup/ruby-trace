#!/bin/sh

SCRIPT="$0"
cd `dirname "${SCRIPT}"`
SCRIPT=`basename "${SCRIPT}"`

while [ -L "${SCRIPT}" ]
do
  SCRIPT=`readlink "${SCRIPT}"`
  cd `dirname "${SCRIPT}"`
  SCRIPT=`basename "${SCRIPT}"`
done
SCRIPTDIR=`pwd -P`
cd "${SCRIPTDIR}"

if [ $# != "1" ]; then
  echo "usage: $0 <ruby-version>"
  exit 1
fi
version=$1

vshort=`echo $version | sed 's/\.//g'`

image="ruby${vshort}-frida"

lookup=`docker image ls -q "${image}"`
if [ "${lookup}" == "" ]; then
  docker build -t "${image}" -f "test/Dockerfile.ruby${version}" .
fi

docker run --rm -it -v "${SCRIPTDIR}/../:/ruby-trace" -w "/ruby-trace" "${image}" \
  /bin/sh -c "npm install ; npm run compile-agent"

docker run --rm -it -v "${SCRIPTDIR}/../:/ruby-trace" -w "/ruby-trace" "${image}" \
  /bin/sh -c "npm install -g ; cd test ; python3 test_runner.py test_map.json"
