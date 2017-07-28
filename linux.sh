docker run -v $PWD:/home -e ACSKEY=$ACSKEY -e ACSPWD=$ACSPWD rockywei/swift:3.1 /bin/bash -c "cd /home; swift test --build-path=.build_lin"

