#!/bin/sh
# BUGX wrapper: run the official ZAP baseline (spider + passive rules only)
# from Docker. Put this file on PATH as "zap-baseline.py" and chmod +x it.
# BUGX runs it with the evidence directory as the working directory.
exec docker run --rm --network host -v "$PWD:/zap/wrk:rw" zaproxy/zap-stable zap-baseline.py "$@"
