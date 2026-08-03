#!/bin/bash
#
# quico — QUIC Interop Runner endpoint entrypoint.
# Template: quic-interop/quic-network-simulator
#
# Provided by the runner:
#   ROLE          client | server
#   TESTCASE      test case name
#   REQUESTS      space-separated URLs for the client to download
#   SSLKEYLOGFILE NSS key log path (inside /logs)
#   QLOGDIR       qlog output directory
# Bind-mounted: /www (server), /downloads (client), /certs (both).

# Set up the routing needed for the simulation.
/setup.sh

# Supported test cases. Anything else MUST exit 127 ("unsupported"), which the
# runner shows as a neutral '?' instead of a red failure — and which it also
# probes for directly, by starting the endpoint with a randomly generated
# TESTCASE and expecting it to decline. An allow-list is therefore required:
# with a deny-list the random probe looks like a valid test case, the server
# starts and listens forever, and the whole run hangs before the client is
# ever launched.
#
# Note several test cases reach us under a different name than they appear in
# the results matrix — longrtt arrives as `handshake`; multiplexing,
# amplificationlimit, blackhole, transferloss, transfercorruption and
# rebind-* all arrive as `transfer`; handshakeloss arrives as `multiconnect`.
# They need no entries of their own: only the simulator behaves differently.
case "$TESTCASE" in
    "handshake"|"transfer"|"multiconnect"|"http3"|"keyupdate")
        # supported
        ;;
    *)
        echo "Unsupported test case: $TESTCASE"
        exit 127
        ;;
esac

mkdir -p /logs

echo "quico $(cat /quico/commit.txt 2>/dev/null || echo 'commit unknown')"
echo "ROLE=$ROLE TESTCASE=$TESTCASE"

if [ "$ROLE" == "client" ]; then
    # Wait for the simulator to start up.
    /wait-for-it.sh sim:57832 -s -t 30
    echo "REQUESTS=$REQUESTS"
    node /quico/interop.js client 2>&1 | tee -a /logs/client.log
    # tee ends the pipeline, so ${PIPESTATUS[0]} is required to report node's
    # status: the runner reads 0 as success and 1 as failure. Using tee's own
    # status would report success unconditionally.
    exit "${PIPESTATUS[0]}"
elif [ "$ROLE" == "server" ]; then
    node /quico/interop.js server 2>&1 | tee -a /logs/server.log
    exit "${PIPESTATUS[0]}"
else
    echo "unknown ROLE: $ROLE" >&2
    exit 127
fi
