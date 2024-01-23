#!/bin/bash

# Run the server in the background
python3 ./start_server.py &

sleep 1

# Run the client
ssh -vvv 'localhost' -o HostKeyAlgorithms=ssh-rsa

# Check the exit code of the server
exit_code=$?

# Kill the server
kill %1

# Exit with the exit code of the server
exit $exit_code
