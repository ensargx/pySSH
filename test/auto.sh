

# iterate 1 to 10
for i in {1..20}; do
    python3 start_server.py $i &
    pid=$!
    sleep 1
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o HostKeyAlgorithms="ssh-rsa" 'localhost'

    # Check the exit status of the last command
    if [ $? -eq 0 ]; then
        echo "SSH connection successful for $i"
        break
    else
        echo "SSH connection failed for $i"
    fi
done