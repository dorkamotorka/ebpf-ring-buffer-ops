#!/bin/bash

# Number of iterations
count=1000

# Target URL
url="http://172.18.0.10"

# Start time measurement
start_time=$(date +%s)

# Loop to perform curl 1000 times
for ((i=1; i<=count; i++))
do
    curl -s $url > /dev/null
    echo "Request #$i completed"
done

# End time measurement
end_time=$(date +%s)

# Calculate elapsed time
elapsed_time=$((end_time - start_time))

echo "Total time taken: $elapsed_time seconds"

