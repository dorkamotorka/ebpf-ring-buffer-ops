#!/bin/bash

# Number of iterations
count=10000

# Target URL
url="http://172.18.0.10"

# Loop to perform curl 10,000 times
for ((i=1; i<=count; i++))
do
    curl -s $url > /dev/null
    echo "Request #$i completed"
done
