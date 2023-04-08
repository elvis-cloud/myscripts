#!/bin/bash

# Read the list of target servers from a file
while read server; do
  # Add the server to the list of known servers
  ssh-keyscan -H $server >> ~/.ssh/known_hosts
done < hosts
