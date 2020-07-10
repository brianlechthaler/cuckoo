#!/bin/bash
cp ~/.cuckoo/agent/agent.py $PWD/.agent.py
echo "FROM python:2.7" > agent.Dockerfile
echo "COPY .agent.py /opt/agent.py" >> agent.Dockerfile
echo "CMD python /opt/agent.py" >> agent.Dockerfile
echo "-> Resulting dockerfile:" 
cat agent.Dockerfile
docker build -t cuckooagent:latest -f agent.Dockerfile .
echo "-> Cleaning up..."
rm -rf .agent.py
rm -rf agent.Dockerfile
