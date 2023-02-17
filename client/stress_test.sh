#!/bin/bash

for (( c=1; c<=10; c++))
do
       yes '0\n0\n' | ./client 127.0.0.1 8080 
        
        
done
