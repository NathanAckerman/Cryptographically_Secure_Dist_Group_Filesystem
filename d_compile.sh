#!/bin/bash
if [ -d "./bin/" ] # check if bin/ exists
	then # it does, so cd in
		echo "bin exists..."
	else # it doesn't, so create it and then cd in
		echo "bin doesn't exist, creating..."
		mkdir bin
fi

javac -d bin/ -classpath .:$(pwd)/bin/bcprov-jdk15on-166.jar src/*.java
echo "Compilation complete."
