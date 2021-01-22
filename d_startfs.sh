#!/bin/bash
cd bin
java -classpath .:$(pwd)/bcprov-jdk15on-166.jar RunFileServer $@
