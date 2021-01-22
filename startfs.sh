#!/bin/bash
cd bin
java --class-path .:$(pwd)/bcprov-jdk15on-166.jar RunFileServer $@
