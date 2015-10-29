#!/bin/bash
if [[ $(dpkg -l | grep g++) ]]; then
	echo "Compiling tweetnacl library!!"
	gcc -shared -fpic src/c/tweetnacl.c -o src/c/libtweetnacl.so
else
	echo "This machine does not install G++"
fi