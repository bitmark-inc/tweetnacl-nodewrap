#!/bin/bash
echo $OSTYPE
if [[ $OSTYPE == darwin* ]]; then
	if [[ $(which gcc) ]]; then
		echo "Compiling tweetnacl library!!"
		gcc -dynamiclib -undefined suppress -flat_namespace src/c/tweetnacl.c -o src/c/libtweetnacl.dylib
	else
		echo "This machine does not install G++"
	fi
fi
if [[ $OSTYPE == linux-gnu ]]; then
	if [[ $(dpkg -l | grep g++) ]]; then
		echo "Compiling tweetnacl library!!"
		gcc -shared -fpic src/c/tweetnacl.c -o src/c/libtweetnacl.so
	else
		echo "This machine does not install G++"
	fi
fi