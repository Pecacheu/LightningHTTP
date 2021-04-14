#!/bin/bash
set -e; cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

#cd ../C-Utils; ./compile.sh; cd ../LightningHTTP

GPP=g++-8
FLAGS="-g -pthread -std=c++17 -Wno-psabi -Werror=return-type" #-g = Debug
CPATH=../../C-Utils; LPATH=". -L$CPATH/build"
mkdir -p build; cd build
echo "Compile LightningHTTP"
if [[ $1 == "shared" ]]
then
	$GPP -c -fPIC $FLAGS -I$CPATH ../http.cpp ../server.cpp
	echo "Link Shared"
	$GPP http.o -shared -o libhttp.so
	$GPP server.o -shared -o libserver.so
else
	$GPP -c $FLAGS -I$CPATH ../http.cpp ../server.cpp
	echo "Link Static"
	ar rvs libhttp.a http.o
	ar rvs libserver.a server.o
fi

echo "Compile Snap"
LIB="-lserver -lhttp -lutils -lnet -lssl -lcrypto -lz -lstdc++fs"
[ -f snapsrv ] && mv snapsrv snapsrv.old
$GPP $FLAGS ../snap.cpp -I$CPATH -L$LPATH $LIB -o snapsrv