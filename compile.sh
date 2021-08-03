#!/bin/bash
set -e; cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
GPP=g++
FLAGS="-pthread -std=c++17 -Wno-psabi -Werror=return-type"
CPATH=../../C-Utils #Where to find C-Utils headers
mkdir -p build; cd build
echo "Compile LightningHTTP"
[[ $1 = "debug" || $2 = "debug" ]] && FLAGS="$FLAGS -g"
if [[ $1 = "shared" ]]; then
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