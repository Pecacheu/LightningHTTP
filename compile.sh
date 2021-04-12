set -e
#Debug: -g flag
GPP=g++-8
FLAGS="-g -fPIC -std=c++17 -Wno-psabi -Werror=return-type"
CPATH=../../C-Utils
#LD_LIBRARY_PATH=$CPATH/build
#-L$LD_LIBRARY_PATH -lutils -lnet -lssl -lcrypto
mkdir -p build; cd build
echo "Compile LightningHTTP"
$GPP -c $FLAGS -I$CPATH ../http.cpp ../server.cpp
echo "Link"
$GPP http.o -shared -o libhttp.so
$GPP server.o -shared -o libserver.so