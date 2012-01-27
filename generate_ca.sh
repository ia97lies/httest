
# test if directory exist
if [ ! -d $1 ]; then
  mkdir $1
fi

# move to this directory
cd $1

# generate ca
rm -rf *.pem private newcerts index serial
echo '01' > serial
if [ ! -d private ]; then
  mkdir private
fi
if [ ! -d newcerts ]; then
  mkdir newcerts
fi
touch index
openssl req -nodes -config openssl.cnf -days 3650 -x509 -newkey rsa:1024 -out ca.cert.pem -outform PEM
if [ $? -ne 0 ]; then
  echo FAILED
  rm -f serial
fi

# generate server key
openssl genrsa -out server.key.pem 1024

# generate client key
openssl genrsa -out client.key.pem 1024

# generate server req
openssl req -new -nodes -config openssl.cnf -key server.key.pem -out server.csr

# generate client req
openssl req -new -nodes -config openssl.cnf -key client.key.pem -out client.csr

# sign server
openssl ca -batch -config openssl.cnf -in server.csr -out server.cert.pem

# sign client
openssl ca -batch -config openssl.cnf -in client.csr -out client.cert.pem
