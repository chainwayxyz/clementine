#!/bin/bash
set -e

# Directory structure
CERT_DIR="core/certs"
CA_DIR="$CERT_DIR/ca"
SERVER_DIR="$CERT_DIR/server"
CLIENT_DIR="$CERT_DIR/client"
AGGREGATOR_DIR="$CERT_DIR/aggregator"

# Create directories if they don't exist
mkdir -p $CA_DIR $SERVER_DIR $CLIENT_DIR $AGGREGATOR_DIR

echo "Generating certificates for mutual TLS..."

# Create openssl config file for x509v3 extensions
cat > openssl_x509.cnf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = localhost

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[v3_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints = CA:true

[alt_names]
DNS.1 = localhost
DNS.2 = *.docker.internal
IP.1 = 127.0.0.1
EOF

# Generate CA key and certificate
echo "Generating CA certificate..."
openssl genrsa -out $CA_DIR/ca.key 4096
openssl req -new -x509 -sha256 -days 365 -key $CA_DIR/ca.key -out $CA_DIR/ca.pem \
  -subj "/C=US/ST=California/L=San Francisco/O=Clementine/OU=CA/CN=clementine-ca" \
  -extensions v3_ca -config openssl_x509.cnf

# Generate server key and CSR
echo "Generating server certificate..."
openssl genrsa -out $SERVER_DIR/server.key 2048
openssl req -new -key $SERVER_DIR/server.key -out $SERVER_DIR/server.csr \
  -subj "/C=US/ST=California/L=San Francisco/O=Clementine/OU=Server/CN=localhost" \
  -config openssl_x509.cnf

# Sign server certificate with CA
openssl x509 -req -sha256 -days 365 -in $SERVER_DIR/server.csr \
  -CA $CA_DIR/ca.pem -CAkey $CA_DIR/ca.key -CAcreateserial \
  -out $SERVER_DIR/server.pem \
  -extfile openssl_x509.cnf -extensions v3_req

# Generate client key and CSR
echo "Generating client certificate..."
openssl genrsa -out $CLIENT_DIR/client.key 2048
openssl req -new -key $CLIENT_DIR/client.key -out $CLIENT_DIR/client.csr \
  -subj "/C=US/ST=California/L=San Francisco/O=Clementine/OU=Client/CN=clementine-client" \
  -config openssl_x509.cnf

# Sign client certificate with CA
openssl x509 -req -sha256 -days 365 -in $CLIENT_DIR/client.csr \
  -CA $CA_DIR/ca.pem -CAkey $CA_DIR/ca.key -CAcreateserial \
  -out $CLIENT_DIR/client.pem \
  -extfile openssl_x509.cnf -extensions v3_req

# Generate aggregator key and CSR
echo "Generating aggregator certificate..."
openssl genrsa -out $AGGREGATOR_DIR/aggregator.key 2048
openssl req -new -key $AGGREGATOR_DIR/aggregator.key -out $AGGREGATOR_DIR/aggregator.csr \
  -subj "/C=US/ST=California/L=San Francisco/O=Clementine/OU=Aggregator/CN=clementine-aggregator" \
  -config openssl_x509.cnf

# Sign client certificate with CA
openssl x509 -req -sha256 -days 365 -in $AGGREGATOR_DIR/aggregator.csr \
  -CA $CA_DIR/ca.pem -CAkey $CA_DIR/ca.key -CAcreateserial \
  -out $AGGREGATOR_DIR/aggregator.pem \
  -extfile openssl_x509.cnf -extensions v3_req

# Copy CA certificate to both directories for convenience
cp $CA_DIR/ca.pem $SERVER_DIR/
cp $CA_DIR/ca.pem $CLIENT_DIR/
cp $CA_DIR/ca.pem $AGGREGATOR_DIR/

# Clean up temporary files
rm -f openssl_x509.cnf
rm -f $SERVER_DIR/server.csr
rm -f $CLIENT_DIR/client.csr
rm -f $AGGREGATOR_DIR/aggregator.csr

echo "Certificate generation complete!"
echo "CA certificate: $CA_DIR/ca.pem"
echo "Server certificate: $SERVER_DIR/server.pem"
echo "Server key: $SERVER_DIR/server.key"
echo "Client certificate: $CLIENT_DIR/client.pem"
echo "Client key: $CLIENT_DIR/client.key"
echo "Aggregator certificate: $AGGREGATOR_DIR/aggregator.pem"
echo "Aggregator key: $AGGREGATOR_DIR/aggregator.key"
