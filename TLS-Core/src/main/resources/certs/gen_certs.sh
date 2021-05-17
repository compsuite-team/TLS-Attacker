#!/bin/bash

# This script generates certificates needed in the TLS-Attacker. More precisely, it first generates a RSA, DSA, and ECC root CA certificate
# It then creates DiffieHellman, RSA, DSA and ECC leaf certificates which it signs with EACH of the three root certificates

#generate an extension file to trick openssl into generating a X509 v3 file (otherwise this should be optional)
touch v3.ext
echo $'authorityKeyIdentifier=keyid,issuer\nbasicConstraints=CA:FALSE\nkeyUsage = digitalSignature, keyAgreement' > v3.ext

#root-CA-rsa key
openssl genrsa -out attacker_rsa_ca_key.pem 2048
openssl req -x509 -new -nodes -key attacker_rsa_ca_key.pem -sha256 -days 3650 -out attacker_rsa_ca.pem -subj="/C=DE/ST=NRW/L=Bochum/O=RUB/OU=NDS"

#root-CA-dsa key
openssl genpkey -genparam -algorithm DSA -out attacker_dsa_cap.pem -pkeyopt dsa_paramgen_bits:2048
openssl genpkey -paramfile attacker_dsa_cap.pem -out attacker_dsa_ca_key.pem
openssl req -key attacker_dsa_ca_key.pem -new -x509 -days 2000 -out attacker_dsa_ca.pem -subj "/C=DE/ST=NRW/L=Bochum/O=RUB/OU=NDS"
rm attacker_dsa_cap.pem

#root-CA ECC
openssl ecparam -name secp521r1 -genkey -out attacker_ecc_ca_key.pem
openssl req -key attacker_ecc_ca_key.pem -new -x509 -days 2000 -out attacker_ecc_ca.pem -subj "/C=DE/ST=NRW/L=Bochum/O=RUB/OU=NDS"

#gen dh_dsa and dh_rsa keys and pems
openssl dhparam -out dhparam.pem 1024
openssl genpkey -paramfile dhparam.pem -out dh_key.pem
openssl pkey -in dh_key.pem -pubout -out dh.pem
# DH is a bit weird as we have to generate the certificate request over the root CA certificates
openssl req -new -subj "/C=DE/ST=NRW/L=Bochum/O=RUB/OU=NDS/CN=tlsattacker.com" -key attacker_rsa_ca_key.pem -out rsa.csr
openssl req -new -subj "/C=DE/ST=NRW/L=Bochum/O=RUB/OU=NDS/CN=tlsattacker.com" -key attacker_dsa_ca_key.pem -out dsa.csr
openssl req -new -subj "/C=DE/ST=NRW/L=Bochum/O=RUB/OU=NDS/CN=tlsattacker.com" -key attacker_ecc_ca_key.pem -out ecc.csr
openssl x509 -req -in rsa.csr -CA attacker_rsa_ca.pem -CAkey attacker_rsa_ca_key.pem -force_pubkey dh.pem -CAcreateserial -out dh_rsa_cert.pem -days 1024 -extfile v3.ext
openssl x509 -req -in dsa.csr -CA attacker_dsa_ca.pem -CAkey attacker_dsa_ca_key.pem -force_pubkey dh.pem -CAcreateserial -out dh_dsa_cert.pem -days 1024 -extfile v3.ext
openssl x509 -req -in ecc.csr -CA attacker_ecc_ca.pem -CAkey attacker_ecc_ca_key.pem -force_pubkey dh.pem -CAcreateserial -out dh_ecc_cert.pem -days 1024 -extfile v3.ext
rm dh_key.pem
rm dh.pem
rm dhparam.pem
rm rsa.csr
rm dsa.csr
rm ecc.csr

#gen DSA keys and pems
for len in 512 1024 2048 3072
do
  #dsa parameters
  openssl genpkey -genparam -algorithm DSA -out dsap${len}.pem -pkeyopt dsa_paramgen_bits:${len}
  openssl genpkey -paramfile dsap${len}.pem -out dsa${len}_key.pem
  openssl req -new -nodes -subj "/C=DE/ST=NRW/L=Bochum/O=RUB/OU=NDS/CN=tlsattacker.com" -key dsa${len}_key.pem -out dsa${len}_key.csr
  #signing with CA keys
  openssl x509 -req -in dsa${len}_key.csr -CA attacker_rsa_ca.pem -CAkey attacker_rsa_ca_key.pem -CAcreateserial -out dsa${len}_rsa_cert.pem -days 1024 -extfile v3.ext
  openssl x509 -req -in dsa${len}_key.csr -CA attacker_dsa_ca.pem -CAkey attacker_dsa_ca_key.pem -CAcreateserial -out dsa${len}_dsa_cert.pem -days 1024 -extfile v3.ext
  openssl x509 -req -in dsa${len}_key.csr -CA attacker_ecc_ca.pem -CAkey attacker_ecc_ca_key.pem -CAcreateserial -out dsa${len}_ecc_cert.pem -days 1024 -extfile v3.ext
  rm dsa${len}_key.csr
  rm dsap${len}.pem
done

#gen RSA keys and pems
for len in 512 1024 2048 4096
do
  #rsa parameters
  openssl genpkey -algorithm RSA -out rsa${len}_key.pem -pkeyopt rsa_keygen_bits:${len} 
  openssl req -new -nodes -subj "/C=DE/ST=NRW/L=Bochum/O=RUB/OU=NDS/CN=tlsattacker.com" -key rsa${len}_key.pem -out rsa${len}_key.csr
  #signing with CA keys
  openssl x509 -req -in rsa${len}_key.csr -CA attacker_rsa_ca.pem -CAkey attacker_rsa_ca_key.pem -CAcreateserial -out rsa${len}_rsa_cert.pem -days 1024 -extfile v3.ext
  openssl x509 -req -in rsa${len}_key.csr -CA attacker_dsa_ca.pem -CAkey attacker_dsa_ca_key.pem -CAcreateserial -out rsa${len}_dsa_cert.pem -days 1024 -extfile v3.ext
  openssl x509 -req -in rsa${len}_key.csr -CA attacker_ecc_ca.pem -CAkey attacker_ecc_ca_key.pem -CAcreateserial -out rsa${len}_ecc_cert.pem -days 1024 -extfile v3.ext
  rm rsa${len}_key.csr
  rm rsap${len}.pem
done

#gen ec_names_curve keys and pems
for named_curve in secp160k1 secp160r1 secp160r2 secp192k1 secp224k1 secp224r1 secp256k1 secp384r1 secp521r1 sect163k1 sect163r1 sect163r2 sect193r1 sect193r2 sect233k1 #sect233r1 sect239k1 sect283k1 sect283r1 sect409k1 sect409r1 sect571k1 sect571r1
do
  #rsa parameters
  openssl ecparam -name ${named_curve} -genkey -out ec_${named_curve}_key.pem
  openssl req -new -nodes -subj "/C=DE/ST=NRW/L=Bochum/O=RUB/OU=NDS/CN=tlsattacker.com" -key ec_${named_curve}_key.pem -out ec_${named_curve}_key.csr
  #signing with CA keys
  openssl x509 -req -in ec_${named_curve}_key.csr -CA attacker_rsa_ca.pem -CAkey attacker_rsa_ca_key.pem -CAcreateserial -out ec_${named_curve}_rsa_cert.pem -days 1024 -extfile v3.ext
  openssl x509 -req -in ec_${named_curve}_key.csr -CA attacker_dsa_ca.pem -CAkey attacker_dsa_ca_key.pem -CAcreateserial -out ec_${named_curve}_dsa_cert.pem -days 1024 -extfile v3.ext
  openssl x509 -req -in ec_${named_curve}_key.csr -CA attacker_ecc_ca.pem -CAkey attacker_ecc_ca_key.pem -CAcreateserial -out ec_${named_curve}_ecc_cert.pem -days 1024 -extfile v3.ext
  rm ec_${named_curve}_key.csr
done

# TODO: implemented GOST curves

#cleanup
rm attacker_rsa_ca.srl
rm attacker_dsa_ca.srl
rm attacker_ecc_ca.srl
rm attacker_rsa_ca_key.pem
rm attacker_dsa_ca_key.pem
rm attacker_ecc_ca_key.pem
rm v3.ext