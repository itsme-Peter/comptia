Generating RSA asymmetric key pair
> openssl genrsa -out name 2048

extracting public key
> openssl rsa -in corp.515support.com.key -pubout -out corp.515support.com_public.key

Generating a certificate signing request
> openssl req -new -key corp.515support.com.key -out corp.515support.com.csr

verifying thecertificate request
> openssl req -text -in corp.515support.com.csr -noout -verify

Generating a self signed request
> openssl req -newkey rsa:2048 -nodes -keyout corp.515support.com.key -x509 -days 365 -out corp.515support.com.crt

Converting the format of the file
> openssl pkcs12 -export -name "corp.515support.com" -out corp.515support.com.pfx -inkey corp.515support.com.key -in corp.515support.com.crt