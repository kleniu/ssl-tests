## Creating a Private Certification Authority
Information provided here is based on the awesome "OpenSSL Cookbook" by Ivan Ristić available at: https://www.feistyduck.com/library/openssl-cookbook/
https://jamielinux.com/docs/openssl-certificate-authority/index.html


# Dictionary
- CA   = certificate authority - is an entity that signs digital certificates
- CRL  = Certificate Revocation List
- CSR  = Certificate Signing Request
- OCSP = Online Certificate Status Protocol 

# Procedure of making self signed certificate
'''
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 9999 -batch
'''
- req               - command for X.509 Certificate Signing Request (CSR) Management.
- -x509             - output a x509 structure instead of a cert. req.
- -newkey rsa:2048  - generate a new RSA key of 'bits' in size
- -keyout key.pem   - file to send the key to
- -out cert.pem     - output file
- -days 9999
- -batch            - do not ask anything during request generation

# Decode cert.pem
'''
openssl x509 -in cert.pem -text
'''

## Extract specific information from certificate

Who issued the cert?
'''
$ openssl x509 -in cert.pem -noout -issuer
'''

To whom was it issued?
'''
$ openssl x509 -in cert.pem -noout -subject
'''

For what dates is it valid?
'''
$ openssl x509 -in cert.pem -noout -dates
'''

The above, all at once
'''
$ openssl x509 -in cert.pem -issuer -noout -subject -dates
'''

What is its hash value?
'''
$ openssl x509 -in cert.pem -noout -hash
'''

What is its MD5 fingerprint?
'''
$ openssl x509 -in cert.pem -noout -fingerprint
'''