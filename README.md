# Purpose
The European Payment Services Directive relies for its security on PKI technology. To establish trust all 
participants are required to verify each others certificates. To execute the verification the CA certificate that 
issued the participants certificate is needed. This piece of software was written to provide a convenient way for 
system administrators to download all CA certificates required in PSD2 verifications. 

It's important to download the entire certificate chain because many tools, including OpenSSL, validate the entire chain by default. This collection specifically focuses on downloading certificates with the 'ForWebSiteAuthentication' extension.

# Certificate Chain Construction
The certificate chain is built using the **Authority Information Access (AIA)** extensions, which provide URLs to the issuer’s certificate. If the AIA URLs are not available, the issuer certificate is searched for in a local pool. The process continues until the root certificate is found, completing the chain from the web certificate to the root CA certificate.

# Usage
To run the program requires python version 3 or higher and a few libraries must be installed (see requirements.txt).  
The `do_all.sh` script will run all the necessary steps to generate the final bundle.

```
./do_all.sh
```

The final merged file can be found in the root directory as `eIDAS_web.pem`.

# Disclaimer
This software is provided as source code under an MIT license (see LICENSE)

# Security
The European Trust List Browser does provide limited security on the API. The  API is offered over TLS so 
it is possible to ascertain the source of the information. The information itself is not signed so the 
authenticity and integrity cannot be validated.