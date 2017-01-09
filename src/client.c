
#include "client.h"

void init_openssl_library(void);
void print_error_string(unsigned long err, const char* const label);
void pauseme(void);
void print_cn_name(X509_NAME* const name);

/* Cipher suites, https://www.openssl.org/docs/apps/ciphers.html */
const char* const PREFERRED_CIPHERS = "HIGH:!aNULL:!kRSA:!SRP:!PSK:!CAMELLIA:!RC4:!MD5:!DSS";


int main(int argc, char* argv[])
{
    ((void)(argc)); ((void)(argv));

    unsigned long ssl_err = 0;
    long res=1;
    
    SSL_CTX* ctx = NULL;
    BIO *conn = NULL; 
    SSL *ssl = NULL;
    

    printf("\n### Initialising openssl lib.\n");
    init_openssl_library();
    printf("    OK!\n");
    
    
    do
    {    
        printf("\n### Choosing SSL/TLS method - SSLv23.\n");
        // pointer to constant - a pointer through which we cannot change the value of variable it point  
        const SSL_METHOD* method = SSLv23_method();
        // SSL_METHOD is the ssl_method_st structure used to hold SSL/TLS functions, see: ssl_locl.h
        if( method == NULL )
        {
            ssl_err = ERR_get_error();
            // returns the earliest error code or 0 if OK
            print_error_string(ssl_err, "    ERR! SSLv23_method");
            break; /* failed */
        }
        else
        {
            printf("    - method->version = %d\n", method->version);
            // method->version: SSL 3.0 -> 768 TLS 1.0 -> 769 TLS 1.1 -> 770 TLS 1.2 -> 771
            printf("    OK!\n");
        }
        


        printf("\n### Creating SSL/TLS context structure.\n");
        // The SSL_CTX_new creates a new context structure for use by SSL session(s).
        ctx = SSL_CTX_new(method);
        // SSL_CTX is the ssl_ctx_st structure, see: ssl_locl.h
        if( ctx == NULL)
        {
            ssl_err = ERR_get_error();
            print_error_string(ssl_err, "    ERR! SSL_CTX_new");
            break; /* failed */
        }
        else
        {
            printf("    OK!\n");
        }
        


        printf("\n### Customizing SSL/TLS context structure.\n");
        // first setting up verify callback function.
        // verify_callback function will be used to print Issuer and Subject of the peer. If custom processing is not required
        // (such as printing Issuer and Subject or additional checking), then don't set the callback. 
        // OpenSSL's default checking is often sufficient, so passing NULL to SSL_CTX_set_verify will be also ok.
        // SSL_VERIFY_PEER in client mode requires to validate server's certificate'
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        // the cert issuers chain can not be longer then 5
        SSL_CTX_set_verify_depth(ctx, 5);
        // set additional options to ssl/tls context
        // SSL_OP_ALL - enable bug workarounds see: https://linux.die.net/man/3/ssl_ctx_set_options
        // SSL_OP_NO_SSLv2 - disable SSLv2, it's been know as unsecured and should be never used
        // SSL_OP_NO_SSLv3 - disable SSLv3, only TLS will be used
        // SSL_OP_NO_COMPRESSION - disable compression
        (void)SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);
        // now we set default locations for trusted CA certificates - it can be single file (2nd parameter), or directory with certs (3rd parameter)
        // When we have CA certificates in PEM format, creating singe file is easy:
        // #!/bin/sh
        // rm CAfile.pem
        // for i in ca1.pem ca2.pem ca3.pem ; do
        //      openssl x509 -in $i -issuer | sed 's/^issuer= /# Issuer:/g' >> CAfile.pem
        // done
        if( SSL_CTX_load_verify_locations(ctx, "RootCAfile.pem", NULL) != 1 )
        {
            ssl_err = ERR_get_error();
            print_error_string(ssl_err, "    ERR! SSL_CTX_load_verify_locations");
            break;
        }
        else
        {
            printf("    OK!\n");
        }




        printf("\n### Creating new BIO chain.\n");
        // man bio : A BIO is an I/O abstraction, it hides many of the underlying I/O details from an application. If an application 
        // uses a BIO for its I/O it can transparently handle SSL connections, unencrypted network connections and file I/O.
        conn = BIO_new_ssl_connect(ctx);
        if( conn == NULL)
        {
            ssl_err = ERR_get_error();
            print_error_string(ssl_err, "    ERR! BIO_new_ssl_connect");
            break; /* failed */
        }
        else
        {
            printf("    OK!\n");
        }



        printf("\n### Setting hostname=%s and port=%s to BIO chain.\n", HOST_NAME, HOST_PORT);
        // man: The hostname can be an IP address. The hostname can also include the port in the form hostname:port
        if( BIO_set_conn_hostname(conn, HOST_NAME ":" HOST_PORT) != 1)
        {
            ssl_err = ERR_get_error();
            print_error_string(ssl_err, "    ERR! BIO_set_conn_hostname");
            break; /* failed */
        }
        else
        {
            printf("    OK!\n");
        }
        

        printf("\n### Configuring ssl retrived from BIO chain.\n");
        /* https://www.openssl.org/docs/crypto/BIO_f_ssl.html */
        /* This copies an internal pointer. No need to free.  */
        BIO_get_ssl(conn, &ssl);
        if( ssl == NULL)
        {
            ssl_err = ERR_get_error();
            print_error_string(ssl_err, "    ERR! BIO_get_ssl");
            break; /* failed */
        }
        else
        {
            printf("    - ssl pointer retrived.\n");
        }
        // setting the list of available ciphers 
        if( SSL_set_cipher_list(ssl, PREFERRED_CIPHERS) != 1)
        {
            ssl_err = ERR_get_error();
            print_error_string(ssl_err, "    ERR! SSL_set_cipher_list");
            break; /* failed */
        }
        else
        {
            printf("    - set the list of available ciphers [%s].\n", PREFERRED_CIPHERS);
        }
        // according to: https://wiki.openssl.org/index.php/SSL/TLS_Client
        // SSL_set_tlsext_host_name uses the TLS SNI extension to set the hostname. If you are connecting to a Server Name Indication-aware server 
        // (such as Apache with name-based virtual hosts or IIS 8.0), then you will receive the proper certificate during the handshake.
        if( SSL_set_tlsext_host_name(ssl, HOST_NAME) != 1)
        {
            ssl_err = ERR_get_error();
            /* Non-fatal, but who knows what cert might be served by an SNI server  */
            /* (We know its the default site's cert in Apache and IIS...)           */
            print_error_string(ssl_err, "    ERR! SSL_set_tlsext_host_name");
            /* break; */
        }
        else
        {
            printf("    - set the hostname for the TLS SNI extension [%s].\n", HOST_NAME);
        }
        printf("    OK!\n");


        //pauseme();
        // now we are ready to connect to the remote host
        printf("\n### Connecting using configured BIO chain.\n");
        if( BIO_do_connect(conn) != 1)
        {
            ssl_err = ERR_get_error();
            print_error_string(ssl_err, "    ERR! BIO_do_connect");
            break; /* failed */
        }
        else
        {
            printf("    OK!\n");
        }
        

        //pauseme();
        // since we are connected lets do hand shake
        printf("\n### Handshakeing using connected BIO chain.\n");
        if(BIO_do_handshake(conn) != 1)
        {
            ssl_err = ERR_get_error();
            print_error_string(ssl_err, "    ERR! BIO_do_handshake");
            break; /* failed */
        }
        else {
            printf("    OK!\n");
        }
        
        //pauseme();
        
        
        printf("\n### Performing 3-step verification:\n");
        // Step 1: verify a server certifcate was presented during negotiation
        printf("    - STEP 1 - check is peer has returned certificate.\n");
        X509 *cert_before = NULL, *cert_after = NULL;
        X509* cert = SSL_get_peer_certificate(ssl);
        cert_before = cert;
        if(cert) { 
            // X509 is x509_st structure typedef in ossl_typ.h 
            // x509_st is defined in x509_int.h 
            X509_NAME* iname = cert ? X509_get_issuer_name(cert) : NULL;
            X509_NAME* sname = cert ? X509_get_subject_name(cert) : NULL;
            printf("             * Issuer name  : ["); print_cn_name(iname); printf("]\n");
            printf("             * Subject name : ["); print_cn_name(sname); printf("]\n");
            X509_free(cert); /* Free immediately */
            cert_after = cert;
        } 
        // X509_free() does not change the address of the pointer
        if(NULL == cert)
        {
            /* Hack a code for print_error_string. */
            print_error_string(X509_V_ERR_APPLICATION_VERIFICATION, "    ERR! SSL_get_peer_certificate");
            break; /* failed */
        }
        else 
        {
            printf("             * Cert pointer before [%p] and after [%p] X509_free().\n", cert_before, cert_after);
        }
        // Step 2: verify the result of chain verifcation        
        printf("    - STEP 2 - check the result of chain verification.\n");     
        if( ( res = SSL_get_verify_result(ssl) ) != X509_V_OK )
        {
            /* Hack a code into print_error_string. */
            print_error_string((unsigned long)res, "    ERR! SSL_get_verify_results");
            break; /* failed */
        }
        else
        {
            printf("             * X509_V_OK=%d. SSL_get_verify_result returned [%ld]\n", X509_V_OK, res );
        }
        // Step 3: custom (e.g. hostname) verifcation. 
        // e.g. http://etutorials.org/Programming/secure+programming/Chapter+10.+Public+Key+Infrastructure/10.8+Adding+Hostname+Checking+to+Certificate+Verification/:w!
        printf("    - STEP 3 - Custom veryfication.\n");
        printf("             * do whatever you want.\n");
        printf("    OK!\n");



        /**************************************************************************************/
        /**************************************************************************************/
        /* Now, we can finally start reading and writing to the BIO...                        */
        /**************************************************************************************/
        /**************************************************************************************/
        
        printf("\n### sending data to host [%s]\n", HOST_NAME);
        char *request = "GET " HOST_RESOURCE " HTTP/1.1\r\nHost: " HOST_NAME "\r\nConnection: close\r\n\r\n";
        //char *request = "GET " HOST_RESOURCE " HTTP/1.1\r\nHost: " HOST_NAME "\r\n\r\n";
        printf("=============================== BEGIN =================================\n");
        printf("%s", request);
        printf("===============================  END  =================================\n");
        int data_written = BIO_puts(conn, request);
        printf("    - bytes of data written [%d]\n", data_written);
        if( data_written <= 0)
        {
            printf("    ERR! BIO_puts");
        }
        else
        {
            printf("    OK!\n");
        }


        // be aware of chanks https://en.wikipedia.org/wiki/Chunked_transfer_encoding
        printf("\n### receiving data from host [%s]\n", HOST_NAME);
        int len = 0;
        printf("=============================== BEGIN =================================\n");
        do {
            // char buff[1536] = {};
            char buff[8192] = {};
            memset(buff, 0, sizeof(buff));
            
            /* https://www.openssl.org/docs/crypto/BIO_read.html */
            len = BIO_read(conn, buff, sizeof(buff));
            
            if(len > 0)
            {
                printf("%s", buff);
                //printf("\nlength=%d\n",len);
            }
            /* BIO_should_retry returns TRUE unless there's an  */
            /* error. We expect an error when the server        */
            /* provides the response and closes the connection. */
            
        } while (len > 0 || BIO_should_retry(conn));
        printf("===============================  END  =================================\n");
        printf("    OK!\n");
      
    } while(0);

    if(conn != NULL)
        BIO_free_all(conn);
    
    if(NULL != ctx)
        SSL_CTX_free(ctx);
    
    return 0;
}

void init_openssl_library(void)
{
    (void)SSL_library_init();   // https://www.openssl.org/docs/man1.0.2/ssl/SSL_library_init.html
    SSL_load_error_strings();   // https://www.openssl.org/docs/man1.0.2/crypto/SSL_load_error_strings.html
    OPENSSL_config(NULL);       // https://www.openssl.org/docs/man1.0.2/crypto/OPENSSL_config.html
}

void print_error_string(unsigned long err, const char* const label)
{
    const char* const str = ERR_reason_error_string(err);
    if(str)
        fprintf(stderr, "%s failed: %s\n", label, str);
    else
        fprintf(stderr, "%s failed: %lu (0x%lx)\n", label, err, err);
}

void pauseme(void) 
{
    char single_char = '\0';
    printf("Paused - press ENTER");
    scanf("%c", &single_char);
}

void print_cn_name(X509_NAME* const name)
{
    int idx = -1, success = 0;
    unsigned char *utf8 = NULL;
    
    do
    {
        if(!name) break; /* failed */
        
        idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
        if(!(idx > -1))  break; /* failed */
        
        X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, idx);
        if(!entry) break; /* failed */
        
        ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
        if(!data) break; /* failed */
        
        int length = ASN1_STRING_to_UTF8(&utf8, data);
        if(!utf8 || !(length > 0))  break; /* failed */
        
        printf("%s",utf8);
        success = 1;
        
    } while (0);
    
    if(utf8)
        OPENSSL_free(utf8);
    
    if(!success)
        printf("N/A");
}