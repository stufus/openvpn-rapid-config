#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  Generate OpenVPN Certs
#  Stuart Morgan <stuart.morgan@mwrinfosecurity.com> @ukstufus
#
#  This will generate a CA and certificate (signed by the CA) for mutual SSL/TLS
#  authentication. It is intended to be used with OpenVPN.
#

import os
import sys
import tarfile
import subprocess
from OpenSSL import crypto

def certerator_config():
    server_ca = {}
    server_cert = {}
    client_ca = {}
    client_cert = {}

    # Server Certification Authority
    server_ca['commonName'] = "Server CA"
    #server_ca['stateOrProvinceName'] = "Hampshire"
    #server_ca['localityName'] = "Basingstoke"
    #server_ca['organizationName'] = "MWR InfoSecurity"
    #server_ca['organizationalUnitName'] = "Certification Authority"
    #server_ca['emailAddress'] = "labs@mwrinfosecurity.com"
    #server_ca['countryName'] = "GB"
    server_ca['cert_filename'] = "server_ca.pem"
    server_ca['cert_key'] = "server_ca.key"
    server_ca['serial'] = 12345999
    server_ca['validfrom'] = "20160101000000Z"
    server_ca['validto'] = "20170101000000Z"
    server_ca['keyfilesize'] = 4096
    server_ca['hashalgorithm'] = "sha512"

    # Server Certificate (signed by the CA above)
    server_cert['commonName'] = "Server Cert"
    #server_cert['stateOrProvinceName'] = "Hampshire"
    #server_cert['localityName'] = "Basingstoke"
    #server_cert['organizationName'] = "MWR InfoSecurity"
    #server_cert['organizationalUnitName'] = "Certification Authority"
    #server_cert['emailAddress'] = "labs@mwrinfosecurity.com"
    #server_cert['countryName'] = "GB"
    server_cert['cert_filename'] = "server_cert.pem"
    server_cert['cert_key'] = "server_cert.key"
    server_cert['serial'] = 12345888
    server_cert['validfrom'] = "20160101000000Z"
    server_cert['validto'] = "20170101000000Z"
    server_cert['keyfilesize'] = 4096
    server_cert['hashalgorithm'] = "sha512"

    # Client Certification Authority
    client_ca['commonName'] = "Client CA"
    #client_ca['stateOrProvinceName'] = "Hampshire"
    #client_ca['localityName'] = "Basingstoke"
    #client_ca['organizationName'] = "MWR InfoSecurity"
    #client_ca['organizationalUnitName'] = "Certification Authority"
    #client_ca['emailAddress'] = "labs@mwrinfosecurity.com"
    #client_ca['countryName'] = "GB"
    client_ca['cert_filename'] = "client_ca.pem"
    client_ca['cert_key'] = "client_ca.key"
    client_ca['serial'] = 12345777
    client_ca['validfrom'] = "20160101000000Z"
    client_ca['validto'] = "20170101000000Z"
    client_ca['keyfilesize'] = 4096
    client_ca['hashalgorithm'] = "sha512"

    # Client Certificate (signed by the CA above)
    client_cert['commonName'] = "Client Cert"
    #client_cert['stateOrProvinceName'] = "Hampshire"
    #client_cert['localityName'] = "Basingstoke"
    #client_cert['organizationName'] = "MWR InfoSecurity"
    #client_cert['organizationalUnitName'] = "Certification Authority"
    #client_cert['emailAddress'] = "labs@mwrinfosecurity.com"
    #client_cert['countryName'] = "GB"
    client_cert['cert_filename'] = "client_cert.pem"
    client_cert['cert_key'] = "client_cert.key"
    client_cert['serial'] = 12345666
    client_cert['validfrom'] = "20160101000000Z"
    client_cert['validto'] = "20170101000000Z"
    client_cert['keyfilesize'] = 4096
    client_cert['hashalgorithm'] = "sha512"

    return server_ca, server_cert, client_ca, client_cert

def banner():
    sys.stdout.write("\n")
    sys.stdout.write("       .mMMMMMm.             MMm    M   WW   W   WW   RRRRR\n")
    sys.stdout.write("      mMMMMMMMMMMM.           MM   MM    W   W   W    R   R\n")
    sys.stdout.write("     /MMMM-    -MM.           MM   MM    W   W   W    R   R\n")
    sys.stdout.write("    /MMM.    _  \/  ^         M M M M     W W W W     RRRR\n")
    sys.stdout.write("    |M.    aRRr    /W|        M M M M     W W W W     R  R\n")
    sys.stdout.write("    \/  .. ^^^   wWWW|        M  M  M      W   W      R   R\n")
    sys.stdout.write("       /WW\.  .wWWWW/         M  M  M      W   W      R    R\n")
    sys.stdout.write("       |WWWWWWWWWWW/\n")
    sys.stdout.write("         .WWWWWW.         Server/Client Cert Generator (for OpenVPN)\n")
    sys.stdout.write("                        stuart.morgan@mwrinfosecurity.com | @ukstufus\n")
    sys.stdout.write("\n")
    sys.stdout.flush()

def openssl_generate_privatekey(size):
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, size)
    return key

def generate_ca(config_ca):
    ca = crypto.X509()
    ca.set_version(2)
    ca.set_serial_number(config_ca['serial'])
    ca_subj = ca.get_subject()
    if 'commonName' in config_ca:
        ca_subj.commonName = config_ca['commonName']
    if 'stateOrProvinceName' in config_ca:
        ca_subj.stateOrProvinceName = config_ca['stateOrProvinceName']
    if 'localityName' in config_ca:
        ca_subj.localityName = config_ca['localityName']
    if 'organizationName' in config_ca:
        ca_subj.organizationName = config_ca['organizationName']
    if 'organizationalUnitName' in config_ca:
        ca_subj.organizationalUnitName = config_ca['organizationalUnitName']
    if 'emailAddress' in config_ca:
        ca_subj.emailAddress = config_ca['emailAddress']
    if 'countryName' in config_ca:
        ca_subj.countryName = config_ca['countryName']
    if 'validfrom' in config_ca:
        ca.set_notBefore(config_ca['validfrom'])
    if 'validto' in config_ca:
        ca.set_notAfter(config_ca['validto'])
    key = openssl_generate_privatekey(config_ca['keyfilesize'])
    ca.add_extensions([
        crypto.X509Extension("basicConstraints", True, "CA:TRUE, pathlen:0"),
        crypto.X509Extension("keyUsage", False, "keyCertSign, cRLSign"),
        crypto.X509Extension("subjectKeyIdentifier", False, "hash", subject=ca),
    ])
    ca.add_extensions([
        crypto.X509Extension("authorityKeyIdentifier", False, "keyid:always",issuer=ca)
    ])
    ca.set_issuer(ca.get_subject())
    ca.set_pubkey(key)
    ca.sign(key, config_ca['hashalgorithm'])
    return ca, key

def colourise(string,colour):
    return "\033["+colour+"m"+string+"\033[0m"

def generate_certificate(config_cert, ca, cakey, name):
    # Generate the private key
    key = openssl_generate_privatekey(config_cert['keyfilesize'])

    # Generate the certificate request
    req = crypto.X509Req()
    req_subj = req.get_subject()
    if 'commonName' in config_cert:
        req_subj.commonName = config_cert['commonName']
    if 'stateOrProvinceName' in config_cert:
        req_subj.stateOrProvinceName = config_cert['stateOrProvinceName']
    if 'localityName' in config_cert:
        req_subj.localityName = config_cert['localityName']
    if 'organizationName' in config_cert:
        req_subj.organizationName = config_cert['organizationName']
    if 'organizationalUnitName' in config_cert:
        req_subj.organizationalUnitName = config_cert['organizationalUnitName']
    if 'emailAddress' in config_cert:
        req_subj.emailAddress = config_cert['emailAddress']
    if 'countryName' in config_cert:
        req_subj.countryName = config_cert['countryName']

    req.set_pubkey(key)
    req.sign(key, config_cert['hashalgorithm'])

    # Now generate the certificate itself
    cert = crypto.X509()
    cert.set_version(2)
    cert.set_serial_number(config_cert['serial'])
    cert.set_subject(req.get_subject())
    cert.set_pubkey(req.get_pubkey())
    cert.set_issuer(ca.get_subject())

    if 'validfrom' in config_cert:
        cert.set_notBefore(config_cert['validfrom'])
    if 'validto' in config_cert:
        cert.set_notAfter(config_cert['validto'])

    if name == 'client':
        usage = 'clientAuth'
        nscerttype = 'client'
    elif name == 'server':
        usage = 'serverAuth'
        nscerttype = 'server'
    else:
        sys.stdout.write("ERROR: Bad certificate type\n")
        sys.exit(1)

    cert.add_extensions([
        crypto.X509Extension("basicConstraints", True, "CA:FALSE"),
        crypto.X509Extension("keyUsage", False, "digitalSignature,keyAgreement"),
        crypto.X509Extension("extendedKeyUsage", False, usage),
        crypto.X509Extension("nsCertType", False, nscerttype),
        crypto.X509Extension("subjectKeyIdentifier", False, "hash", subject=cert),
        crypto.X509Extension("authorityKeyIdentifier", False, "keyid:always", issuer=ca)
    ])

    cert.sign(cakey, config_cert['hashalgorithm'])
    return req, cert, key

def build_tar(filename,includedfiles):
    tar = tarfile.open(filename, "w:gz")
    for name in includedfiles:
        tar.add(name)
    tar.close()

def build_ca(server_ca,name):
    if os.path.isfile(server_ca['cert_filename']) and os.path.isfile(server_ca['cert_key']):
        sys.stdout.write(colourise("Reusing "+server_ca['cert_filename']+" as the "+name+"\n",'0;36'))
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, file(server_ca['cert_filename']).read())
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, file(server_ca['cert_key']).read())
        sys.stdout.write(colourise(" "+name+" Fingerprint: "+ca_cert.digest('sha1')+"\n", '0;32'))
    else:
        sys.stdout.write(colourise("Generating new "+name+" CA...",'0;32'))
        sys.stdout.flush()
        ca_cert, ca_key = generate_ca(server_ca)
        sys.stdout.write(colourise("..done\n",'0;32'))
        open(server_ca['cert_filename'], "w").write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert))
        open(server_ca['cert_key'], "w").write(crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key))
        sys.stdout.write(colourise(" Written PEM CA certificate to "+server_ca['cert_filename']+"\n", '0;32'))
        sys.stdout.write(colourise(" Written PEM CA key to "+server_ca['cert_key']+"\n", '0;32'))
        sys.stdout.write(colourise(" "+name+" Fingerprint: "+ca_cert.digest('sha1')+"\n", '0;32'))
    return ca_cert, ca_key

def build_cert(config_cert,ca_cert,ca_key,name):
    if os.path.isfile(config_cert['cert_filename']) and os.path.isfile(config_cert['cert_key']):
        sys.stdout.write(colourise("Reusing "+config_cert['cert_filename']+" as the "+name+" certificate\n",'0;36'))
        cert_cert = crypto.load_certificate(crypto.FILETYPE_PEM, file(config_cert['cert_filename']).read())
        cert_key = crypto.load_privatekey(crypto.FILETYPE_PEM, file(config_cert['cert_key']).read())
        sys.stdout.write(colourise(" SHA1 "+name+" Cert Fingerprint: "+cert_cert.digest('sha1')+"\n", '0;32'))
    else:
        sys.stdout.write(colourise("Generating new "+name+" certificate...",'0;32'))
        sys.stdout.flush()
        cert_req, cert_cert, cert_key = generate_certificate(config_cert,ca_cert,ca_key,name)
        sys.stdout.write(colourise("..done\n",'0;32'))
        open(config_cert['cert_filename'], "w").write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert_cert))
        open(config_cert['cert_key'], "w").write(crypto.dump_privatekey(crypto.FILETYPE_PEM, cert_key))
        sys.stdout.write(colourise(" Written PEM certificate to "+config_cert['cert_filename']+"\n", '0;32'))
        sys.stdout.write(colourise(" Written private key to "+config_cert['cert_key']+"\n", '0;32'))
        sys.stdout.write(colourise(" SHA1 "+name+" Cert Fingerprint: "+cert_cert.digest('sha1')+"\n", '0;32'))
    return cert_cert, cert_key

def run_cmd(cmd):
    popen = subprocess.Popen(cmd)
    popen.wait()

def build_openssl_extra():
    if os.path.isfile('ta.key'):
        sys.stdout.write(colourise("Reusing ta.key\n",'0;36'))
    else:
        sys.stdout.write(colourise("Generating new HMAC key...\n",'0;32'))
        run_cmd(['openvpn','--genkey','--secret','ta.key'])
    sys.stdout.write("\n")

    if os.path.isfile('dh2048.pem'):
        sys.stdout.write(colourise("Reusing dh2048.pem\n",'0;36'))
    else:
        sys.stdout.write(colourise("Generating DH params...\n",'0;32'))
        sys.stdout.write("\033[0;90m")
        sys.stdout.flush()
        run_cmd(['openssl','dhparam','-out','dh2048.pem','2048'])
        sys.stdout.write("\033[0;37m")
    sys.stdout.write("\n")

    sys.stdout.flush()

if __name__ == "__main__":
    banner()
    try:
        # Gather all the configuration files
        config_server_ca, config_server_cert, config_client_ca, config_client_cert = certerator_config()
    
        # Build the Server and Client CA (if they do not already exist)
        server_ca_cert, server_ca_key = build_ca(config_server_ca,'Server CA')
        sys.stdout.write("\n")
        client_ca_cert, client_ca_key = build_ca(config_client_ca,'Client CA')
        sys.stdout.write("\n")
            
        # Build the server and client certificate (signed by the above CAs)
        build_cert(config_server_cert, server_ca_cert, server_ca_key, 'server')
        sys.stdout.write("\n")
        build_cert(config_client_cert, client_ca_cert, client_ca_key, 'client')
        sys.stdout.write("\n")

        # Now build ta.key and dh2048.pem if they do not already exist
        build_openssl_extra()
        sys.stdout.write("\n")

        # Now give instructions
        sys.stdout.write(colourise("On the OpenVPN Server:\n",'0;40'))
        sys.stdout.write(colourise("ca client_ca.pem\n",'0;32'))
        sys.stdout.write(colourise("cert server_cert.pem\n",'0;32'))
        sys.stdout.write(colourise("key server_cert.key\n",'0;32'))
        sys.stdout.write("\n")
        sys.stdout.write(colourise("On the OpenVPN Client:\n",'0;40'))
        sys.stdout.write(colourise("ca server_ca.pem\n",'0;32'))
        sys.stdout.write(colourise("cert client_cert.pem\n",'0;32'))
        sys.stdout.write(colourise("key client_cert.key\n",'0;32'))
        sys.stdout.write("\n")

        # Build the server config file
        server_config = open('example.server.conf', 'w')
        server_config.write("port 1194\n")
        server_config.write("proto udp\n")
        server_config.write("dev tun\n")
        server_config.write("ca client_ca.pem\n")
        server_config.write("cert server_cert.pem\n")
        server_config.write("key server_cert.key\n")
        server_config.write("dh dh2048.pem\n")
        server_config.write("server 10.255.255.0 255.255.255.0\n")
        server_config.write("topology net30\n")
        server_config.write("ifconfig-pool-persist ipp.txt\n")
        server_config.write("push \"redirect-gateway def1 bypass-dhcp\"\n")
        server_config.write("push \"dhcp-option DNS 8.8.8.8\"\n")
        server_config.write("push \"dhcp-option DNS 8.8.4.4\"\n")
        server_config.write("keepalive 10 120\n")
        server_config.write("tls-auth ta.key 0\n")
        server_config.write("cipher AES-128-CBC\n")
        server_config.write("comp-lzo\n")
        server_config.write("persist-key\n")
        server_config.write("persist-tun\n")
        server_config.write("#user openvpn\n")
        server_config.write("#group openvpn\n")
        server_config.write("status openvpn-status.log\n")
        server_config.close()

        # Build the client config file
        client_config = open('example.client.conf', 'w')
        client_config.write("client\n")
        client_config.write("dev tun\n")
        client_config.write("proto udp\n")
        client_config.write("remote SERVER 1194\n")
        client_config.write("resolv-retry infinite\n")
        client_config.write("nobind\n")
        client_config.write("#user openvpn\n")
        client_config.write("#group openvpn\n")
        client_config.write("persist-key\n")
        client_config.write("persist-tun\n")
        client_config.write("ca server_ca.pem\n")
        client_config.write("cert client_cert.pem\n")
        client_config.write("key client_cert.key\n")
        client_config.write("remote-cert-tls server\n")
        client_config.write("tls-auth ta.key 1\n")
        client_config.write("cipher AES-128-CBC\n")
        client_config.write("comp-lzo\n")
        client_config.write("#For HTTP proxy uncomment the below\n")
        client_config.write("#http-proxy-retry\n")
        client_config.write("#http-proxy HTTPPROXYSERVER HTTPPROXYPORT\n")
        client_config.write("#http-proxy-option AGENT Mozilla/5.0+(Windows;+U;+Windows+NT+5.0;+en-GB;+rv:1.7.6)+Gecko/20050226+Firefox/1.0.1\n")
        client_config.write("#or create a 2 line text file, username on first line, pass on second, call it userpass.txt\n")
        client_config.write("#http-proxy HTTPPROXYSERVER HTTPPROXYPORT userpass.txt_file basic\n")
        client_config.write("#http-proxy HTTPPROXYSERVER HTTPPROXYPORT userpass.txt_file ntlm\n")
        client_config.write("#socks-proxy SERVER PORT\n")
        client_config.close()

        # Inform the user
        sys.stdout.write(colourise(" Example configs written to example.server.conf and example.client.conf\n", '0;32'))
   
        # Tar up the required files for the server and client
        build_tar('example.server.tar.gz', ['client_ca.pem','ta.key','dh2048.pem','server_cert.pem','server_cert.key'])
        build_tar('example.client.tar.gz', ['server_ca.pem','ta.key','client_cert.pem','client_cert.key'])

        sys.exit(0)

    except Exception as e:
        sys.stderr.write("Error: %s\n" % e)
        sys.exit(1)
