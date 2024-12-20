#!/usr/bin/env python

# Python script to create webhook certificate
# Last modified: 2024.11.21 02:33:51

import os
import logging
import sys
import datetime
import base64
import time
import ipaddress
import json
import random
from datetime import timedelta
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

#####

webhookPodName = os.getenv("POD_NAME", "changeimage-init-pod")
webhookNamespace = os.getenv("NAMESPACE","changeimage-system")
webhookTlsSecretName = os.getenv("WEBHOOK_SECRET_NAME","webhook-tls")
webhookSecretFsPath = os.getenv("SECRET_PATH", "/tls")
webhookMWCName = os.getenv("MWCNAME", "changeimage-webhook")
webhookVWCName = os.getenv("VWCNAME", "changeimage-webhook")
webhookLogLevel = os.getenv("LOG_LEVEL", "INFO")
webhookServiceName = os.getenv("WEBHOOK_SERVICE_NAME", "changeimage")
webhookLabelEnv = os.getenv("LABELS", '{"wbhooklabel":"changeimage"}')
webhookLabels = {}
webhookUpdateAnnotation = "SecretDuringUpdate"

################################################
# Global variables
v1 = None
################################################
def readLabels():
    """
    Function to read implementation labels - from environment variable
    """
    global webhookLabels
    try:
        webhookLabels = json.loads(webhookLabelEnv)
    except json.JSONDecodeError as e:
        logging.worning(f"Failed to parse LABELS: {e}")

    logging.debug(f"The label dictionary: {webhookLabels}")
################################################
def generate_selfsigned_cert(hostname, ip_addresses=None, key=None):
    """Generates self signed certificate for a hostname, and optional IP addresses."""
    
    # Generate our key
    if key is None:
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend(),
        )
    
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname)
    ])
 
    # best practice seem to be to include the hostname in the SAN, which *SHOULD* mean COMMON_NAME is ignored.    
    alt_names = [x509.DNSName(hostname)]
    
    # allow addressing by IP, for when you don't have real DNS (common in most testing scenarios 
    if ip_addresses:
        for addr in ip_addresses:
            # openssl wants DNSnames for ips...
            alt_names.append(x509.DNSName(addr))
            # ... whereas golang's crypto/tls is stricter, and needs IPAddresses
            # note: older versions of cryptography do not understand ip_address objects
            alt_names.append(x509.IPAddress(ipaddress.ip_address(addr)))
    
    san = x509.SubjectAlternativeName(alt_names)
    
    # path_len=0 means this cert can only sign itself, not other certs.
    basic_contraints = x509.BasicConstraints(ca=True, path_length=0)
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1000)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=10*365))
        .add_extension(basic_contraints, False)
        .add_extension(san, False)
        .sign(key, hashes.SHA256(), default_backend())
    )
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    logging.info(f"Self Signed CA created")
    return (cert_pem, cert, key)
################################################
def InitConfig():
    global v1
    try:
        config.load_incluster_config()
    except:
        logging.info("Could not get kube config")
        sys.exit(1)

    v1 = client.CoreV1Api()
################################################
def ReadTls(namespace,secretName):
    global v1

    try:
        secretObj = v1.read_namespaced_secret(secretName,namespace)
    except ApiException as exception:
        if exception.status != 404:
            logging.error(f'Can not to read secret "{secretName}" in the "{namespace}" namespace\n')
            logging.debug(f"Exception: {exception}\n")
            sys.exit(1)
        else:
            logging.info(f'Can not find secret "{secretName}" in the "{namespace}" namespace\n')
            return False,None
    logging.info(f"Found secret: {secretName} in namespace: {namespace}")
    return True,secretObj
####################################################################
def releaseSecret(secret):
    global v1
    if not secret.metadata.annotations:
        logging.debug(f"Secret {secret.metadata.name} does not have annotations in secret")
        return(False)
    
    if  webhookUpdateAnnotation in secret.metadata.annotations:
        if not secret.metadata.annotations[webhookUpdateAnnotation] == webhookPodName:
                logging.debug(f"{webhookPodName}: found annotation {webhookUpdateAnnotation} in secret, bat from another pod: {secret.metadata.annotations[webhookUpdateAnnotation]} - giving up")
                return(False)
    else:
        logging.debug(f"There is no {webhookUpdateAnnotation} annotation in secret {secret.metadata.name}")
        return(False)

    secret.metadata.annotations[webhookUpdateAnnotation] = None

    logging.debug(f'Removing annotation {webhookUpdateAnnotation} from secret {secret.metadata.name}')
    v1.patch_namespaced_secret(
        name=secret.metadata.name,
        namespace=secret.metadata.namespace,
        body=secret
        )
    return(True)

####################################################################
def checkSecret(secret):
    global v1

    if secret.metadata.annotations != None:
        if  webhookUpdateAnnotation in secret.metadata.annotations:
            if secret.metadata.annotations[webhookUpdateAnnotation] == webhookPodName:
                return(True)
            else:
                return(False)  
    else:
        secret.metadata.annotations = {}
    logging.debug(f"Secret annotations: {secret.metadata.annotations}")
    secret.metadata.annotations[webhookUpdateAnnotation] = webhookPodName

    v1.patch_namespaced_secret(
        name=secret.metadata.name,
        namespace=secret.metadata.namespace,
        body=secret
        )
    logging.debug(f"Added annotation: {secret.metadata.annotations}")
    return(True)
    
def checkExpTls(secret):
    global v1

    if not checkSecret(secret):
        return(False)
    keyName = "tls.key"
    certName = "tls.crt"

    if secret.data == None:
        logging.info(f"secret {secret.metadata.name} has no data")
        return(True)

    if keyName not in secret.data or certName not in secret.data:
        logging.info(f"secret {secret.metadata.name} has no {keyName} or {certName}")
        return(True)

    if secret.data[certName] == "" or secret.data[keyName] == "":
        logging.info(f"secret {secret.metadata.name} has empty {keyName} or {certName}")
        return(True)

    now = datetime.datetime.now(datetime.timezone.utc)
    certPEM =  base64.b64decode(secret.data[certName])
    logging.debug(f"certPEM: {certPEM}")
    logging.debug(certPEM)
    cert = x509.load_pem_x509_certificate(certPEM, default_backend())
    daysE = cert.not_valid_after_utc -  now
    days = daysE.days
    logging.info(f"Days to certificat expire: {days}")


    if days <= 90:
        return(True)

    return(False)

def generateKey():
  logging.info(f"renewCert: generating private key")
  key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

  logging.debug(f"renewCert: PEM encoding private key")
  keyPEM = key.private_bytes(
                             encoding=serialization.Encoding.PEM,
                             format=serialization.PrivateFormat.TraditionalOpenSSL,
                             encryption_algorithm=serialization.NoEncryption(),
                             )
  return key, keyPEM

def generateCSR(namespace,key):

  logging.info("Creating CSR")

  dns = list()
  dns.append(f"{webhookServiceName}")
  dns.append(f"{webhookServiceName}.{namespace}")
  dns.append(f"{webhookServiceName}.{namespace}.svc")

  csr = x509.CertificateSigningRequestBuilder()
  csr = csr.subject_name(
           x509.Name(
               [
                   x509.NameAttribute(NameOID.COMMON_NAME, "system:node:" + dns[2]),
                   x509.NameAttribute(NameOID.ORGANIZATION_NAME, "system:nodes")
                   ]
               )
           )

  csr = csr.add_extension(
          x509.SubjectAlternativeName(
              [
                  x509.DNSName(dns[0]),
                  x509.DNSName(dns[1]),
                  x509.DNSName(dns[2]),
                  ]
              ),
          critical=False,
          )

# Chyba nie podpisujemy tu
#   csr = csr.sign(key, hashes.SHA256(), default_backend())
#  request  = csr.sign(key, hashes.SHA256(), default_backend())
  request  = csr.sign(key, hashes.SHA256())


  return(request,csr,dns[1])


################################################################################
def signCSR(namespace,caKey,caCert,key):

    csr, csrPEM, host = generateCSR(namespace,key)
    valid_from = datetime.datetime.now(datetime.timezone.utc)
    valid_to = valid_from + datetime.timedelta(days=365)
    logging.info("Signing CSR")
    dns_names = []
    try:
        san_extension = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san_extension.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        print("No SubjectAlternativeName extension found in CSR.")

    cert_builder = (
       x509.CertificateBuilder()
       .subject_name(csr.subject)
       .issuer_name(caCert.subject)
       .public_key(csr.public_key())
       .serial_number(x509.random_serial_number())
       .not_valid_before(valid_from)
       .not_valid_after(valid_to)
       .add_extension(
          x509.BasicConstraints(ca=False, path_length=None), critical=True,
          )
    )

    if dns_names:
        san_extension = x509.SubjectAlternativeName([x509.DNSName(name) for name in dns_names])
        cert_builder = cert_builder.add_extension(san_extension, critical=False)
    cert = cert_builder.sign(private_key=caKey, algorithm=hashes.SHA256())

#  cert = csr.sign(caKey, hashes.SHA256(), default_backend())
    certPEM = cert.public_bytes(encoding=serialization.Encoding.PEM)
    logging.info(f"CSR request signed")
    return(certPEM)


def writeSecret(namespace,secretName,keyPEM,certPEM):
    logging.info(f"Creating/Modifying secret {secretName}")
    logging.debug(f"cert:\n{certPEM.decode('utf-8')}")

    secretData = {
            "tls.crt": base64.b64encode(certPEM).decode("utf-8"),
            "tls.key": base64.b64encode(keyPEM).decode("utf-8"),
            }

    secretMetadata = client.V1ObjectMeta(
            name=secretName,
            namespace=namespace,
            labels=webhookLabels,
            annotations={webhookUpdateAnnotation: webhookPodName}
            )

    try:
       secret = v1.read_namespaced_secret(name=secretName, namespace=namespace)
    except ApiException as exception:
#### Seems to secret does not exists
        if exception.status == 404:
            try:
                secret = client.V1Secret(metadata=secretMetadata, data=secretData, type="tls")
                v1.create_namespaced_secret(namespace, secret)
            except ApiException as exception:
                logging.error(f'Can not create secret: "{secretName}" in the namespace: "{namespace}", exception: {exception}\n')
                sys.exit(1)
            else:
                logging.info(f"Secret {secretName} created")
        else:
            logging.error(f'Can not read secret: "{secretName}" in the namespace: "{namespace}", exception: {exception}\n')
            sys.exit(1)

#### Update existing secret
    else:
        secret.data = secretData 
        try:
            v1.patch_namespaced_secret(
               name=secretName,
               namespace=namespace,
               body=secret
               )
        except ApiException as exception:
            logging.error(f'Can not update secret: "{secretName}" in the namespace: "{namespace}", exception: {exception}\n')
            sys.exit(1)
        else:
            logging.debug(f"Updated secret: {secretName} in namespace: {namespace}, with data: {secretData}")
            logging.info(f"Secret {secretName} modified")

  
#################################################################################
#################################################################################
def getMWC(admissionApi):
  try:
    mwc = admissionApi.read_mutating_webhook_configuration(webhookMWCName)

  except ApiException as exception:

    if exception.status != 404:
      
      logging.error(f"Can not read MWC: {webhookMWCName}, exception: {exception}\n")
      sys.exit(1)

    elif exception.status == 404:
      logging.info(f'Did not find existing MWC "{webhookMWCName}"')
      logging.debug(f"Exception:\n{exception}\n")
      
      return(None)

  logging.info(f'Existing MWC "{webhookMWCName}" found')
  return mwc

#################################################################################
def getVWC(admissionApi):
  try:
    vwc = admissionApi.read_validating_webhook_configuration(webhookVWCName)

  except ApiException as exception:

    if exception.status != 404:
      
      logging.error(f"Can not read VWC: {webhookVWCName}, exception: {exception}\n")
      sys.exit(1)

    elif exception.status == 404:
      logging.info(f'Did not find existing VMC "{webhookVWCName}"')
      logging.debug(f"Exception:\n{exception}\n")
      
      return(None)

  logging.info(f'Existing VWC "{webhookVWCName}" found')
  return vwc

#################################################################################
#################################################################################
def updateMWC(caCertPEM):
    configuration = client.Configuration().get_default_copy()
    admissionApi = client.AdmissionregistrationV1Api(client.ApiClient(configuration))  

    mwc = getMWC(admissionApi)

    if not mwc:
        logging.error(f"Can not find MWC {webhookMWCName}")
        sys.exit(1)

    logging.info("Found MWC")

    for webhook in mwc.webhooks:
        logging.info("Found webhook {webhook.name} in MWC")
        webhook.client_config.ca_bundle = base64.b64encode(caCertPEM).decode('utf-8')

    try:
        admissionApi.patch_mutating_webhook_configuration(webhookMWCName, mwc)
    except ApiException as exception:
        logging.error(f'Unable to patch MWC "{webhookMWCName}": {exception}\n')
        sys.exit(1)


#################################################################################
def updateVWC(caCertPEM):
    configuration = client.Configuration().get_default_copy()
    admissionApi = client.AdmissionregistrationV1Api(client.ApiClient(configuration))  

    vwc = getVWC(admissionApi)

    if not vwc:
        logging.error(f"Can not find VWC {webhookMWCName}")
        sys.exit(1)

    logging.info("Found VWC")

    for webhook in vwc.webhooks:
        logging.info("Found webhook {webhook.name} in VWC")
        webhook.client_config.ca_bundle = base64.b64encode(caCertPEM).decode('utf-8')

    try:
        admissionApi.patch_validating_webhook_configuration(webhookVWCName, vwc)
    except ApiException as exception:
        logging.error(f'Unable to patch VWC "{webhookVWCName}": {exception}\n')
        sys.exit(1)

#################################################################################
def renewTlsCert(namespace,secretName,keyPEM,certPEM,caCertPEM):

    writeSecret(namespace,secretName,keyPEM,certPEM)
    updateMWC(caCertPEM)
    updateVWC(caCertPEM)

#################################################################################
def writeSecretToFs(namespace,secretName):
    global v1

    logging.info(f"Writing secret {secretName} to FS, path: {webhookSecretFsPath} ")

    try:
        secret = v1.read_namespaced_secret(secretName, namespace)
    except ApiException as exception:
        logging.error(f"Can not read secret: {secretName} in namespace: {namespace} exception: {exception}\n")
        sys.exit(1)

    certPEM = base64.b64decode(secret.data["tls.crt"])
    keyPEM = base64.b64decode(secret.data["tls.key"])

    with open(f"{webhookSecretFsPath}/cert.pem", "wb") as certFile:
        certFile.write(certPEM)

    with open(f"{webhookSecretFsPath}/key.pem", "wb") as keyFile:
        keyFile.write(keyPEM)


#################################################################################
def CreateTls(namespace,secretName):
    InitConfig()

# Generate CA Certificate and service key and certificate
# It will be used in case there is a need to update/create secret and MWC
    key, keyPEM = generateKey()
    caCertPEM,caCert,caKey = generate_selfsigned_cert("CN=changeimage-webhook")
    certPEM = signCSR(namespace,caKey,caCert,key)
# Waiting random time, to avoid two init containers try to update/create
# secret and MWC at the same time
    time.sleep(random.uniform(0, 10) + .01)
    isSecret,secretObj = ReadTls(namespace,secretName)
    needRenewTls = True
    if isSecret:
        needRenewTls = checkExpTls(secretObj)

    if needRenewTls:
        logging.info("Renew TLS nedded")
        renewTlsCert(namespace,secretName,keyPEM,certPEM,caCertPEM)
    else:
        logging.info("Renew TLS not nedded")

    isSecret,secretObj = ReadTls(namespace,secretName)
    if isSecret:
        releaseSecret(secretObj)
    writeSecretToFs(namespace,secretName) 
  
################# MAIN  ########################
def main():

    # Logging setup
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", webhookLogLevel),
        stream=sys.stdout,
        format="%(asctime)s %(levelname)s: %(message)s",
    )

    readLabels()

    logging.info("Create Certificate and webhook started")
    logging.info(f"namespace: {webhookNamespace}")
    logging.info(f"secret: {webhookTlsSecretName}")
    logging.info(f"webhookLabels: {webhookLabels}")
    logging.info(f"webhookSecretFsPath :{webhookSecretFsPath}")
    logging.info(f"webhookPodName :{webhookPodName}")
    logging.info(f"webhookMWCName :{webhookMWCName}")
    logging.info(f"webhookLogLevel :{webhookLogLevel}")
    logging.info(f"webhookServiceName :{webhookServiceName}")
    logging.info(f"webhookUpdateAnnotation :{webhookUpdateAnnotation}")
    CreateTls(webhookNamespace,webhookTlsSecretName)
    logging.info("Create Certificate and webhook ended")


################################################ 
if __name__ == "__main__":

    main()

