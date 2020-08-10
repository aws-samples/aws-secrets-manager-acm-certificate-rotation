# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import boto3
import botocore
from botocore.exceptions import WaiterError
from botocore.waiter import WaiterModel, create_waiter_with_client
import logging
import os
import secrets
import time
import json
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
import pem
from cryptography import x509
from cryptography.x509.oid import AttributeOID, NameOID
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed448, ed25519

logger = logging.getLogger()
logger.setLevel(logging.INFO)

cryptography_backend = backends.default_backend()


# ENV VARIABLES
DELAY = 1
MAX_ATTEMPTS = 6
ISSUE_NAME = "CertificateIssued"
RENEW_NAME = "CertificateRenewed"

waiter_config = {
  "version": 2,
  "waiters": {
    "CertificateIssued": {
      "operation": "DescribeCertificate",
      "delay": DELAY,
      "maxAttempts": MAX_ATTEMPTS,
      "acceptors": [
        {
          "matcher": "path",
          "expected": "ISSUED",
          "argument": "Certificate.Status",
          "state": "success"
        },
        {
          "matcher": "path",
          "expected": "PENDING_VALIDATION",
          "argument": "Certificate.Status",
          "state": "retry"
        },
        {
          "matcher": "path",
          "expected": "FAILED",
          "argument": "Certificate.Status",
          "state": "failure"
        }
      ]
    },
    "CertificateRenewed": {
      "operation": "DescribeCertificate",
      "delay": DELAY,
      "maxAttempts": MAX_ATTEMPTS,
      "acceptors": [
        {
          "matcher": "path",
          "expected": "INELIGIBLE",
          "argument": "Certificate.RenewalEligibility",
          "state": "success"
        },
        {
          "matcher": "path",
          "expected": "PENDING_AUTO_RENEWAL",
          "argument": "Certificate.RenewalSummary.RenewalStatus",
          "state": "retry"
        },
        {
          "matcher": "path",
          "expected": "ELIGIBLE",
          "argument": "Certificate.RenewalEligibility",
          "state": "retry"
        },
        {
          "matcher": "path",
          "expected": "PENDING_VALIDATION",
          "argument": "Certificate.RenewalSummary.RenewalStatus",
          "state": "retry"
        },
        {
          "matcher": "path",
          "expected": "FAILED",
          "argument": "Certificate.RenewalSummary.RenewalStatus",
          "state": "failure"
        }
      ]
    }
  }
}

# Main Function
def lambda_handler(event, context):
    """Secrets Manager Rotation Template

    This is a template for creating an AWS Secrets Manager rotation lambda

    Args:
        event (dict): Lambda dictionary of event parameters. These keys must include the following:
            - SecretId: The secret ARN or identifier
            - ClientRequestToken: The ClientRequestToken of the secret version
            - Step: The rotation step (one of createSecret, setSecret, testSecret, or finishSecret)

        context (LambdaContext): The Lambda runtime information

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

        ValueError: If the secret is not properly configured for rotation

        KeyError: If the event parameters do not contain the expected keys

    """
    arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']

    # Setup the client
    service_client = boto3.client('secretsmanager')

    # Make sure the version is staged correctly
    metadata = service_client.describe_secret(SecretId=arn)
    if not metadata['RotationEnabled']:
        logger.error("Secret %s is not enabled for rotation" % arn)
        raise ValueError("Secret %s is not enabled for rotation" % arn)
    versions = metadata['VersionIdsToStages']
    if token not in versions:
        logger.error("Secret version %s has no stage for rotation of secret %s." % (token, arn))
        raise ValueError("Secret version %s has no stage for rotation of secret %s." % (token, arn))
    if "AWSCURRENT" in versions[token]:
        logger.info("Secret version %s already set as AWSCURRENT for secret %s." % (token, arn))
        return
    elif "AWSPENDING" not in versions[token]:
        logger.error("Secret version %s not set as AWSPENDING for rotation of secret %s." % (token, arn))
        raise ValueError("Secret version %s not set as AWSPENDING for rotation of secret %s." % (token, arn))

    if step == "createSecret":
        create_secret(service_client, arn, token)

    elif step == "setSecret": # dont need this
        set_secret(service_client, arn, token)

    elif step == "testSecret": # dont need this
        test_secret(service_client, arn, token)

    elif step == "finishSecret":
        finish_secret(service_client, arn, token)

    else:
        raise ValueError("Invalid step parameter")




############################################################################################################
####################################### HELPER FUNCTIONS ###################################################
############################################################################################################


def create_secret(service_client, arn, token):
    """Create the secret

    This method first checks for the existence of a secret for the passed in token. If one does not exist, it will generate a
    new secret and put it with the passed in token.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

    """
    # Make sure the current secret exists
    current_dict = get_secret_dict(service_client, arn, 'AWSCURRENT')

    #Clients 
    acm_client = boto3.client('acm', region_name = current_dict["CA_ARN"].split(":")[3])
    acm_pca_client = boto3.client('acm-pca', region_name = current_dict["CA_ARN"].split(":")[3])


    waiter_model = WaiterModel(waiter_config)
    issue_waiter = create_waiter_with_client(ISSUE_NAME, waiter_model, acm_client)
    renew_waiter = create_waiter_with_client(RENEW_NAME, waiter_model, acm_client)

    # Now try to get the secret version, if that fails, put a new secret
    try:
        get_secret_dict(service_client, arn, 'AWSPENDING', token)
        logger.info("createSecret: Successfully retrieved secret for %s." % arn)
    except service_client.exceptions.ResourceNotFoundException:
        if current_dict['CERTIFICATE_TYPE'] == 'ACM_MANAGED':
            current_dict = generate_acm_managed(current_dict, acm_client, renew_waiter, issue_waiter)
        else:
            key = ""
            if 'CERTIFICATE_ARN' in current_dict: # renew certificate
                key = serialization.load_pem_private_key(current_dict['PRIVATE_KEY_PEM'].encode(), password=None, backend=cryptography_backend)
            else: # need to create new certificate
                # keypair object
                key = generate_private_key(
                        current_dict["KEY_ALGORITHM"], 
                        "" if "KEY_SIZE" not in current_dict else current_dict["KEY_SIZE"],
                        "" if "EC_CURVE" not in current_dict else current_dict["EC_CURVE"])
            try:
                ## issue PCA certificate
                current_dict = generate_customer_managed(current_dict, acm_pca_client, key)
            except Exception as e:
                logger.error("CreateSecret: Unable to create secret with error: %s" % (e))

        # Put the secret
        service_client.put_secret_value(SecretId=arn, ClientRequestToken=token, SecretString=json.dumps(current_dict), VersionStages=['AWSPENDING'])
        logger.info("createSecret: Successfully put secret for ARN %s and version %s." % (arn, token))


def set_secret(service_client, arn, token):
    """Set the secret

    This method should set the AWSPENDING secret in the service that the secret belongs to. For example, if the secret is a database
    credential, this method should take the value of the AWSPENDING secret and set the user's password to this value in the database.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    """
    # This is where the secret should be set in the service
    # raise NotImplementedError

    # can implement if not concerned about application interruption

    return


def test_secret(service_client, arn, token):
    """Test the secret

    This method should validate that the AWSPENDING secret works in the service that the secret belongs to. For example, if the secret
    is a database credential, this method should validate that the user can login with the password in AWSPENDING and that the user has
    all of the expected permissions against the database.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    """
    # This is where the secret should be tested against the service
    # raise NotImplementedError

    # can implement if not concerned about application interruption

    return


def finish_secret(service_client, arn, token):
    """Finish the secret

    This method finalizes the rotation process by marking the secret version passed in as the AWSCURRENT secret.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn does not exist

    """
    # First describe the secret to get the current version
    metadata = service_client.describe_secret(SecretId=arn)
    current_version = None
    for version in metadata["VersionIdsToStages"]:
        if "AWSCURRENT" in metadata["VersionIdsToStages"][version]:
            if version == token:
                # The correct version is already marked as current, return
                logger.info("finishSecret: Version %s already marked as AWSCURRENT for %s" % (version, arn))
                return
            current_version = version
            break

    # Finalize by staging the secret version current
    service_client.update_secret_version_stage(SecretId=arn, VersionStage="AWSCURRENT", MoveToVersionId=token, RemoveFromVersionId=current_version)
    logger.info("finishSecret: Successfully set AWSCURRENT stage to version %s for secret %s." % (token, arn))


def get_secret_dict(service_client, arn, stage, token=None):
  """Gets the secret dictionary corresponding for the secret arn, stage, and token
  This helper function gets credentials for the arn and stage passed in and returns the dictionary by parsing the JSON string
  Args:
      service_client (client): The secrets manager service client
      arn (string): The secret ARN or other identifier
      token (string): The ClientRequestToken associated with the secret version, or None if no validation is desired
      stage (string): The stage identifying the secret version
  Returns:
      SecretDictionary: Secret dictionary
  Raises:
      ResourceNotFoundException: If the secret with the specified arn and stage does not exist
      ValueError: If the secret is not valid JSON
  """
  required_fields = []


  # Only do VersionId validation against the stage if a token is passed in
  if token:
      secret = service_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage=stage)
  else:
      secret = service_client.get_secret_value(SecretId=arn, VersionStage=stage)
  plaintext = secret['SecretString']
  secret_dict = json.loads(plaintext)

  if 'CERTIFICATE_TYPE' not in secret_dict: # check that we got a certificate type
    raise KeyError("Certificate Type (CERTIFICATE_TYPE) must be set to generate the proper certificate")
  
  if secret_dict['CERTIFICATE_TYPE'] == 'ACM_MANAGED':
    required_fields = ["CA_ARN", "COMMON_NAME", "ENVIRONMENT"]
  else:
    required_fields = ["CA_ARN", "COMMON_NAME", "TEMPLATE_ARN", "KEY_ALGORITHM", "KEY_SIZE", "SIGNING_ALGORITHM"] # add key size, singing algo, validity???

  for field in required_fields:
      if field not in secret_dict:
          raise KeyError("%s key is missing from secret JSON" % field)

  # Parse and return the secret JSON string
  return secret_dict


def generate_private_key(key_type, size, curve):
    """
        Generates a private key using existing data for context

        Supports (RSA, DSA, Ed25519, Ed448, and EllipticCurve keys)

        Args: 
            key_type: The type of key to generate
            size: the size of key to generate
            curve: (optional) if generating an EC key pair

        Raises:
            ValueError: if key type is not supported
    """

    if key_type == "RSA":
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=size,
            backend=cryptography_backend
            )

    if key_type == "DSA":
        return dsa.generate_private_key(
            key_size=size,
            backend=cryptography_backend
        )

    if key_type == "ED25519":
        return ed25519.Ed25519PrivateKey.generate()

    if key_type == "ED448":
        return ed448.Ed448PrivateKey.generate()

    if key_type == "EC":
        return ec.generate_private_key(
            curve=getattr(globals()['ec'], curve),
            backend=cryptography_backend
        )

    raise ValueError("Unsupported key type")


def generate_csr(current_dict, key):
    """
        Generates and signs a CSR for ACM PCA Certificate

        Args:
            current_dict: current secret values used to add extensions/metadata to CSR
            key: key pair to use to sign CSR

        Raises:
    """
    builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, current_dict['COMMON_NAME'])
    ]))



    hash_algorithm = None if (isinstance(key, ed25519.Ed25519PrivateKey) or
                              isinstance(key, ed448.Ed448PrivateKey)) else getattr(globals()['hashes'], current_dict["SIGNING_ALGORITHM"].upper())()

    csr = builder.sign(
        key,
        ec.ECDSA(hash_algorithm) if (isinstance(key, ec.EllipticCurvePrivateKey)) else hash_algorithm,
        cryptography_backend
    )

    return csr.public_bytes(serialization.Encoding.PEM).decode()


def get_signature_algorithm(isEC, alg_type):
    """
        Returns signature algorithm for ACM PCA 

        Args:
            isEC: true if Elliptic Curve certificate
            alg_type: Hash Algorithm from cryptography package to find

        Raises:
            ValueError: Algorithm type not supported
    """

    signing_algorithms = {
        "TYPE_RSA": {
            "sha256": "SHA256WITHRSA",
            "sha384": "SHA384WITHRSA",
            "sha512": "SHA512WITHRSA"  
        },
        "TYPE_ECDSA": {
            "sha256": "SHA256WITHECDSA",
            "sha384": "SHA384WITHECDSA",
            "sha512": "SHA512WITHECDSA" 
        }
    }
    if alg_type not in ['sha256', 'sha384', 'sha512']:
        return ValueError('Signing Algorithm not supported')

    if isEC:
        return signing_algorithms['TYPE_ECDSA'][alg_type]
    else:
        return signing_algorithms['TYPE_RSA'][alg_type]


def generate_acm_managed(current_dict, client, renew, issue):
    """
        Generates an Private Certificate using AWS Ceritificate Manager (ACM)

        Args:
            current_dict: current secret values used to generate certificate
            client: boto3 client used to make requests to ACM
            renew: boto3 waiter designed to wait for certificate renewal to complete
            issue: boto3 waiter to wait for certificate to be issued

        Raises:
            CreateSecret error if unable to export certificate and set secret value
    """
    CERTIFICATE_ARN = ""

    # renew certificate to test everything works
    if 'CERTIFICATE_ARN' in current_dict and current_dict['ENVIRONMENT'] == 'TEST':
        CERTIFICATE_ARN = current_dict['CERTIFICATE_ARN']
        client.renew_certificate(CertificateArn=current_dict['CERTIFICATE_ARN'])
        # wait for certificate renewal to complete
        renew.wait(CertificateArn=CERTIFICATE_ARN)

    else: # first time creating secret
        response = client.request_certificate(
        DomainName = current_dict['COMMON_NAME'],
        CertificateAuthorityArn=current_dict['CA_ARN']
        )
        CERTIFICATE_ARN = response['CertificateArn']
        current_dict['CERTIFICATE_ARN'] = CERTIFICATE_ARN
        issue.wait(CertificateArn=CERTIFICATE_ARN)

    try: # export certificate
        pw = secrets.token_hex(16).encode()
        response = client.export_certificate(
        CertificateArn = CERTIFICATE_ARN,
        Passphrase = pw
        )

        current_dict['CERTIFICATE_PEM'] = response["Certificate"]
        current_dict['CERTIFICATE_CHAIN_PEM'] = response["CertificateChain"]
        # decrypt and store private key
        pkey = serialization.load_pem_private_key(response['PrivateKey'].encode(), password=pw, backend=cryptography_backend)
        current_dict['PRIVATE_KEY_PEM'] = pkey.private_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PrivateFormat.PKCS8,
            encryption_algorithm = serialization.NoEncryption()
        ).decode()
    except WaiterError as e:
        logger.error("CreateSecret: Unable to create secret with error: %s" % (e))
    
    return current_dict


def generate_customer_managed(current_dict, client, key):
    # # issue PCA certificate
    response = client.issue_certificate(
        CertificateAuthorityArn = current_dict['CA_ARN'],
        Csr = generate_csr(current_dict, key).encode(),
        SigningAlgorithm = get_signature_algorithm(
                        True if (isinstance(key, ec.EllipticCurvePrivateKey)) else False, 
                        current_dict['SIGNING_ALGORITHM']),
        TemplateArn = current_dict['TEMPLATE_ARN'],
        Validity = {
            'Value': 365 if "VALIDITY" not in current_dict else current_dict["VALIDITY"], 'Type': 'DAYS'
        }
    )

    current_dict['CERTIFICATE_ARN'] = response['CertificateArn']

    # # wait for certificate to be issued
    waiter = client.get_waiter("certificate_issued")
    waiter.wait(
    CertificateAuthorityArn=current_dict['CA_ARN'], 
    CertificateArn=current_dict['CERTIFICATE_ARN'],
    WaiterConfig={
        'Delay': 1,
        'MaxAttempts': 10
    })

    # # get certificate
    response = client.get_certificate(
        CertificateAuthorityArn=current_dict['CA_ARN'],
        CertificateArn=current_dict['CERTIFICATE_ARN']
    )

    current_dict['CERTIFICATE_PEM'] = response['Certificate']
    current_dict['CERTIFICATE_CHAIN_PEM'] = response['CertificateChain']
    current_dict['PRIVATE_KEY_PEM'] = key.private_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PrivateFormat.PKCS8,
        encryption_algorithm = serialization.NoEncryption()
    ).decode()

    return current_dict
