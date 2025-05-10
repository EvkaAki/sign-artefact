import argparse
from minio import Minio
from minio.error import S3Error
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import os
import tempfile
import base64
from kubernetes import client, config


def get_cert():
    configuration = client.Configuration()
    config.load_incluster_config(client_configuration=configuration)
    configuration.verify_ssl = False

    v1 = client.CoreV1Api(client.ApiClient(configuration))

    secret_name = 'private-key-signing-models'
    namespace = 'admin'
    secret = v1.read_namespaced_secret(secret_name, namespace)

    key_b64 = secret.data.get("private.pem")
    if not key_b64:
        raise ValueError("private.pem not found in secret")

    # Decode base64 and load key
    key_data = base64.b64decode(key_b64)
    print(key_data)
    private_key = load_pem_private_key(key_data, password=None)
    return private_key


def get_artefact(minio_client, bucket_name, object_name):
    try:
        prefix = "/mlpipeline/minio/mlpipeline/"
        object_name = object_name.lstrip(prefix)         # Get object and save it to tempfile
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            minio_client.fget_object(bucket_name, object_name, temp_file.name)
            print("Download successful")
            return temp_file.name
    except S3Error as e:
        print("Error during download:", e)
        return None


def sign(file_path, private_key):
    with open(file_path, "rb") as f:
        data = f.read()

    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    with tempfile.NamedTemporaryFile(delete=False) as sig_file:
        sig_file.write(signature)
        print(f"Signature saved to {sig_file.name}")
        return sig_file.name


def replace_files(minio_client, bucket_name, original_artefact, signed_artefact):
    try:
        # Ensure the signed_artefact file exists
        if not os.path.exists(signed_artefact):
            print(f"Error: Signed artefact '{signed_artefact}' does not exist.")
            return

        # Upload the signed artefact with the same name as the original artefact
        minio_client.fput_object(bucket_name, original_artefact, signed_artefact)
        os.remove(signed_artefact)  # Clean up the temporary signature file
        print(f"Signature uploaded and original signed file removed.")

    except S3Error as e:
        print("Error during upload:", e)

        # If upload fails, try to remove the original artefact from Minio
        try:
            minio_client.remove_object(bucket_name, original_artefact)
            print("Original unsigned file removed from Minio successfully")
        except S3Error as e:
            print("Error during deletion from Minio:", e)


def main():
    parser = argparse.ArgumentParser(description='Sign artefacts and upload to Minio.')
    parser.add_argument('--artefact-path', type=str, required=True, help='Artefact path to sign')
    args = parser.parse_args()
    artefact_name = args.artefact_path
    print(f"Artefact name: {artefact_name}")

    minio_client = Minio(
        "minio.kubeflow.svc.cluster.local:9000",
        access_key='minio',
        secret_key='FY2YHUU7A4ITWS2FTSAR6VKBBH3AFL',
        secure=False
    )

    artefact = get_artefact(minio_client, 'mlpipeline', artefact_name)
    if artefact:
        private_key = get_cert()
        signed_artefact = sign(artefact, private_key)
        if signed_artefact:
            replace_files(minio_client, 'mlpipeline', artefact_name, signed_artefact)


if __name__ == "__main__":
    try:
        main()
    except S3Error as exc:
        print("error occurred.", exc)
