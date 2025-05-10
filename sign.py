import argparse
from minio import Minio
from minio.error import S3Error
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import os
import tempfile
import base64
import zipfile
from kubernetes import client, config


def get_cert():
    configuration = client.Configuration()
    config.load_incluster_config(client_configuration=configuration)
    configuration.verify_ssl = False

    v1 = client.CoreV1Api(client.ApiClient(configuration))
    current_namespace = open("/var/run/secrets/kubernetes.io/serviceaccount/namespace").read()

    secret_name = 'private-key-signing-models'
    namespace = current_namespace
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


def package_signed_artefact(original_path, signature_path):
    zip_path = tempfile.mktemp(suffix=".zip")
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.write(original_path, arcname=os.path.basename(original_path))
        zipf.write(signature_path, arcname=os.path.basename(original_path) + '.sig')
    return zip_path


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
        signature = sign(artefact, private_key)
        if signature:
            zip_path = package_signed_artefact(artefact, signature)
            zip_name = f"{artefact_name}.signed.zip"
            minio_client.fput_object('artifacts', zip_name, zip_path)
            try:
                minio_client.remove_object("mlpipeline", artefact_name)
                print(f"Removed original artefact: {artefact_name}")
            except S3Error as e:
                print(f"Error deleting original artefact: {e}")

            print(f"Signed artefact package uploaded as: {zip_name}")


if __name__ == "__main__":
    try:
        main()
    except S3Error as exc:
        print("error occurred.", exc)
