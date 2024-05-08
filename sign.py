import argparse
from minio import Minio
from minio.error import S3Error
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import os


def get_artefact(minio_client, bucket_name, object_name):

    # File path to save the downloaded file
    file_path = './tempfile'
    try:
        # Get object and save it to file_path
        minio_client.fget_object(bucket_name, object_name, file_path)
        print("Download successful")
        return file_path
    except S3Error as e:
        print("Error during download:", e)
        return None


def sign(file_path, private_key_path):
    with open(private_key_path, "rb") as key_file:
        private_key = load_pem_private_key(key_file.read(), password=None)

    # Read the content of the file to sign
    with open(file_path, "rb") as f:
        data = f.read()

    # Generate the signature
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    signature_file_path = file_path + '.sig'
    with open(signature_file_path, "wb") as sig_file:
        sig_file.write(signature)

    return signature_file_path


def replace_files(minio_client, bucket_name, original_artefact, signed_artefact):
    try:
        minio_client.fput_object(bucket_name, signed_artefact, "signature.sig")
        os.remove(signed_artefact)

    except S3Error as e:
        print("Error during upload:", e)

        try:
            minio_client.remove_object(bucket_name, original_artefact)
            print("Original unsigned file removed from Minio successfully")
        except S3Error as e:
            print("Error during deletion from Minio:", e)

def main():
    parser = argparse.ArgumentParser(description='Find and delete run pods.')
    parser.add_argument('--artefact-name', type=str)
    args = parser.parse_args()
    artefact_name = args.artefact_name
    minio_client = Minio(
            "minio.kubeflow.svc.cluster.local:9000",
            access_key='minio',
            secret_key='H5MQWLCSVTOHZ20EQU920IEATPIDG9',
            secure=False
    )
    artefact = get_artefact(minio_client, 'bucket', artefact_name)
    signed_artefact = sign(artefact)
    replace_files(minio_client, 'bucket', artefact_name, signed_artefact)


if __name__ == "__main__":
    try:
        main()
    except S3Error as exc:
        print("error occurred.", exc)