import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.backends import default_backend
import crud
from models import StatusType, Keys, Algorithms, Frameworks
import time
from sqlalchemy.orm import Session


import subprocess
import tempfile

OPENSSL_PATH = r"C:\Program Files\Git\usr\bin\openssl.exe"

def calculate_file_hash(file_path: str):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def encrypt_file(db: Session, file_id: int, framework_id: int = 1):
    file_record = crud.get_file(db, file_id)
    if not file_record:
        raise ValueError("The file does not exist.")
    
    key_record = crud.get_key_by_id(db, file_record.key_id)
    algo_record = crud.get_algorithm_by_id(db, file_record.algorithm_id)
    fw_record = crud.get_framework_by_id(db, framework_id)
    
    if not algo_record or not key_record or not fw_record:
        raise ValueError("Not found.")
    
    file_path = file_record.storage_path
    algo_name = algo_record.name
    framework_name = fw_record.name.lower()

    with open(file_path, "rb") as f:
        data = f.read()
    
    output_path = file_path + ".enc"
    start_time = time.time()
   
    try: 
        if "cryptography" in framework_name:
            if "AES" in algo_name.upper():
                iv = os.urandom(16)
                algo_instance = algorithms.AES(key_record.key_private)
                cipher = Cipher(algo_instance, modes.CBC(iv), backend=default_backend())
                encryptor = cipher.encryptor()

                padder = sym_padding.PKCS7(128).padder()
                padded_data = padder.update(data) + padder.finalize()
            
                encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
                result_data = iv + encrypted_data 

            elif "RSA" in algo_name.upper():
                if not key_record.key_public:
                    raise ValueError("RSA encryption requires a public key, but none was found in the DB.")
                
                public_key = serialization.load_pem_public_key(
                    key_record.key_public,
                    backend=default_backend()
                )
                
                result_data = public_key.encrypt(
                    data,
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            else:
                raise ValueError("Unsupported algorithm.")
            
            with open(output_path, "wb") as f:
                f.write(result_data)

        elif "openssl" in framework_name:
            if "AES" in algo_name:
                

                iv = os.urandom(16)
                iv_hex = iv.hex()
                key_hex = key_record.key_private.hex()

                # command: openssl enc -aes-256-cbc -K <key> -iv <iv> -in <p_text> -out <c_text>
                cmd = [
                    OPENSSL_PATH, "enc", "-aes-256-cbc", "-e",
                    "-K", key_hex,
                    "-iv", iv_hex,
                    "-in", file_path,
                    "-out", output_path
                ]
                subprocess.run(cmd, check=True)

                
                with open(output_path, "rb") as f:
                    encrypted_content = f.read()
                with open(output_path, "wb") as f:
                    f.write(iv + encrypted_content)

            elif "RSA" in algo_name:
                if not key_record.key_public:
                    raise ValueError("RSA encryption requires a public key.")
                
                
                with tempfile.NamedTemporaryFile(delete=False, mode="wb") as pub_file:
                    pub_file.write(key_record.key_public)
                    pub_file_path = pub_file.name

                try:
                    # command: openssl pkeyutl -encrypt -pubin -inkey pub.pem -in plain.txt -out enc.txt -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_mgf1_md:sha256 -pkeyopt rsa_oaep_md:sha256
                    cmd = [
                        OPENSSL_PATH, "pkeyutl", "-encrypt", "-pubin",
                        "-inkey", pub_file_path,
                        "-in", file_path,
                        "-out", output_path,
                        "-pkeyopt", "rsa_padding_mode:oaep",
                        "-pkeyopt", "rsa_mgf1_md:sha256",
                        "-pkeyopt", "rsa_oaep_md:sha256"
                    ]
                    subprocess.run(cmd, check=True)
                finally:
                    if os.path.exists(pub_file_path):
                        os.remove(pub_file_path)
            else:
                raise ValueError("Unsupported algorithm.")
        else:
            raise NotImplementedError("Selected framework is not implemented.")
        

        # with open(output_path, "wb") as f:
        #         f.write(result_data)

        end_time = (time.time() - start_time) * 1000

        if not file_record.file_hash:
                file_record.file_hash = calculate_file_hash(file_path)

        crud.update_file_status(db, file_id, StatusType.ENCRYPTED, output_path)
            
        crud.log_performance(
                db=db,
                op="ENCRYPTION",
                time_ms=round(end_time, 4),
                fw_id=framework_id,
                file_id=file_id
            )

        return output_path
    except Exception as e:
            db.rollback()
            raise e
    
    

def decrypt_file(db: Session, file_id: int, framework_id: int = 1):
    
    file_record = crud.get_file(db, file_id)
    if not file_record:
        raise ValueError("The file does not exist.")
    
    if file_record.status != StatusType.ENCRYPTED:
        raise ValueError("File is not in encrypted status.")

    key_record = crud.get_key_by_id(db, file_record.key_id)
    algo_record = crud.get_algorithm_by_id(db, file_record.algorithm_id)
    fw_record = crud.get_framework_by_id(db, framework_id)

    file_path = file_record.storage_path
    algo_name = algo_record.name
    framework_name = fw_record.name.lower()

    # with open(file_path, "rb") as f:
    #     encrypted_data = f.read()

    
    output_path = file_path.replace(".enc", "") 
    if output_path == file_path: output_path += ".dec"
    
    start_time = time.time()

    try:
        if "cryptography" in framework_name:
            
            with open(file_path, "rb") as f:
                encrypted_data = f.read()

            if "AES" in algo_name.upper():
                
                iv = encrypted_data[:16]
                actual_ciphertext = encrypted_data[16:]
                
                algo_instance = algorithms.AES(key_record.key_private)
                cipher = Cipher(algo_instance, modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                
                padded_data = decryptor.update(actual_ciphertext) + decryptor.finalize()
                
               
                unpadder = sym_padding.PKCS7(128).unpadder()
                result_data = unpadder.update(padded_data) + unpadder.finalize()

            elif "RSA" in algo_name.upper():
                
                private_key = serialization.load_pem_private_key(
                    key_record.key_private,
                    password=None,
                    backend=default_backend()
                )
                
                result_data = private_key.decrypt(
                    encrypted_data,
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            else:
                raise ValueError("Unsupported algorithm.")
            
            with open(output_path, "wb") as f:
                f.write(result_data)
        
        elif "openssl" in framework_name:
            if "AES" in algo_name:
                with open(file_path, "rb") as f:
                    file_content = f.read()
                
                
                iv = file_content[:16]
                actual_ciphertext = file_content[16:]

                
                with tempfile.NamedTemporaryFile(delete=False, mode="wb") as cipher_file:
                    cipher_file.write(actual_ciphertext)
                    cipher_file_path = cipher_file.name

                try:
                    cmd = [
                        OPENSSL_PATH, "enc", "-aes-256-cbc", "-d",
                        "-K", key_record.key_private.hex(),
                        "-iv", iv.hex(),
                        "-in", cipher_file_path,
                        "-out", output_path
                    ]
                    subprocess.run(cmd, check=True)
                finally:
                    if os.path.exists(cipher_file_path):
                        os.remove(cipher_file_path)

            elif "RSA" in algo_name:


                with tempfile.NamedTemporaryFile(delete=False, mode="wb") as priv_file:
                    priv_file.write(key_record.key_private)
                    priv_file_path = priv_file.name

                try:
                    # command: openssl pkeyutl -decrypt -inkey priv.pem -in enc.txt -out plain.txt ...
                    cmd = [
                        OPENSSL_PATH, "pkeyutl", "-decrypt",
                        "-inkey", priv_file_path,
                        "-in", file_path,
                        "-out", output_path,
                        "-pkeyopt", "rsa_padding_mode:oaep",
                        "-pkeyopt", "rsa_mgf1_md:sha256",
                        "-pkeyopt", "rsa_oaep_md:sha256"
                    ]
                    subprocess.run(cmd, check=True)
                finally:
                    if os.path.exists(priv_file_path):
                        os.remove(priv_file_path)
            else:
                raise ValueError("Unsupported algorithm.")
        else:
            raise NotImplementedError("Selected framework is not implemented.")
        

        if "openssl" in framework_name:
            if os.path.exists(output_path):
                with open(output_path, "rb") as f:
                    result_data = f.read()
            else:
                raise FileNotFoundError(f"Decrypted file was not created by OpenSSL at {output_path}")
            
        # verificare integritate
        current_hash = hashlib.sha256(result_data).hexdigest()
        if file_record.file_hash and file_record.file_hash != current_hash:
            raise ValueError(f"Integrity check failed!")
        
        
        if "cryptography" in framework_name:
            with open(output_path, "wb") as f:
                f.write(result_data)


        end_time = (time.time() - start_time) * 1000

       
        crud.update_file_status(db, file_id, StatusType.DECRYPTED, output_path)
        
        
        crud.log_performance(
            db=db,
            op="DECRYPTION",
            time_ms=round(end_time, 4),
            fw_id=framework_id,
            file_id=file_id
        )

        return output_path

    except Exception as e:
        db.rollback()
        raise e