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

        else:
            raise NotImplementedError("Alternative framework not ready")
    
        with open(output_path, "wb") as f:
                f.write(result_data)

        end_time = (time.time() - start_time) * 1000

        if not file_record.file_hash:
                file_record.file_hash = calculate_file_hash(file_path)

        crud.update_file_status(db, file_id, StatusType.encrypted, output_path)
            
        crud.log_performance(
                db=db,
                op="encryption",
                time_ms=round(end_time, 4),
                mem_mb=0.1, #to change
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
    
    if file_record.status != StatusType.encrypted:
        raise ValueError("File is not in encrypted status.")

    key_record = crud.get_key_by_id(db, file_record.key_id)
    algo_record = crud.get_algorithm_by_id(db, file_record.algorithm_id)
    fw_record = crud.get_framework_by_id(db, framework_id)

    file_path = file_record.storage_path
    algo_name = algo_record.name
    framework_name = fw_record.name.lower()

    with open(file_path, "rb") as f:
        encrypted_data = f.read()

    
    output_path = file_path.replace(".enc", "") 
    if output_path == file_path: output_path += ".dec"
    
    start_time = time.time()

    try:
        if "cryptography" in framework_name:
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
        else:
            raise NotImplementedError("Alternative framework not ready")

        # verificare integritate
        current_hash = hashlib.sha256(result_data).hexdigest()
        if file_record.file_hash and file_record.file_hash != current_hash:
            raise ValueError(f"Integrity check failed!")
        
        
        with open(output_path, "wb") as f:
            f.write(result_data)

        end_time = (time.time() - start_time) * 1000

       
        crud.update_file_status(db, file_id, StatusType.decrypted, output_path)
        
        
        crud.log_performance(
            db=db,
            op="decryption",
            time_ms=round(end_time, 4),
            mem_mb=0.1,
            fw_id=framework_id,
            file_id=file_id
        )

        return output_path

    except Exception as e:
        db.rollback()
        raise e