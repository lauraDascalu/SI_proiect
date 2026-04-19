from database import init_db, SessionLocal
import crud
import services
import os
from models import AlgType
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import shutil

def clear_storage(folder_name):
    if os.path.exists(folder_name):
        print(f"[*] Clearing folder: {folder_name}")
        shutil.rmtree(folder_name)
    os.makedirs(folder_name)

def run_test():

    print("\nStart!\n")
    if os.path.exists("crypto_management.db"): 
        os.remove("crypto_management.db")
    
    init_db()
    db = SessionLocal()
    
    STORAGE = "../storage"
    clear_storage(STORAGE)

    try:
        
        fw = crud.create_framework(db, "Cryptography", "42.0.5")

        #  AES
        print("\n TEST AES-256 ")
        algo_aes = crud.create_algorithm(db, "AES-256", AlgType.symmetric, 256, "CBC")
        key_aes = crud.create_key(db, "aes_key", os.urandom(32), 256, algo_aes.algorithm_id)
        
        path_aes = os.path.join(STORAGE, "test_aes.txt")
        with open(path_aes, "w") as f: 
            f.write("AES protected content!")
        
        f_aes = crud.register_file(db, "test_aes.txt", os.path.abspath(path_aes), 10, algo_aes.algorithm_id, key_aes.key_id)
        
        # Encryption
        enc_path = services.process_file(db, f_aes.file_id, fw.fw_id, mode="encrypt")
        print(f"[+] AES encrypted successfully: {os.path.relpath(enc_path)}")
        
        # Decryption
        dec_path = services.process_file(db, f_aes.file_id, fw.fw_id, mode="decrypt")
        print(f"[+] AES decrypted successfully: {os.path.relpath(dec_path)}")
        
        with open(dec_path, "r") as f:
            print(f"  Final content: {f.read()}")

        # RSA
        print("\n TEST RSA-2048 ")
        algo_rsa = crud.create_algorithm(db, "RSA-2048", AlgType.asymmetric, 2048, "OAEP")
        
        # pereche rsa
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        priv_bytes = private_key.private_bytes(
            serialization.Encoding.PEM, 
            serialization.PrivateFormat.PKCS8, 
            serialization.NoEncryption()
        )
        pub_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.PEM, 
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        key_rsa = crud.create_key(db, "rsa_key", priv_bytes, 2048, algo_rsa.algorithm_id, pub_bytes)
        
        path_rsa = os.path.join(STORAGE, "test_rsa.txt")
        with open(path_rsa, "w") as f: 
            f.write("RSA protected content!")
        
        f_rsa = crud.register_file(db, "test_rsa.txt", os.path.abspath(path_rsa), 10, algo_rsa.algorithm_id, key_rsa.key_id)
        
        # Encrypt
        enc_rsa_path = services.process_file(db, f_rsa.file_id, fw.fw_id, mode="encrypt")
        print(f"[+] RSA encrypted successfully: {os.path.relpath(enc_rsa_path)}")
        
        # Decrypt
        dec_rsa_path = services.process_file(db, f_rsa.file_id, fw.fw_id, mode="decrypt")
        print(f"[+] RSA decrypted successfully: {os.path.relpath(dec_rsa_path)}")
        
        with open(dec_rsa_path, "r") as f:
            print(f"  Final content: {f.read()}")

    except Exception as e:
        print(f"[!] Error during test:: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("\nFinish!\n")
        db.close()

if __name__ == "__main__":
    run_test()