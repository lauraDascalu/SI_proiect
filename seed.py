from database import SessionLocal, init_db
import crud
from models import AlgType

def seed_database():
    init_db()
    
    db = SessionLocal()
    try:
        fw = crud.create_framework(db, name="Cryptography", version="42.0.5")
        print(f"[*] Created framework: {fw.name} (ID: {fw.fw_id})")

        algo_aes = crud.create_algorithm(
            db, 
            name="AES-256", 
            type=AlgType.SYMMETRIC, 
            key_size=256, 
            mode="CBC"
        )
        print(f"[*] Created alg: {algo_aes.name}")

        algo_rsa = crud.create_algorithm(
            db, 
            name="RSA-2048", 
            type=AlgType.ASYMMETRIC, 
            key_size=2048, 
            mode="OAEP"
        )
        print(f"[*] Created alg: {algo_rsa.name}")

        db.commit()
        print("\nSuccess")
        
    except Exception as e:
        db.rollback()
        print(f"Error: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    seed_database()