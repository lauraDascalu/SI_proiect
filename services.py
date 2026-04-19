import crud
from encrypt import encrypt_file, decrypt_file
from models import StatusType
from sqlalchemy.orm import Session

def process_file(db: Session, file_id: int, framework_id: int, mode: str = "encrypt"):
   
    file_entry = crud.get_file(db, file_id)
    if not file_entry:
        raise ValueError(f"File doesn't exist.")

    if mode == "encrypt":
        return encrypt_file(db, file_id, framework_id)
    elif mode == "decrypt":
        return decrypt_file(db, file_id, framework_id)
    else:
        raise ValueError("Mode must be 'encrypt' or 'decrypt'!")

