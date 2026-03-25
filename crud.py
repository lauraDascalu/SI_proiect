from sqlalchemy.orm import Session
from models import Algorithms, Keys, Files, Performance, Frameworks
from datetime import datetime, timezone

#create
def create_algorithm(db: Session, name: str, type: str, key_size: int, mode: str = "CBC"):
    algo = Algorithms(name=name, type=type, operation_mode=mode, key_size_default=key_size)
    db.add(algo)
    db.commit()
    db.refresh(algo)
    return algo

def create_framework(db: Session, name: str, version: str):
    fw = Frameworks(name=name, lib_version=version)
    db.add(fw)
    db.commit()
    db.refresh(fw)
    return fw

def create_key(db: Session, tag: str, private_b: bytes, size: int, algo_id: int, public_b: bytes = None):
    key_entry = Keys(
        tag=tag,
        key_private=private_b,
        key_public=public_b,
        key_size=size,
        algorithm_id=algo_id
    )
    db.add(key_entry)
    db.commit()
    db.refresh(key_entry)
    return key_entry

def register_file(db: Session, name: str, path: str, size: int, algo_id: int, key_id: int, file_hash: str = None, status: str = "raw"):
    new_file = Files(
        name=name,
        storage_path=path,
        extension=name.split('.')[-1],
        file_size=size,
        file_hash=file_hash,
        status=status,
        algorithm_id=algo_id,
        key_id=key_id
    )
    db.add(new_file)
    db.commit()
    db.refresh(new_file)
    return new_file

def log_performance(db: Session, op: str, time_ms: float, mem_mb: float, fw_id: int, file_id: int):
    perf = Performance(
        operation=op,
        exec_time_ms=time_ms,
        mem_usage_mb=mem_mb,
        fw_id=fw_id,
        file_id=file_id,
       
        test_date=datetime.now(timezone.utc).replace(tzinfo=None)
    )
    db.add(perf)
    db.commit()
    db.refresh(perf)
    return perf


#read
def get_algorithms(db: Session):
    return db.query(Algorithms).all()

def get_key(db: Session, tag: str):
    return db.query(Keys).filter(Keys.tag == tag).first()

def get_file(db: Session, file_id: int):
    return db.query(Files).filter(Files.file_id == file_id).first()


def get_all_frameworks(db: Session):
    return db.query(Frameworks).all()

def get_all_keys(db: Session):
    return db.query(Keys).all()

def get_performance_logs(db: Session):
    return db.query(Performance).all()

def get_performance_comparison(db: Session, file_id: int):
    return db.query(Performance).filter(Performance.file_id == file_id).all()

def get_all_files(db: Session):
    return db.query(Files).all()


#update
# crud.py

#for raw to encrypted 
def update_file_status(db: Session, file_id: int, new_status: str, new_path: str = None):
    file_entry = db.query(Files).filter(Files.file_id == file_id).first()
    if file_entry:
        file_entry.status = new_status
        if new_path:
            file_entry.storage_path = new_path
        db.commit()
        db.refresh(file_entry)
    return file_entry

#delete

def delete_key(db: Session, key_id: int):
    key_entry = db.query(Keys).filter(Keys.key_id == key_id).first()
    if key_entry:
        db.delete(key_entry)
        db.commit()
        return True
    return False

def delete_file_record(db: Session, file_id: int):
    file_entry = db.query(Files).filter(Files.file_id == file_id).first()
    if file_entry:
        db.delete(file_entry)
        db.commit()
        return True
    return False