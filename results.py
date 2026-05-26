import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker
from models import Base, Performance, Files, Algorithms 

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

results = (
    session.query(
        Algorithms.name,
        Performance.operation,
        func.count(Performance.perform_id).label("total_ops"),
        func.sum(Performance.exec_time_ms).label("total_time"),
        func.sum(Files.file_size).label("total_bytes")
    )
    .join(Files, Performance.file_id == Files.file_id)
    .join(Algorithms, Files.algorithm_id == Algorithms.algorithm_id)
    .group_by(Algorithms.name, Performance.operation)
    .all()
)

print(f"{'Algoritm':<15} | {'Operație':<12} | {'Latență Medie':<15} | {'Medie Timp/Octet':<20}")
print("-" * 70)

for row in results:
    total_time = float(row.total_time) if row.total_time else 0.0
    total_bytes = float(row.total_bytes) if row.total_bytes else 0.0
    
    avg_latency = total_time / row.total_ops if row.total_ops else 0
    avg_per_byte = total_time / total_bytes if total_bytes else 0
    
    print(f"{row.name:<15} | {row.operation.value:<12} | {avg_latency:.4f} ms/op   | {avg_per_byte:.8f} ms/byte")
session.close()