import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker
from models import Performance, Files, Algorithms, Frameworks

# Încărcare configurație din .env
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

# Query: Grupare după Framework, Algoritm și Operație
results = (
    session.query(
        Frameworks.name.label("fw_name"),
        Algorithms.name.label("algo_name"),
        Performance.operation.label("op_type"),
        func.count(Performance.perform_id).label("total_ops"),
        func.sum(Performance.exec_time_ms).label("total_time"),
        func.sum(Files.file_size).label("total_bytes")
    )
    .join(Files, Performance.file_id == Files.file_id)
    .join(Algorithms, Files.algorithm_id == Algorithms.algorithm_id)
    .join(Frameworks, Performance.fw_id == Frameworks.fw_id)
    .group_by(Frameworks.name, Algorithms.name, Performance.operation)
    .all()
)

print(f"{'Framework':<15} | {'Algoritm':<12} | {'Operație':<12} | {'Latență Medie':<15} | {'Medie Timp/Octet'}")
print("-" * 85)

for row in results:
    # Evitare erori de tip Decimal/Float
    total_time = float(row.total_time) if row.total_time else 0.0
    total_bytes = float(row.total_bytes) if row.total_bytes else 0.0
    
    avg_latency = total_time / row.total_ops if row.total_ops else 0.0
    avg_per_byte = total_time / total_bytes if total_bytes else 0.0
    
    # Afișare curată a valorii din Enum
    op_str = row.op_type.value if hasattr(row.op_type, 'value') else str(row.op_type)
    
    print(f"{row.fw_name:<15} | {row.algo_name:<12} | {op_str:<12} | {avg_latency:.4f} ms/op   | {avg_per_byte:.8f} ms/byte")

session.close()