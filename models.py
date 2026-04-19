import enum
from datetime import datetime
from typing import List, Optional
from sqlalchemy import ForeignKey, String, Float, LargeBinary, Integer, Enum
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

class AlgType(enum.Enum):
    symmetric = "symmetric"
    asymmetric = "asymmetric"

class StatusType(enum.Enum):
    raw = "raw"
    encrypted = "encrypted"
    decrypted = "decrypted"

class OperationType(enum.Enum):
    encryption = "encryption"
    decryption = "decryption"

class Base(DeclarativeBase):
    pass

class Algorithms(Base):
    __tablename__ = "algorithms"
    
    algorithm_id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(50))      
    type: Mapped[AlgType] = mapped_column(Enum(AlgType), nullable=False)      # symmetric, asymmetric
    operation_mode: Mapped[Optional[str]] = mapped_column(String(20)) 
    key_size_default: Mapped[int] = mapped_column(Integer)

    keys: Mapped[List["Keys"]] = relationship(back_populates="algorithm")

class Keys(Base):
    __tablename__ = "keys"
    
    key_id: Mapped[int] = mapped_column(primary_key=True)
    tag: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)
    key_private: Mapped[bytes] = mapped_column(LargeBinary)
    key_public: Mapped[Optional[bytes]] = mapped_column(LargeBinary)
    key_size: Mapped[int] = mapped_column(Integer)
    
    algorithm_id: Mapped[int] = mapped_column(ForeignKey("algorithms.algorithm_id"))
    algorithm: Mapped["Algorithms"] = relationship(back_populates="keys")

class Frameworks(Base):
    __tablename__ = "frameworks"
    
    fw_id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(50))      
    lib_version: Mapped[str] = mapped_column(String(20))

class Files(Base):
    __tablename__ = "files"
    
    file_id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    storage_path: Mapped[str] = mapped_column(String(500))
    extension: Mapped[str] = mapped_column(String(10))
    file_size: Mapped[int] = mapped_column(Integer)
    file_hash: Mapped[Optional[str]] = mapped_column(String(64))
    status: Mapped[StatusType] = mapped_column(Enum(StatusType), default=StatusType.raw)    # raw, encrypted, decrypted
    algorithm_id: Mapped[int] = mapped_column(ForeignKey("algorithms.algorithm_id"))
    key_id: Mapped[int] = mapped_column(ForeignKey("keys.key_id"))

class Performance(Base):
    __tablename__ = "performances"
    
    perform_id: Mapped[int] = mapped_column(primary_key=True)
    operation: Mapped[OperationType] = mapped_column(Enum(OperationType), nullable=False) # encryption, decryption
    exec_time_ms: Mapped[float] = mapped_column(Float)
    mem_usage_mb: Mapped[float] = mapped_column(Float)
    test_date: Mapped[datetime] = mapped_column(default=datetime.utcnow)
    
    fw_id: Mapped[int] = mapped_column(ForeignKey("frameworks.fw_id"))
    file_id: Mapped[int] = mapped_column(ForeignKey("files.file_id"))