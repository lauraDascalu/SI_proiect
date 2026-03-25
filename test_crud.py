from database import init_db, SessionLocal
import crud
import os


def run_db_tests():

    db = SessionLocal()

    print("\nSTART\n")


    try:
         #framework
        fw_name = "OpenSSL"
        fw = db.query(crud.Frameworks).filter_by(name=fw_name).first()
        if not fw:
            fw = crud.create_framework(db, fw_name, "3.0.8")
            print(f"CREATE framework: {fw.name}")
        else:
            print(f"READ framework existent: {fw.name}")

        # algoritm
        algo_name = "AES-256"
        algo = db.query(crud.Algorithms).filter_by(name=algo_name).first()
        if not algo:
            algo = crud.create_algorithm(db, algo_name, "symmetric", 256, "CBC")
            print(f"CREATE algoritm: {algo.name}")
        else:
            print(f"READ algoritm existent: {algo.name}")

        # key
        key_tag = f"key_{os.urandom(2).hex()}"
        key = crud.create_key(db, key_tag, os.urandom(32), 256, algo.algorithm_id)
        print(f"CREATE  cheie: {key.tag} (ID: {key.key_id})")

        # file
        myfile = crud.register_file(db, "test.txt", "./data/test.txt", 100, algo.algorithm_id, key.key_id, file_hash="hash")
        print(f"CREATE fisier: {myfile.name}, status: {myfile.status}")

        # update 
        updated_file = crud.update_file_status(db, myfile.file_id, "encrypted", "./data/test.txt.enc")
        print(f"UPDATE fisier ID {updated_file.file_id} este acum: {updated_file.status}")

        # performanta
        perf = crud.log_performance(db, "encryption", 5.23, 0.4, fw.fw_id, updated_file.file_id)
        print(f"CREATE performanta logata (ID: {perf.perform_id}): {perf.exec_time_ms}ms")

        # read
        algos = crud.get_algorithms(db)
        print(f"READ total algoritmi in lista: {len(algos)}")

        #delete
        nb = crud.get_all_files(db)
        print(f"READ nr total de fisiere in lista: {len(nb)}")
        booldel = crud.delete_file_record(db, 5)
        print(f"DELETE fisier: {booldel}")
        


    except Exception as e:
        print(f"\nEROARE test esuat: {e}")
        db.rollback()
    finally:
        db.close()
        print("\nFINISH\n")


if __name__ == "__main__":
    init_db()
    run_db_tests()