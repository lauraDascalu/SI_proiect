import streamlit as st
import crud
from database import SessionLocal
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from services import process_file

def handle_key_generation():
    st.session_state.new_key_check = False
    del st.session_state.key_success

st.set_page_config(page_title="Secure your files", layout="wide")
st.title("Local key management system")

st.markdown("""
    <style>
    
    .stTable table {
        border: 3px solid #808080;
        border-collapse: collapse;
    }
    .stTable th, .stTable td {
        border: 2px solid #808080 ; 
        padding: 10px ;
    }
    
    </style>
    """, unsafe_allow_html=True)


db = SessionLocal()

if "key_generated_success" in st.session_state and st.session_state.key_generated_success:
    st.session_state.new_key_check = False  
    if "last_msg" in st.session_state:
        st.success(st.session_state.last_msg)
    del st.session_state.key_generated_success


col1, col2 = st.columns(2)

with col1:
    st.subheader("Configure")

    algos = crud.get_algorithms(db)
    algo_options = {a.name: a for a in algos}
    selected_algo_name = st.selectbox("Select algorithm", list(algo_options.keys()))
    selected_algo = algo_options[selected_algo_name]

    keys = crud.get_all_keys(db)
    key_tags = {k.tag: k for k in keys if k.algorithm_id == selected_algo.algorithm_id}
    
    selected_key = None

    
    if st.checkbox("New key?", key="new_key_check"):
        new_tag = st.text_input("New key tag")

        if st.button("Generate key"):
            if not new_tag:
                st.error("Please enter a name tag for the key.")
            else:
                try:
                    if "RSA" in selected_algo.name.upper():

                        k_size = 2048

                        private_key = rsa.generate_private_key(
                            public_exponent=65537,
                            key_size=k_size
                        )
                        
                        private_bytes = private_key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=serialization.NoEncryption()
                        )
                        public_bytes = private_key.public_key().public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        )
                        crud.create_key(db, 
                                        tag=new_tag, 
                                        private_b=private_bytes, 
                                        size=k_size, 
                                        algo_id=selected_algo.algorithm_id, 
                                        public_b=public_bytes)
                        
                        
                    else:
                        new_key_bytes = os.urandom(selected_algo.key_size_default // 8)
                        crud.create_key(db, new_tag, new_key_bytes, selected_algo.key_size_default, selected_algo.algorithm_id)
                    
                    st.session_state.key_generated_success = True
                    st.session_state.key_success_msg = f"Key '{new_tag}' generated successfully!"
                    st.rerun()
                    
                    

                except Exception as e:
                    st.error(f"Failed to generate key: {e}")
                
                
    if not st.session_state.get("new_key_check", False):
        if key_tags:
            selected_key_tag = st.selectbox("Select key", list(key_tags.keys()))
            selected_key = key_tags.get(selected_key_tag)
        else:
            st.warning("No keys available for this algorithm. Create one!")

with col2:
    st.subheader("File")
    uploaded_file = st.file_uploader("Load file to encrypt")
    
    fws = crud.get_all_frameworks(db)
    fw_options = {f.name: f.fw_id for f in fws}
    selected_fw_name = st.selectbox("Select Framework", list(fw_options.keys())) if fw_options else None
    selected_fw_id = fw_options[selected_fw_name] if selected_fw_name else 1

    if uploaded_file and selected_key:
        if st.button("Encrypt file"):

            if "RSA" in selected_algo.name.upper():
               
                max_rsa_bytes = (selected_key.key_size // 8) - 66
                if uploaded_file.size > max_rsa_bytes:
                    st.error(f" RSA Error: File too big ({uploaded_file.size} bytes). "
                             f"RSA-2048 suports max {max_rsa_bytes} bytes. "
                             "Try a small .txt file.")
                    st.stop()

            temp_path = f"./data/{uploaded_file.name}"
            os.makedirs("./data", exist_ok=True)
           
            file_bytes = uploaded_file.read()
            with open(temp_path, "wb") as f:
                f.write(file_bytes)
            
            try:
                file_rec = crud.register_file(
                    db, 
                    name=uploaded_file.name, 
                    path=temp_path, 
                    size=len(file_bytes), 
                    algo_id=selected_algo.algorithm_id, 
                    key_id=selected_key.key_id
                )

                
                enc_path = process_file(db, file_rec.file_id, framework_id=selected_fw_id, mode = "encrypt")
                
                st.success(f"Successfully encrypted: {os.path.basename(enc_path)}")
                
                with open(enc_path, "rb") as ef:
                    st.download_button(
                        label="Download encrypted file",
                        data=ef,
                        file_name=os.path.basename(enc_path)
                    )
            except Exception as e:
                st.error(f"Error during processing: {e}")

st.divider()
st.subheader("File history")
files = crud.get_all_files(db) 
action_options = {}

if files:

    history_data = []
    

    for f in files:
        algo = crud.get_algorithm_by_id(db, f.algorithm_id)
        status_val = f.status.value if hasattr(f.status, 'value') else str(f.status)

        history_data.append({
            "ID": f.file_id,
            "Name": f.name, 
            "Status": f.status.value, 
            "Algorithm": algo.name if algo else "N/A",
            "Size": f.file_size,
            "Path": f.storage_path
        })

        action_options[f"{f.name} ( ID: {f.file_id} - {status_val} )"] = f
    
    if history_data:
       
        st.table(history_data)
    else:
        st.info("No files in history yet.")


    if action_options:

        st.divider()
        st.write("### Actions")
       
        selected_file_name = st.selectbox("Select a file from history to act upon:", list(action_options.keys()))
        target_file = action_options[selected_file_name]

        
        if target_file.status.value == "encrypted":
            if st.button("Decrypt selected file"):
                try:
                    process_file(db, target_file.file_id, framework_id=selected_fw_id, mode="decrypt")
                    st.success("File decrypted!")
                    st.rerun()
                except Exception as e:
                    st.error(f"Decryption error: {e}")

        
        elif target_file.status.value == "decrypted":
            if os.path.exists(target_file.storage_path):
                with open(target_file.storage_path, "rb") as f_to_download:
                    st.download_button(
                        label="Download file",
                        data=f_to_download,
                        file_name=os.path.basename(target_file.storage_path),
                        mime="application/octet-stream"
                    )
            else:
                st.error("File not found on disk.")
else:
    st.info("No files in database.")

db.close()