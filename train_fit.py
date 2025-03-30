import pandas as pd
from live_data_preprocess import LiveDataPreprocessor

# Original column names for the KDDTrain+.txt file
columns = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
    'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
    'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
    'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
    'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
    'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate', 'attack', 'level'
]

# Load your training data
train_df = pd.read_csv("./backend/model/KDDTrain+.txt", names=columns, header=None)

# Define live traffic columns
live_traffic_columns = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 
    'num_file_creations', 'num_access_files', 'count', 'srv_count', 
    'same_src_bytes_avg', 'same_src_bytes_var', 'error_rate', 'same_srv_rate', 
    'diff_srv_rate', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 
    'srv_rerror_rate', 'dst_host_count', 'dst_host_srv_count', 
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_serror_rate', 
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 
    'hot', 'num_failed_logins', 'logged_in'
]

# Filter live_traffic_columns to include only columns present in the training data
live_traffic_columns = [col for col in live_traffic_columns if col in columns]
print("Updated live traffic columns:", live_traffic_columns)

# Filter training data to include only live traffic columns
train_df_filtered = train_df[live_traffic_columns]

# Initialize the preprocessor
preprocessor = LiveDataPreprocessor()

# Fit the preprocessor on the filtered training data
preprocessor.fit(train_df_filtered)

# Save the preprocessor components for later use
preprocessor.save_components("./backend/model")

print("Preprocessor fitted and components saved successfully!")