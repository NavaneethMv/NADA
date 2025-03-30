
import numpy as np
import pandas as pd
from preprocessing import DataPreprocessor
from model_arc import NetworkArchitecture
from training import ModelTrainer

def load_data(train_path, test_path):
    """Load and prepare the NSL-KDD dataset"""
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
    
    
    df_train = pd.read_csv(train_path, names=columns)
    df_test = pd.read_csv(test_path, names=columns)
    
    
    df_train['attack_flag'] = df_train.attack.map(lambda a: 0 if a == 'normal' else 1)
    df_test['attack_flag'] = df_test.attack.map(lambda a: 0 if a == 'normal' else 1)
    
    
    attack_mapping = {
        'normal': 0,
        
        'apache2': 1, 'back': 1, 'land': 1, 'neptune': 1, 'mailbomb': 1,
        'pod': 1, 'processtable': 1, 'smurf': 1, 'teardrop': 1, 'udpstorm': 1,
        'worm': 1,
        
        'ipsweep': 2, 'mscan': 2, 'nmap': 2, 'portsweep': 2, 'saint': 2,
        'satan': 2,
        
        'buffer_overflow': 3, 'loadmodule': 3, 'perl': 3, 'ps': 3, 'rootkit': 3,
        'sqlattack': 3, 'xterm': 3,
        
        'ftp_write': 4, 'guess_passwd': 4, 'http_tunnel': 4, 'imap': 4,
        'multihop': 4, 'named': 4, 'phf': 4, 'sendmail': 4, 'snmpgetattack': 4,
        'snmpguess': 4, 'spy': 4, 'warezclient': 4, 'warezmaster': 4,
        'xclock': 4, 'xsnoop': 4
    }
    
    df_train['attack_class'] = df_train['attack'].map(attack_mapping)
    df_test['attack_class'] = df_test['attack'].map(attack_mapping)
    
    return df_train, df_test

def main():
    try:
        df_train, df_test = load_data('KDDTrain+.txt', 'KDDTest+.txt')
    except FileNotFoundError:
        print("Train and Test dataset not found!")
        return
    
    
    preprocessor = DataPreprocessor(df_train, df_test)
    
    
    X_train, X_val, y_train, y_val, X_test, y_test = preprocessor.process()
    preprocessing_components_path = "."
    preprocessor.save_components(preprocessing_components_path)
    print("saved the label encoder and data preprocessing")
    
    num_classes = len(np.unique(y_train))
    input_shape = (X_train.shape[1],)
    model = NetworkArchitecture.build_cnn_model(input_shape, num_classes)
    
    
    trainer = ModelTrainer(model)
    
    
    history = trainer.train(X_train, y_train, X_val, y_val)
    
    
    trainer.evaluate(X_test, y_test)
    trainer.plot_training_history()
    
    return model, history

if __name__ == "__main__":
    model, history = main()