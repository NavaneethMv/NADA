#!/home/$(whoami)/NADA/.venv/bin/python

import pandas as pd
import time
import os
import json
from datetime import datetime
from live_data_preprocess import LiveDataPreprocessor
from backend.network.parse_main import NetworkFeatureExtractor
from backend.model.model_arc import NetworkArchitecture
from backend.model.training import ModelTrainer

class LiveDataCollector:
    def __init__(self, output_dir="live_training_data", capture_duration=3600):
        self.output_dir = output_dir
        self.capture_duration = capture_duration
        self.extractor = NetworkFeatureExtractor(time_window=2, batch_size=10)
        self.preprocessor = LiveDataPreprocessor(load_from_file=False)
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Define only the 34 features we can actually collect from live traffic
        self.feature_columns = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
            'dst_bytes', 'num_compromised', 'root_shell', 'su_attempted',
            'num_root', 'num_file_creations', 'num_access_files', 'count',
            'srv_count', 'same_src_bytes_avg', 'same_src_bytes_var',
            'error_rate', 'same_srv_rate', 'diff_srv_rate', 'serror_rate',
            'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
            'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
            'dst_host_diff_srv_rate', 'dst_host_serror_rate',
            'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
            'dst_host_srv_rerror_rate', 'hot', 'num_failed_logins', 'logged_in'
        ]
        
        # Initialize empty DataFrame with these columns
        self.live_dataset = pd.DataFrame(columns=self.feature_columns)
        
        # Will store our class mapping
        self.class_mapping = {
            'normal': 0,
            'dos': 1,
            'probe': 2,
            'u2r': 3,
            'r2l': 4
        }
        
    def start_capture(self, interface="s1-eth3"):
        """Start capturing live traffic and building dataset"""
        print(f"Starting live traffic capture for {self.capture_duration} seconds...")
        self.extractor.start_capture(interface=interface, continuous=True)
        
        start_time = time.time()
        while time.time() - start_time < self.capture_duration:
            # Get batch of features from live traffic
            df_batch = self.extractor.get_features_batch(timeout=1.0)
            
            if df_batch is not None and not df_batch.empty:
                # Ensure we only keep the 34 features we can collect
                df_batch = df_batch[[col for col in self.feature_columns if col in df_batch.columns]]
                
                # Add missing columns with default values
                for col in self.feature_columns:
                    if col not in df_batch.columns:
                        if col in ['hot', 'num_failed_logins', 'logged_in', 'num_compromised',
                                 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
                                 'num_access_files']:
                            df_batch[col] = 0  # Default for integer features
                        else:
                            df_batch[col] = 0.0  # Default for float features
                
                # Append to our live dataset
                self.live_dataset = pd.concat([self.live_dataset, df_batch], ignore_index=True)
                
                print(f"Collected {len(self.live_dataset)} samples so far...")
        
        # Stop capture when duration is reached
        self.extractor.stop()
        print(f"Capture completed. Collected {len(self.live_dataset)} total samples.")
        
        # Save the raw captured data
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        raw_file = os.path.join(self.output_dir, f"live_capture_{timestamp}.csv")
        self.live_dataset.to_csv(raw_file, index=False)
        
        return self.live_dataset
    
    def label_anomalies(self, df):
        """
        Label anomalies in the captured data based on heuristic rules
        Returns DataFrame with 'attack' and 'attack_class' columns added
        """
        print("Labeling anomalies in captured data...")
        
        # Initialize all as normal
        df['attack'] = 'normal'
        df['attack_class'] = self.class_mapping['normal']
        
        # Define heuristic rules for labeling anomalies
        # Rule 1: High packet rate (SYN flood) - DOS
        syn_flood_mask = (df['protocol_type'] == 'tcp') & (df['flag'].isin(['S0', 'SF'])) & (df['src_bytes'] > 1000)
        df.loc[syn_flood_mask, 'attack'] = 'dos'
        df.loc[syn_flood_mask, 'attack_class'] = self.class_mapping['dos']
        
        # Rule 2: UDP flood - DOS
        udp_flood_mask = (df['protocol_type'] == 'udp') & (df['dst_bytes'] > 1000)
        df.loc[udp_flood_mask, 'attack'] = 'dos'
        df.loc[udp_flood_mask, 'attack_class'] = self.class_mapping['dos']
        
        # Rule 3: High error rate - Probe
        high_error_mask = (df['serror_rate'] > 0.5) | (df['rerror_rate'] > 0.5)
        df.loc[high_error_mask, 'attack'] = 'probe'
        df.loc[high_error_mask, 'attack_class'] = self.class_mapping['probe']
        
        # Rule 4: Suspicious payload (root commands) - U2R
        suspicious_payload_mask = (df['num_compromised'] > 0) | (df['root_shell'] == 1) | (df['su_attempted'] == 1)
        df.loc[suspicious_payload_mask, 'attack'] = 'u2r'
        df.loc[suspicious_payload_mask, 'attack_class'] = self.class_mapping['u2r']
        
        # Rule 5: Multiple failed logins - R2L
        failed_logins_mask = df['num_failed_logins'] > 3
        df.loc[failed_logins_mask, 'attack'] = 'r2l'
        df.loc[failed_logins_mask, 'attack_class'] = self.class_mapping['r2l']
        
        print(f"Labeled {len(df[df['attack'] != 'normal'])} anomalies out of {len(df)} total samples")
        
        return df
    
    def preprocess_and_save(self, df):
        """Preprocess the live dataset and save in training format"""
        print("Preprocessing live dataset...")
        
        # Fit the preprocessor on our live data
        self.preprocessor.fit(df[self.feature_columns])
        
        # Save preprocessing components
        self.preprocessor.save_components("./backend/model")
        
        # Save class mapping
        with open('./backend/model/class_mapping.json', 'w') as f:
            json.dump(self.class_mapping, f)
        
        # Process the data (this will encode categoricals, scale features, etc.)
        X = df[self.feature_columns]
        y = df['attack_class']
        
        # Split into train and test (80/20)
        from sklearn.model_selection import train_test_split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Save the processed datasets
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        train_file = os.path.join(self.output_dir, f"live_train_{timestamp}.csv")
        test_file = os.path.join(self.output_dir, f"live_test_{timestamp}.csv")
        
        # Combine features and labels for saving
        train_df = pd.concat([X_train, y_train], axis=1)
        test_df = pd.concat([X_test, y_test], axis=1)
        
        train_df.to_csv(train_file, index=False)
        test_df.to_csv(test_file, index=False)
        
        print(f"Saved preprocessed training data to {train_file}")
        print(f"Saved preprocessed test data to {test_file}")
        
        return X_train, X_test, y_train, y_test
    
    def train_model(self, X_train, y_train, X_test, y_test):
        """Train a new model on the live dataset"""
        print("Training new model on live data...")
        
        # Build the model
        input_shape = (X_train.shape[1],)
        num_classes = len(self.class_mapping)
        model = NetworkArchitecture.build_cnn_model(input_shape, num_classes)
        
        # Train the model
        trainer = ModelTrainer(model)
        history = trainer.train(X_train, y_train, X_test, y_test)
        
        # Evaluate
        trainer.evaluate(X_test, y_test)
        trainer.plot_training_history()
        
        # Save the model weights and class mapping
        model.save_weights('live_trained_weights.h5')
        print("Saved model weights to live_trained_weights.h5")
        
        with open('class_mapping.json', 'w') as f:
            json.dump(self.class_mapping, f)
        print("Saved class mapping to class_mapping.json")
        
        return model, history

def main():
    # Initialize collector - capture for 1 hour (3600 seconds)
    collector = LiveDataCollector(capture_duration=3600)
    
    # Step 1: Capture live traffic and build dataset
    live_df = collector.start_capture(interface="s1-eth3")
    
    # Step 2: Label anomalies (using heuristics)
    labeled_df = collector.label_anomalies(live_df)
    
    # Step 3: Preprocess and save dataset
    X_train, X_test, y_train, y_test = collector.preprocess_and_save(labeled_df)
    
    # Step 4: Train new model on live data
    model, history = collector.train_model(X_train, y_train, X_test, y_test)
    
    print("Live data collection and model training completed successfully!")

if __name__ == "__main__":
    main()