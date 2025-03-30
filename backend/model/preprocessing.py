import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from imblearn.over_sampling import SMOTE
from collections import Counter
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import os

class DataPreprocessor:
    def __init__(self, train_df, test_df):
        self.train_df = train_df.copy() 
        self.test_df = test_df.copy()
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.train_median_values = {}  # Store median values for numerical features
        self.train_mode_values = {}   # Store mode values for categorical features

    def save_components(self, path):
        """
        Save preprocessing components (e.g., scaler, label encoders) to disk.
        
        Args:
            path: Directory where components will be saved.
        """
        # Create the directory if it doesn't exist
        os.makedirs(path, exist_ok=True)

        # Save the scaler
        joblib.dump(self.scaler, f"{path}/scaler.pkl")

        # Save the label encoders
        joblib.dump(self.label_encoders, f"{path}/label_encoders.pkl")

        # Save median and mode values for imputation
        joblib.dump(self.train_median_values, f"{path}/train_median_values.pkl")
        joblib.dump(self.train_mode_values, f"{path}/train_mode_values.pkl")

        print(f"Preprocessing components saved to {path}")


    def handle_missing_values(self):
        """Handle missing values in both training and test data"""
        # Check for and report missing values
        train_nulls = self.train_df.isnull().sum()
        test_nulls = self.test_df.isnull().sum()

        print("Missing values in training data:")
        print(train_nulls[train_nulls > 0])
        print("\nMissing values in test data:")
        print(test_nulls[test_nulls > 0])

        # For numerical columns, fill NaN with median
        numeric_columns = self.train_df.select_dtypes(include=[np.number]).columns
        for col in numeric_columns:
            median_value = self.train_df[col].median()
            self.train_median_values[col] = median_value  # Store median value
            self.train_df[col].fillna(median_value, inplace=True)
            self.test_df[col].fillna(median_value, inplace=True)

        # For categorical columns, fill NaN with mode
        categorical_columns = self.train_df.select_dtypes(include=['object']).columns
        for col in categorical_columns:
            mode_value = self.train_df[col].mode()[0]
            self.train_mode_values[col] = mode_value  # Store mode value
            self.train_df[col].fillna(mode_value, inplace=True)
            self.test_df[col].fillna(mode_value, inplace=True)
            
    def remove_unnecessary_columns(self):
        """Remove columns that aren't needed for training"""
        columns_to_drop = ['attack', 'level', 'attack_flag']
        self.train_df = self.train_df.drop(columns=columns_to_drop, errors='ignore')
        self.test_df = self.test_df.drop(columns=columns_to_drop, errors='ignore')
        
    def encode_categorical_columns(self):
        """Encode categorical columns using LabelEncoder"""
        categorical_columns = ['protocol_type', 'service', 'flag']
        
        for column in categorical_columns:
            if column not in self.train_df.columns or column not in self.test_df.columns:
                print(f"Warning: Column {column} not found in dataset")
                continue
                
            # Initialize a new label encoder for this column
            le = LabelEncoder()
            # Fit on both train and test to ensure all categories are covered
            combined_values = pd.concat([self.train_df[column], self.test_df[column]]).unique()
            le.fit(combined_values)
            
            # Transform the data
            self.train_df[column] = le.transform(self.train_df[column])
            self.test_df[column] = le.transform(self.test_df[column])
            
            # Store the encoder
            self.label_encoders[column] = le
            
        print("Categorical columns encoded successfully")
        
    def split_features_target(self):
        """Split data into features and target"""
        if 'attack_class' not in self.train_df.columns or 'attack_class' not in self.test_df.columns:
            raise ValueError("'attack_class' column not found in dataset")
            
        self.X_train = self.train_df.drop('attack_class', axis=1)
        self.y_train = self.train_df['attack_class']
        self.X_test = self.test_df.drop('attack_class', axis=1)
        self.y_test = self.test_df['attack_class']
        
        # Verify no NaN values in target
        if self.y_train.isnull().any() or self.y_test.isnull().any():
            raise ValueError("NaN values found in target variable 'attack_class'")
        
    def scale_features(self):
        """Scale the features using StandardScaler"""
        # Convert to float type before scaling
        self.X_train = self.X_train.astype(float)
        self.X_test = self.X_test.astype(float)
        
        # Check for and handle any remaining NaN values
        if np.any(np.isnan(self.X_train)) or np.any(np.isnan(self.X_test)):
            print("Warning: NaN values found in features after type conversion")
            self.X_train = np.nan_to_num(self.X_train, nan=0.0)
            self.X_test = np.nan_to_num(self.X_test, nan=0.0)
        
        self.X_train = self.scaler.fit_transform(self.X_train)
        self.X_test = self.scaler.transform(self.X_test)
        
    def apply_smote(self):
        """Apply SMOTE to handle class imbalance"""
        print("Class distribution before SMOTE:")
        print(Counter(self.y_train))
        
        smote = SMOTE(sampling_strategy='auto', random_state=42)
        self.X_train, self.y_train = smote.fit_resample(self.X_train, self.y_train)
        
        print("\nClass distribution after SMOTE:")
        print(Counter(self.y_train))
        
    def process(self):
        """Execute all preprocessing steps"""
        print("Starting preprocessing...")
        
        print("1. Handling missing values...")
        self.handle_missing_values()
        
        print("2. Removing unnecessary columns...")
        self.remove_unnecessary_columns()
        
        print("3. Encoding categorical columns...")
        self.encode_categorical_columns()
        
        print("4. Splitting features and target...")
        self.split_features_target()
        
        print("5. Scaling features...")
        self.scale_features()
        
        print("6. Applying SMOTE...")
        self.apply_smote()
        
        print("7. Creating train/validation split...")
        X_train, X_val, y_train, y_val = train_test_split(
            self.X_train, self.y_train, 
            test_size=0.2, 
            random_state=42, 
            stratify=self.y_train
        )
        
        # Final verification of no NaN values
        datasets = {
            'X_train': X_train, 'X_val': X_val, 'y_train': y_train, 
            'y_val': y_val, 'X_test': self.X_test, 'y_test': self.y_test
        }
        for name, data in datasets.items():
            if isinstance(data, np.ndarray) and np.any(np.isnan(data)):
                raise ValueError(f"NaN values found in {name} after preprocessing")
        
        print("Preprocessing completed successfully!")
        return X_train, X_val, y_train, y_val, self.X_test, self.y_test