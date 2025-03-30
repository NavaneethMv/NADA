import pandas as pd
import numpy as np
import joblib
from sklearn.preprocessing import StandardScaler, LabelEncoder


class LiveDataPreprocessor:
    def __init__(self, load_from_file=False, components_path=None):
        """
        Initialize the preprocessor for live data.

        Args:
            load_from_file: Whether to load pre-trained components
            components_path: Path to the directory with saved components
        """
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.train_median_values = {}  # Initialize as an empty dictionary
        self.train_mode_values = {}  # Initialize as an empty dictionary

        if load_from_file and components_path:
            self.load_components(components_path)

    def load_components(self, path):
        """Load pre-trained preprocessing components"""
        try:
            self.scaler = joblib.load(f"{path}/scaler.pkl")
            self.label_encoders = joblib.load(f"{path}/label_encoders.pkl")
            self.train_median_values = joblib.load(f"{path}/train_median_values.pkl")
            self.train_mode_values = joblib.load(f"{path}/train_mode_values.pkl")
            print("Successfully loaded preprocessing components")
        except Exception as e:
            print(f"Error loading components: {e}")

    def save_components(self, path):
        """Save preprocessing components for future use"""
        try:
            joblib.dump(self.scaler, f"{path}/scaler.pkl")
            joblib.dump(self.label_encoders, f"{path}/label_encoders.pkl")
            joblib.dump(self.train_median_values, f"{path}/train_median_values.pkl")
            joblib.dump(self.train_mode_values, f"{path}/train_mode_values.pkl")
            print("Successfully saved preprocessing components")
        except Exception as e:
            print(f"Error saving components: {e}")

    def fit(self, df):
        print("Fitting preprocessing components...")

        # Store median and mode values for missing value handling
        self.train_median_values = (
            df.select_dtypes(include=[np.number]).median().to_dict()
        )
        self.train_mode_values = (
            df.select_dtypes(include=["object"]).mode().iloc[0].to_dict()
        )

        # Define all possible categories for each categorical feature
        all_categories = {
            "protocol_type": ["tcp", "udp", "icmp", "unknown"],  # Add 'unknown'
            "service": ["http", "https", "ssh", "ftp", "smtp", "other", "unknown"],  # Add 'unknown' and 'other'
            "flag": ["SF", "S0", "S1", "REJ", "RSTO", "A", "PA", "FA", "RA", "AP", "unknown"],  # Add 'unknown'
        }

        # Handle categorical columns
        categorical_columns = ["protocol_type", "service", "flag"]
        for column in categorical_columns:
            if column in df.columns:
                # Initialize and fit a new label encoder for this column
                le = LabelEncoder()
                # Fit on all possible categories (including 'unknown')
                le.fit(all_categories[column])
                self.label_encoders[column] = le

        # Fit scaler on numerical columns
        numeric_columns = df.select_dtypes(include=[np.number]).columns
        self.scaler.fit(df[numeric_columns])

        print("Preprocessing components fitted successfully")

    def transform(self, df):
        """
        Transform live data using fitted components.
        Raises an error if an unseen category is encountered.
        """
        print("Transform method called")  # Debug statement
        # Create a copy to avoid modifying the original
        df_processed = df.copy()

        print("Input data columns:", df_processed.columns)
        print("Input data unique values in categorical columns:")
        for col in ["protocol_type", "service", "flag"]:
            if col in df_processed.columns:
                print(f"{col}: {df_processed[col].unique()}")

        # 1. Handle missing values
        self._handle_missing_values(df_processed)

        # 2. Encode categorical columns
        self._encode_categorical_columns(df_processed)

        # 3. Scale numerical features
        self._scale_features(df_processed)

        print("Processed data columns:", df_processed.columns)
        print("Processed data unique values in categorical columns:")
        for col in ["protocol_type", "service", "flag"]:
            if col in df_processed.columns:
                print(f"{col}: {df_processed[col].unique()}")

        return df_processed

    def _handle_missing_values(self, df):
        """Handle missing values in the data"""
        # For numerical columns, fill NaN with median (from training data)
        numeric_columns = df.select_dtypes(include=[np.number]).columns
        for col in numeric_columns:
            df[col].fillna(self.train_median_values.get(col, 0), inplace=True)

        # For categorical columns, fill NaN with mode (from training data)
        categorical_columns = df.select_dtypes(include=["object"]).columns
        for col in categorical_columns:
            df[col].fillna(
                self.train_mode_values.get(col, df[col].mode()[0]), inplace=True
        )

    def _encode_categorical_columns(self, df):
        """Encode categorical columns using pre-fitted LabelEncoders"""
        categorical_columns = ["protocol_type", "service", "flag"]

        for column in categorical_columns:
            if column in df.columns and column in self.label_encoders:
                # Handle values not seen during training
                df[column] = df[column].astype(str)
                df[column] = df[column].apply(
                    lambda x: x if x in self.label_encoders[column].classes_ else 'unknown'
                )
                
                # Transform known values, use fallback for unknown
                known_mask = df[column].isin(self.label_encoders[column].classes_)
                df.loc[known_mask, column] = self.label_encoders[column].transform(df.loc[known_mask, column])
                df.loc[~known_mask, column] = self.label_encoders[column].transform(['unknown'])[0]

    def _scale_features(self, df):
        """Scale numerical features using the pre-fitted scaler"""
        numeric_columns = df.select_dtypes(include=[np.number]).columns

        if len(numeric_columns) > 0:
            # Handle any remaining NaN values (shouldn't be any after missing value handling)
            df[numeric_columns] = df[numeric_columns].fillna(0)

            # Apply scaling
            df[numeric_columns] = self.scaler.transform(df[numeric_columns])

    def prepare_for_cnn(self, df):
        """
        Prepare data specifically for CNN input format
        """
        # First apply standard preprocessing
        df_processed = self.transform(df)

        # Convert to numpy array
        X = df_processed.values

        # Reshape based on your CNN architecture needs
        n_samples = X.shape[0]
        n_features = X.shape[1]

        # For 1D CNN (adjust as needed for your model)
        X_reshaped = X.reshape(n_samples, n_features, 1)

        return X_reshaped