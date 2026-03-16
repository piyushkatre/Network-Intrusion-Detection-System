import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import joblib
import os

class DataPreprocessor:
    def __init__(self, csv_path):
        self.csv_path = csv_path
        self.data = None
        self.X_train = None
        self.X_test = None
        self.X_val = None
        self.y_train = None
        self.y_test = None
        self.y_val = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_columns = None
        
    def load_data(self):
        print(f"Loading data from {self.csv_path}...")
        self.data = pd.read_csv(self.csv_path)
        print(f"Dataset shape: {self.data.shape}")
        print(f"First few rows:\n{self.data.head()}")
        return self.data
    
    def handle_missing_values(self):
        print("\nHandling missing values...")
        initial_rows = len(self.data)
        self.data = self.data.dropna()
        print(f"Rows removed (NaN): {initial_rows - len(self.data)}")
        
        self.data = self.data.replace([np.inf, -np.inf], np.nan)
        
        numeric_columns = self.data.select_dtypes(include=[np.number]).columns
        self.data[numeric_columns] = self.data[numeric_columns].fillna(
            self.data[numeric_columns].median()
        )
        
        print(f"Rows after handling infinity: {len(self.data)}")
        return self.data
    
    def select_features(self):
        print("\nPerforming feature selection...")
        
        target_col = None
        label_candidates = ['Label', 'label', 'Class', 'class', 'Attack', 'attack']
        
        for col in label_candidates:
            if col in self.data.columns:
                target_col = col
                break
        
        if target_col is None:
            target_col = self.data.columns[-1]
        
        print(f"Target column: {target_col}")
        
        # Separate features and target
        self.y = self.data[target_col]
        self.X = self.data.drop(columns=[target_col])
        
        # Keep only numeric features
        numeric_features = self.X.select_dtypes(include=[np.number]).columns.tolist()
        self.X = self.X[numeric_features]
        
        self.feature_columns = numeric_features
        print(f"Selected {len(numeric_features)} numeric features")
        print(f"Features: {numeric_features[:10]}...")  # Show first 10
        
        return self.X, self.y
    
    def extract_statistical_features(self):
        print("\nExtracting statistical features...")
        
        if len(self.X.columns) > 0:
            self.X['feature_mean'] = self.X.mean(axis=1)
            self.X['feature_std'] = self.X.std(axis=1)
            self.X['feature_max'] = self.X.max(axis=1)
            self.X['feature_min'] = self.X.min(axis=1)
            
            print(f"Extracted 4 statistical features")
            print(f"Total features now: {self.X.shape[1]}")
        
        return self.X
    
    def encode_target(self):
        print("\nEncoding target variable...")
        
        if self.y.dtype == 'object':
            self.y = self.label_encoder.fit_transform(self.y)
            print(f"Classes: {self.label_encoder.classes_}")
        
        print(f"Target value counts:\n{pd.Series(self.y).value_counts()}")
        return self.y
    
    def normalize_features(self):
        print("\nNormalizing features...")
        
        self.X = self.X.replace([np.inf, -np.inf], np.nan)
        self.X = self.X.fillna(self.X.median())
        
        self.X = self.scaler.fit_transform(self.X)
        
        all_features = list(self.feature_columns) + ['feature_mean', 'feature_std', 'feature_max', 'feature_min']
        self.feature_columns = all_features
        
        self.X = pd.DataFrame(self.X, columns=all_features)
        return self.X
    
    def split_dataset(self, test_size=0.2, val_size=0.1):
        print(f"\nSplitting dataset (test={test_size}, val={val_size})...")
        
        X_temp, self.X_test, y_temp, self.y_test = train_test_split(
            self.X, self.y, test_size=test_size, random_state=42, stratify=self.y
        )
        
        val_ratio = val_size / (1 - test_size)
        self.X_train, self.X_val, self.y_train, self.y_val = train_test_split(
            X_temp, y_temp, test_size=val_ratio, random_state=42, stratify=y_temp
        )
        
        print(f"Training set: {self.X_train.shape}")
        print(f"Validation set: {self.X_val.shape}")
        print(f"Test set: {self.X_test.shape}")
        
        return (self.X_train, self.X_val, self.X_test, 
                self.y_train, self.y_val, self.y_test)
    
    def save_preprocessed_data(self, output_dir='data'):
        import os
        
        if not os.path.isabs(output_dir):
            parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            output_dir = os.path.join(parent_dir, output_dir)
        
        print(f"\nSaving preprocessed data to {output_dir}...")
        
        os.makedirs(output_dir, exist_ok=True)
        
        np.save(f'{output_dir}/X_train.npy', self.X_train)
        np.save(f'{output_dir}/X_val.npy', self.X_val)
        np.save(f'{output_dir}/X_test.npy', self.X_test)
        np.save(f'{output_dir}/y_train.npy', self.y_train)
        np.save(f'{output_dir}/y_val.npy', self.y_val)
        np.save(f'{output_dir}/y_test.npy', self.y_test)
        
        joblib.dump(self.scaler, f'{output_dir}/scaler.pkl')
        joblib.dump(self.label_encoder, f'{output_dir}/label_encoder.pkl')

        np.save(f'{output_dir}/feature_columns.npy', self.feature_columns)
        
        print("Data saved successfully!")
        return True
    
    def preprocess(self):
        print("="*50)
        print("STARTING DATA PREPROCESSING PIPELINE")
        print("="*50)
        
        self.load_data()
        self.handle_missing_values()
        self.select_features()
        self.extract_statistical_features()
        self.encode_target()
        self.normalize_features()
        self.split_dataset()
        self.save_preprocessed_data()
        
        print("\n" + "="*50)
        print("PREPROCESSING COMPLETED SUCCESSFULLY")
        print("="*50)


if __name__ == "__main__":
    import os
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    csv_path = os.path.join(parent_dir, 'cicids.csv')
    
    preprocessor = DataPreprocessor(csv_path)
    preprocessor.preprocess()
