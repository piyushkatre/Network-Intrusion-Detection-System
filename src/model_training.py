import numpy as np
import joblib
import os
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from xgboost import XGBClassifier #type: ignore
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
import json


class ModelTrainer:
    def __init__(self, data_dir='data'):
        import os
        
        if not os.path.isabs(data_dir):
            script_dir = os.path.dirname(os.path.abspath(__file__))
            parent_dir = os.path.dirname(script_dir)
            data_dir = os.path.join(parent_dir, data_dir)
        
        self.data_dir = data_dir
        self.models = {}
        self.results = {}
        self.best_model = None
        self.best_model_name = None
        self.best_score = 0
        
        self.load_data()
    
    def load_data(self):
        print("Loading preprocessed data...")
        self.X_train = np.load(f'{self.data_dir}/X_train.npy')
        self.X_val = np.load(f'{self.data_dir}/X_val.npy')
        self.X_test = np.load(f'{self.data_dir}/X_test.npy')
        self.y_train = np.load(f'{self.data_dir}/y_train.npy')
        self.y_val = np.load(f'{self.data_dir}/y_val.npy')
        self.y_test = np.load(f'{self.data_dir}/y_test.npy')
        
        print(f"Training set: {self.X_train.shape}")
        print(f"Validation set: {self.X_val.shape}")
        print(f"Test set: {self.X_test.shape}")
    
    def train_xgboost(self):
        print("\n" + "="*50)
        print("Training XGBoost Model...")
        print("="*50)
        
        model = XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=42,
            n_jobs=-1,
            eval_metric='logloss'
        )
        
        model.fit(
            self.X_train, self.y_train,
            eval_set=[(self.X_val, self.y_val)],
            verbose=False
        )
        
        self.models['XGBoost'] = model
        print("XGBoost training completed!")
        return model
    
    def train_svm(self):
        print("\n" + "="*50)
        print("Training SVM Model...")
        print("="*50)
        
        from sklearn.utils import resample
        
        sample_size = min(50000, len(self.X_train)) 
        rng = np.random.RandomState(42)
        indices = rng.choice(len(self.X_train), size=sample_size, replace=False)
        X_train_sample = self.X_train[indices]
        y_train_sample = self.y_train[indices]
        
        print(f"Using {sample_size} samples for SVM training (full set: {len(self.X_train)})")
        print("(SVM has O(n²) complexity, so using subset for reasonable training time)")
        
        model = SVC(
            kernel='linear', 
            C=1.0,
            probability=True,
            random_state=42,
            max_iter=2000
        )
        
        print("Training... (this may take a few minutes)")
        model.fit(X_train_sample, y_train_sample)
        
        self.models['SVM'] = model
        print("SVM training completed!")
        return model
    
    def train_logistic_regression(self):
        print("\n" + "="*50)
        print("Training Logistic Regression Model...")
        print("="*50)
        
        model = LogisticRegression(
            max_iter=1000,
            random_state=42,
            n_jobs=-1
        )
        
        model.fit(self.X_train, self.y_train)
        
        self.models['LogisticRegression'] = model
        print("Logistic Regression training completed!")
        return model
    
    def evaluate_model(self, model_name, model, X_test, y_test):
        print(f"\nEvaluating {model_name}...")
        
        y_pred = model.predict(X_test)
        
        if hasattr(model, 'predict_proba'):
            y_pred_proba = model.predict_proba(X_test)[:, 1]
        else:
            y_pred_proba = None
        
        metrics = {
            'Accuracy': accuracy_score(y_test, y_pred),
            'Precision': precision_score(y_test, y_pred, average='weighted', zero_division=0),
            'Recall': recall_score(y_test, y_pred, average='weighted', zero_division=0),
            'F1-Score': f1_score(y_test, y_pred, average='weighted', zero_division=0),
        }
        
        if len(np.unique(y_test)) == 2 and y_pred_proba is not None:
            metrics['ROC-AUC'] = roc_auc_score(y_test, y_pred_proba)
        
        self.results[model_name] = metrics
        
        print(f"\nResults for {model_name}:")
        for metric, value in metrics.items():
            print(f"  {metric}: {value:.4f}")
        
        return metrics
    
    def train_all_models(self):
        print("="*60)
        print("STARTING MODEL TRAINING")
        print("="*60)
        print()
        
        self.train_xgboost()
        self.train_svm()
        self.train_logistic_regression()
        
        print("\n" + "="*60)
        print("ALL MODELS TRAINED")
        print("="*60)
    
    def evaluate_all_models(self):
        print("\n" + "="*60)
        print("EVALUATING ALL MODELS ON TEST SET")
        print("="*60)
        
        for model_name, model in self.models.items():
            self.evaluate_model(model_name, model, self.X_test, self.y_test)
        
        print("\n" + "="*60)
        print("EVALUATION COMPLETED")
        print("="*60)
    
    def compare_models(self):
        print("\n" + "="*60)
        print("MODEL COMPARISON")
        print("="*60)
        
        print("\n{:<20} {:<12} {:<12} {:<10} {:<10}".format(
            "Model", "Accuracy", "Precision", "Recall", "F1-Score"
        ))
        print("-"*64)
        
        for model_name, metrics in self.results.items():
            print("{:<20} {:<12.4f} {:<12.4f} {:<10.4f} {:<10.4f}".format(
                model_name,
                metrics['Accuracy'],
                metrics['Precision'],
                metrics['Recall'],
                metrics['F1-Score']
            ))
            
            if metrics['F1-Score'] > self.best_score:
                self.best_score = metrics['F1-Score']
                self.best_model_name = model_name
                self.best_model = self.models[model_name]
        
        print("-"*64)
        print(f"\nBest Model: {self.best_model_name} (F1-Score: {self.best_score:.4f})")
        
        return self.best_model_name, self.best_model
    
    def save_models(self, output_dir='models'):
        import os
        
        if not os.path.isabs(output_dir):
            script_dir = os.path.dirname(os.path.abspath(__file__))
            parent_dir = os.path.dirname(script_dir)
            output_dir = os.path.join(parent_dir, output_dir)
        
        print(f"\nSaving models to {output_dir}...")
        os.makedirs(output_dir, exist_ok=True)
        
        for model_name, model in self.models.items():
            model_path = f'{output_dir}/{model_name}_model.pkl'
            joblib.dump(model, model_path)
            print(f"  Saved: {model_path}")
        
        joblib.dump(self.best_model, f'{output_dir}/best_model.pkl')
        print(f"  Saved: {output_dir}/best_model.pkl")
        
        results_json = {k: v for k, v in self.results.items()}
        with open(f'{output_dir}/model_results.json', 'w') as f:
            json.dump(results_json, f, indent=4)
        print(f"  Saved: {output_dir}/model_results.json")
    
    def train_and_evaluate(self):
        self.train_all_models()
        self.evaluate_all_models()
        self.compare_models()
        self.save_models()


if __name__ == "__main__":
    trainer = ModelTrainer()
    trainer.train_and_evaluate()
