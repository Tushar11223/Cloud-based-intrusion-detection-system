#!/usr/bin/env python3
"""
Enhanced ML Trainer - For Your EXISTING Project
Works with your current ml-service folder structure
Trains XGBoost model with enhanced features from CIC-IDS data
"""

import numpy as np
import pandas as pd
import joblib
import json
from pathlib import Path
from datetime import datetime

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier


class ExistingProjectMLTrainer:
    """Enhanced ML trainer that integrates with your existing project"""
    
    def __init__(self, ml_service_dir='ml-service'):
        self.ml_service_dir = Path(ml_service_dir)
        self.models_dir = self.ml_service_dir / 'models'
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
        self.scaler = None
        self.feature_names = None
    
    def extract_features_from_flowlog(self, flow_log):
        """
        Extract features from your FlowLog format
        Works with both synthetic and CIC-IDS imported data
        """
        features = {}
        
        # Basic features (your original 14)
        features['duration'] = float(flow_log.get('duration', 0))
        features['protocol'] = int(flow_log.get('protocol', 6))
        features['src_port'] = int(flow_log.get('srcPort', 0))
        features['dst_port'] = int(flow_log.get('dstPort', 0))
        features['packets'] = int(flow_log.get('packets', 0))
        features['bytes'] = int(flow_log.get('bytes', 0))
        
        # Derived features
        features['bytes_per_packet'] = features['bytes'] / max(features['packets'], 1)
        features['packets_per_second'] = features['packets'] / max(features['duration'], 0.001)
        features['bytes_per_second'] = features['bytes'] / max(features['duration'], 0.001)
        
        # Port features
        features['is_common_port'] = 1 if features['dst_port'] in [80, 443, 53, 22, 21, 25] else 0
        features['is_privileged_port'] = 1 if features['dst_port'] < 1024 else 0
        features['port_ratio'] = features['src_port'] / max(features['dst_port'], 1)
        
        # Protocol features
        features['is_tcp'] = 1 if features['protocol'] == 6 else 0
        features['is_udp'] = 1 if features['protocol'] == 17 else 0
        
        return features
    
    def load_flowlogs_from_json(self, json_path):
        """Load FlowLogs from JSON file (CIC-IDS converted format)"""
        print(f"📂 Loading flow logs from {json_path}...")
        
        with open(json_path, 'r') as f:
            flow_logs = json.load(f)
        
        print(f"✅ Loaded {len(flow_logs):,} flow logs")
        
        return flow_logs
    
    def load_flowlogs_from_mongodb(self, mongo_uri='mongodb://localhost:27017',
                                   db_name='malware_detection', 
                                   collection_name='flow_logs',
                                   limit=None):
        """Load FlowLogs directly from your MongoDB"""
        try:
            from pymongo import MongoClient
            
            print(f"🔌 Connecting to MongoDB...")
            client = MongoClient(mongo_uri)
            db = client[db_name]
            collection = db[collection_name]
            
            query = {}
            cursor = collection.find(query).limit(limit) if limit else collection.find(query)
            
            flow_logs = list(cursor)
            
            print(f"✅ Loaded {len(flow_logs):,} flow logs from MongoDB")
            
            client.close()
            return flow_logs
            
        except ImportError:
            print("❌ pymongo not installed. Install with: pip install pymongo")
            return []
        except Exception as e:
            print(f"❌ MongoDB connection failed: {e}")
            return []
    
    def prepare_dataset(self, flow_logs):
        """Convert FlowLogs to feature matrix and labels"""
        print(f"\n🔬 Extracting features from {len(flow_logs):,} flow logs...")
        
        X_data = []
        y_data = []
        
        for idx, flow in enumerate(flow_logs):
            if idx % 1000 == 0:
                print(f"  Progress: {idx:,}/{len(flow_logs):,}", end='\r')
            
            # Extract features
            features = self.extract_features_from_flowlog(flow)
            
            # Get label
            label = 1 if flow.get('actualLabel') == 'MALWARE' else 0
            
            X_data.append(list(features.values()))
            y_data.append(label)
        
        print(f"\n✅ Extracted features")
        
        # Store feature names
        self.feature_names = list(features.keys())
        
        X = np.array(X_data)
        y = np.array(y_data)
        
        print(f"\n📊 Dataset shape: {X.shape}")
        print(f"   Features: {X.shape[1]}")
        print(f"   Samples: {X.shape[0]}")
        
        # Show class distribution
        unique, counts = np.unique(y, return_counts=True)
        print(f"\n📊 Class distribution:")
        for cls, count in zip(unique, counts):
            label_name = "Benign" if cls == 0 else "Malware"
            percentage = (count / len(y)) * 100
            print(f"   {label_name}: {count:,} ({percentage:.1f}%)")
        
        return X, y
    
    def train_models(self, X, y):
        """Train both Random Forest and XGBoost"""
        print("\n" + "="*60)
        print("TRAINING MODELS")
        print("="*60)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"\nTraining set: {len(X_train):,} samples")
        print(f"Test set: {len(X_test):,} samples")
        
        # Scale features
        print("\n🔧 Scaling features...")
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        results = {}
        
        # Train Random Forest (your original model)
        print("\n🌲 Training Random Forest...")
        rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            random_state=42,
            n_jobs=-1
        )
        rf_model.fit(X_train_scaled, y_train)
        
        y_pred_rf = rf_model.predict(X_test_scaled)
        results['random_forest'] = {
            'model': rf_model,
            'accuracy': accuracy_score(y_test, y_pred_rf),
            'precision': precision_score(y_test, y_pred_rf),
            'recall': recall_score(y_test, y_pred_rf),
            'f1': f1_score(y_test, y_pred_rf)
        }
        
        print(f"✅ Random Forest trained")
        print(f"   Accuracy: {results['random_forest']['accuracy']:.4f}")
        print(f"   F1-Score: {results['random_forest']['f1']:.4f}")
        
        # Train XGBoost (enhanced model)
        print("\n🚀 Training XGBoost...")
        xgb_model = XGBClassifier(
            n_estimators=100,
            max_depth=10,
            learning_rate=0.1,
            random_state=42,
            n_jobs=-1,
            verbosity=0
        )
        xgb_model.fit(X_train_scaled, y_train)
        
        y_pred_xgb = xgb_model.predict(X_test_scaled)
        results['xgboost'] = {
            'model': xgb_model,
            'accuracy': accuracy_score(y_test, y_pred_xgb),
            'precision': precision_score(y_test, y_pred_xgb),
            'recall': recall_score(y_test, y_pred_xgb),
            'f1': f1_score(y_test, y_pred_xgb)
        }
        
        print(f"✅ XGBoost trained")
        print(f"   Accuracy: {results['xgboost']['accuracy']:.4f}")
        print(f"   F1-Score: {results['xgboost']['f1']:.4f}")
        
        # Compare
        print("\n" + "="*60)
        print("MODEL COMPARISON")
        print("="*60)
        print(f"\n{'Model':<20} {'Accuracy':<12} {'Precision':<12} {'Recall':<12} {'F1-Score':<12}")
        print("-"*68)
        
        for name, res in results.items():
            print(f"{name.replace('_', ' ').title():<20} "
                  f"{res['accuracy']:<12.4f} "
                  f"{res['precision']:<12.4f} "
                  f"{res['recall']:<12.4f} "
                  f"{res['f1']:<12.4f}")
        
        # Select best model
        best_name = max(results.items(), key=lambda x: x[1]['f1'])[0]
        best_model = results[best_name]['model']
        
        print(f"\n🏆 Best Model: {best_name.replace('_', ' ').title()}")
        
        return best_model, results, (X_test_scaled, y_test)
    
    def save_model(self, model, model_name='malware_detector'):
        """Save model in your existing ml-service/models/ folder"""
        print(f"\n💾 Saving model...")
        
        # Save main model (replaces your existing one)
        model_path = self.models_dir / f'{model_name}.pkl'
        joblib.dump(model, model_path)
        print(f"✅ Saved model: {model_path}")
        
        # Save scaler
        scaler_path = self.models_dir / 'scaler.pkl'
        joblib.dump(self.scaler, scaler_path)
        print(f"✅ Saved scaler: {scaler_path}")
        
        # Save feature names
        features_path = self.models_dir / 'feature_names.json'
        with open(features_path, 'w') as f:
            json.dump(self.feature_names, f, indent=2)
        print(f"✅ Saved feature names: {features_path}")
        
        # Save metadata
        metadata = {
            'trained_date': datetime.now().isoformat(),
            'n_features': len(self.feature_names),
            'feature_names': self.feature_names,
            'model_type': type(model).__name__
        }
        
        metadata_path = self.models_dir / 'model_metadata.json'
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        print(f"✅ Saved metadata: {metadata_path}")
        
        return model_path


def main():
    """Main training pipeline"""
    print("""
╔══════════════════════════════════════════════════════════╗
║     Enhanced ML Training - Existing Project              ║
║     Works with your current ml-service structure         ║
╚══════════════════════════════════════════════════════════╝
    """)
    
    trainer = ExistingProjectMLTrainer()
    
    # Choose data source
    print("\n📊 Data Source Options:")
    print("1. Load from JSON file (converted CIC-IDS)")
    print("2. Load from MongoDB (your existing database)")
    print("\nChoice (1 or 2): ", end='')
    
    choice = input().strip()
    
    if choice == '1':
        # Load from JSON
        json_path = 'datasets/cic-ids-2017/converted/flowlogs.json'
        
        if not Path(json_path).exists():
            print(f"\n❌ File not found: {json_path}")
            print("\n📝 First run: python integrate_cicids_to_existing_project.py")
            return
        
        flow_logs = trainer.load_flowlogs_from_json(json_path)
        
    elif choice == '2':
        # Load from MongoDB
        print("\nHow many samples to load? (e.g., 10000): ", end='')
        limit = int(input().strip())
        
        flow_logs = trainer.load_flowlogs_from_mongodb(limit=limit)
        
        if not flow_logs:
            print("❌ No data loaded from MongoDB")
            return
    else:
        print("❌ Invalid choice")
        return
    
    # Prepare dataset
    X, y = trainer.prepare_dataset(flow_logs)
    
    # Train models
    best_model, results, test_data = trainer.train_models(X, y)
    
    # Save model
    model_path = trainer.save_model(best_model)
    
    print("\n" + "="*60)
    print("✅ TRAINING COMPLETE!")
    print("="*60)
    print(f"\n📁 Model saved to: {model_path}")
    print("\n🔄 Next steps:")
    print("1. Your ml-service/models/ folder now has the enhanced model")
    print("2. Restart your ML service: python ml_server.py")
    print("3. Your backend will automatically use the new model")
    print("4. Test detection on CIC-IDS data!")
    print("="*60)


if __name__ == '__main__':
    main()