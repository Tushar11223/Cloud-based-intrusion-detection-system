# utils/model_trainer.py
# Train Random Forest classifier for malware detection

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import StandardScaler
import joblib
import os

class ModelTrainer:
    """
    Train and evaluate Random Forest classifier for network malware detection
    
    Uses simulated dataset that mimics CIC-IDS 2017 / NSL-KDD characteristics
    """
    
    def __init__(self, random_state=42):
        self.random_state = random_state
        self.model = None
        self.scaler = None
        self.feature_names = None
        
    def generate_synthetic_dataset(self, n_samples=10000, malware_ratio=0.3):
        """
        Generate synthetic dataset for training
        
        This simulates characteristics of real malware vs benign traffic
        based on research from CIC-IDS 2017 dataset patterns
        
        Args:
            n_samples: number of samples to generate
            malware_ratio: proportion of malware samples
            
        Returns:
            X: feature array
            y: labels (0=benign, 1=malware)
        """
        n_malware = int(n_samples * malware_ratio)
        n_benign = n_samples - n_malware
        
        # Benign traffic characteristics
        benign_data = self._generate_benign_traffic(n_benign)
        benign_labels = np.zeros(n_benign)
        
        # Malware traffic characteristics
        malware_data = self._generate_malware_traffic(n_malware)
        malware_labels = np.ones(n_malware)
        
        # Combine and shuffle
        X = np.vstack([benign_data, malware_data])
        y = np.concatenate([benign_labels, malware_labels])
        
        # Shuffle
        indices = np.random.permutation(len(X))
        X = X[indices]
        y = y[indices]
        
        return X, y
    
    def _generate_benign_traffic(self, n_samples):
        """Generate benign traffic patterns"""
        data = []
        
        for _ in range(n_samples):
            # Normal HTTP/HTTPS traffic
            if np.random.random() < 0.7:
                duration = np.random.exponential(2.0)  # 0-5 seconds typically
                protocol = 6  # TCP
                src_port = np.random.randint(1024, 65535)
                dst_port = np.random.choice([80, 443])  # HTTP/HTTPS
                packets = np.random.randint(10, 200)
                bytes_val = packets * np.random.randint(500, 1500)
            # Normal DNS traffic
            else:
                duration = np.random.uniform(0.01, 0.5)
                protocol = 17  # UDP
                src_port = np.random.randint(1024, 65535)
                dst_port = 53  # DNS
                packets = np.random.randint(2, 10)
                bytes_val = packets * np.random.randint(100, 500)
            
            # Calculate derived features
            bytes_per_packet = bytes_val / max(packets, 1)
            packets_per_second = packets / max(duration, 0.01)
            bytes_per_second = bytes_val / max(duration, 0.01)
            
            is_tcp = 1 if protocol == 6 else 0
            is_udp = 1 if protocol == 17 else 0
            is_common_port = 1 if dst_port in [80, 443, 53, 22] else 0
            port_ratio = dst_port / 65535.0
            packet_size_variance = 0  # Normal variance
            
            features = [
                duration, protocol, src_port, dst_port, packets, bytes_val,
                bytes_per_packet, packets_per_second, bytes_per_second,
                is_tcp, is_udp, is_common_port, port_ratio, packet_size_variance
            ]
            data.append(features)
        
        return np.array(data)
    
    def _generate_malware_traffic(self, n_samples):
        """Generate malware traffic patterns"""
        data = []
        
        for _ in range(n_samples):
            pattern_type = np.random.choice(['c2_beaconing', 'port_scan', 'exfiltration'])
            
            if pattern_type == 'c2_beaconing':
                # C2 beaconing: short, periodic connections
                duration = np.random.uniform(0.5, 2.0)
                protocol = 6  # TCP
                src_port = np.random.randint(1024, 65535)
                dst_port = np.random.choice([4444, 5555, 6666, 8080])  # Suspicious ports
                packets = np.random.randint(5, 30)  # Small packets
                bytes_val = packets * np.random.randint(100, 500)  # Small data
                
            elif pattern_type == 'port_scan':
                # Port scanning: very short connections, random ports
                duration = np.random.uniform(0.01, 0.1)
                protocol = 6  # TCP
                src_port = np.random.randint(1024, 65535)
                dst_port = np.random.randint(1, 65535)  # Random port
                packets = np.random.randint(1, 5)
                bytes_val = packets * 64  # Minimal data
                
            else:  # exfiltration
                # Data exfiltration: large outbound transfer
                duration = np.random.uniform(5.0, 30.0)
                protocol = 6  # TCP
                src_port = np.random.randint(1024, 65535)
                dst_port = np.random.choice([4444, 8080, 9000])
                packets = np.random.randint(500, 5000)
                bytes_val = np.random.randint(1000000, 50000000)  # Large data
            
            # Calculate derived features
            bytes_per_packet = bytes_val / max(packets, 1)
            packets_per_second = packets / max(duration, 0.01)
            bytes_per_second = bytes_val / max(duration, 0.01)
            
            is_tcp = 1 if protocol == 6 else 0
            is_udp = 1 if protocol == 17 else 0
            is_common_port = 1 if dst_port in [80, 443, 53, 22] else 0
            port_ratio = dst_port / 65535.0
            packet_size_variance = 1  # High variance
            
            features = [
                duration, protocol, src_port, dst_port, packets, bytes_val,
                bytes_per_packet, packets_per_second, bytes_per_second,
                is_tcp, is_udp, is_common_port, port_ratio, packet_size_variance
            ]
            data.append(features)
        
        return np.array(data)
    
    def train(self, X_train, y_train, n_estimators=100):
        """
        Train Random Forest classifier
        
        Args:
            X_train: training features
            y_train: training labels
            n_estimators: number of trees in forest
        """
        print("Training Random Forest classifier...")
        
        # Standardize features
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        
        # Train model
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=self.random_state,
            n_jobs=-1
        )
        
        self.model.fit(X_train_scaled, y_train)
        print("✓ Training completed")
        
    def evaluate(self, X_test, y_test):
        """Evaluate model performance"""
        if self.model is None:
            raise ValueError("Model not trained yet")
        
        X_test_scaled = self.scaler.transform(X_test)
        y_pred = self.model.predict(X_test_scaled)
        
        print("\n" + "="*50)
        print("MODEL EVALUATION RESULTS")
        print("="*50)
        
        # Accuracy
        accuracy = accuracy_score(y_test, y_pred)
        print(f"\nAccuracy: {accuracy:.4f}")
        
        # Classification report
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, 
                                   target_names=['Benign', 'Malware']))
        
        # Confusion matrix
        print("\nConfusion Matrix:")
        cm = confusion_matrix(y_test, y_pred)
        print(f"                Predicted")
        print(f"                Benign  Malware")
        print(f"Actual Benign   {cm[0][0]:6d}  {cm[0][1]:6d}")
        print(f"       Malware  {cm[1][0]:6d}  {cm[1][1]:6d}")
        
        # Feature importance
        print("\nTop 10 Most Important Features:")
        feature_names = [
            'duration', 'protocol', 'src_port', 'dst_port', 'packets', 'bytes',
            'bytes_per_packet', 'packets_per_second', 'bytes_per_second',
            'is_tcp', 'is_udp', 'is_common_port', 'port_ratio', 'packet_size_variance'
        ]
        
        importances = self.model.feature_importances_
        indices = np.argsort(importances)[::-1]
        
        for i in range(min(10, len(feature_names))):
            idx = indices[i]
            print(f"  {i+1}. {feature_names[idx]:20s}: {importances[idx]:.4f}")
        
        return accuracy, y_pred
    
    def save_model(self, filepath='models/malware_detector.pkl'):
        """Save trained model and scaler"""
        if self.model is None:
            raise ValueError("No model to save")
        
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': [
                'duration', 'protocol', 'src_port', 'dst_port', 'packets', 'bytes',
                'bytes_per_packet', 'packets_per_second', 'bytes_per_second',
                'is_tcp', 'is_udp', 'is_common_port', 'port_ratio', 'packet_size_variance'
            ]
        }
        
        joblib.dump(model_data, filepath)
        print(f"\n✓ Model saved to {filepath}")
    
    def load_model(self, filepath='models/malware_detector.pkl'):
        """Load pre-trained model"""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Model file not found: {filepath}")
        
        model_data = joblib.load(filepath)
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.feature_names = model_data['feature_names']
        print(f"✓ Model loaded from {filepath}")


# Training script
if __name__ == "__main__":
    print("="*60)
    print("MALWARE DETECTION MODEL TRAINING")
    print("="*60)
    
    # Initialize trainer
    trainer = ModelTrainer()
    
    # Generate synthetic dataset
    print("\nGenerating synthetic dataset...")
    X, y = trainer.generate_synthetic_dataset(n_samples=10000, malware_ratio=0.3)
    print(f"✓ Generated {len(X)} samples")
    print(f"  - Benign: {np.sum(y==0)}")
    print(f"  - Malware: {np.sum(y==1)}")
    
    # Split dataset
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\n✓ Split into train ({len(X_train)}) and test ({len(X_test)}) sets")
    
    # Train model
    trainer.train(X_train, y_train, n_estimators=100)
    
    # Evaluate model
    trainer.evaluate(X_test, y_test)
    
    # Save model
    trainer.save_model('models/malware_detector.pkl')
    
    print("\n" + "="*60)
    print("TRAINING COMPLETED SUCCESSFULLY")
    print("="*60)