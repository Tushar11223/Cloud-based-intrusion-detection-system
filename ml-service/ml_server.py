# ml_server.py
# Flask server for machine learning prediction service

from flask import Flask, request, jsonify
from flask_cors import CORS
import numpy as np
import joblib
import os
import sys

# Add utils to path
sys.path.append(os.path.dirname(__file__))
from utils.feature_extraction import FeatureExtractor

app = Flask(__name__)
CORS(app)

# Global variables
model_data = None
feature_extractor = None

def load_model():
    """Load the trained model"""
    global model_data, feature_extractor
    
    model_path = 'models/etectormalware_d.pkl'
    
    if not os.path.exists(model_path):
        print(f"⚠ Model file not found at {model_path}")
        print("  Please train the model first using: python utils/model_trainer.py")
        return False
    
    try:
        model_data = joblib.load(model_path)
        feature_extractor = FeatureExtractor()
        print(f"✓ Model loaded successfully from {model_path}")
        return True
    except Exception as e:
        print(f"✗ Error loading model: {str(e)}")
        return False

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'ML Prediction Service',
        'model_loaded': model_data is not None
    })

@app.route('/predict', methods=['POST'])
def predict():
    """
    Predict malware from network flow features
    
    Request body:
    {
        "features": [
            {
                "duration": 2.5,
                "protocol": 6,
                "srcPort": 54321,
                "dstPort": 443,
                "packets": 150,
                "bytes": 75000
            },
            ...
        ]
    }
    
    Response:
    {
        "success": true,
        "predictions": [
            {
                "prediction": "BENIGN" or "MALICIOUS",
                "confidence": 0.95,
                "probabilities": {
                    "benign": 0.95,
                    "malicious": 0.05
                }
            },
            ...
        ]
    }
    """
    if model_data is None:
        return jsonify({
            'success': False,
            'error': 'Model not loaded. Please train the model first.'
        }), 500
    
    try:
        # Get request data
        data = request.get_json()
        
        if 'features' not in data:
            return jsonify({
                'success': False,
                'error': 'Missing "features" in request body'
            }), 400
        
        flows = data['features']
        
        if not isinstance(flows, list):
            flows = [flows]
        
        # Extract features
        X = feature_extractor.extract_features(flows)
        
        # Scale features
        X_scaled = model_data['scaler'].transform(X)
        
        # Make predictions
        predictions = model_data['model'].predict(X_scaled)
        probabilities = model_data['model'].predict_proba(X_scaled)
        
        # Get feature importance for each prediction
        feature_importances = model_data['model'].feature_importances_
        top_features_idx = np.argsort(feature_importances)[::-1][:5]
        
        # Format results
        results = []
        for i, (pred, probs) in enumerate(zip(predictions, probabilities)):
            result = {
                'prediction': 'MALICIOUS' if pred == 1 else 'BENIGN',
                'confidence': float(max(probs)),
                'probabilities': {
                    'benign': float(probs[0]),
                    'malicious': float(probs[1])
                },
                'features': feature_extractor.explain_features(flows[i]),
                'featureImportance': {
                    model_data['feature_names'][idx]: float(feature_importances[idx])
                    for idx in top_features_idx
                }
            }
            results.append(result)
        
        return jsonify({
            'success': True,
            'predictions': results,
            'model': 'Random Forest Classifier',
            'features_used': len(model_data['feature_names'])
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/model/info', methods=['GET'])
def model_info():
    """Get information about the loaded model"""
    if model_data is None:
        return jsonify({
            'success': False,
            'error': 'Model not loaded'
        }), 500
    
    try:
        # Get feature importances
        importances = model_data['model'].feature_importances_
        feature_importance = {
            name: float(imp) 
            for name, imp in zip(model_data['feature_names'], importances)
        }
        
        # Sort by importance
        sorted_features = sorted(
            feature_importance.items(), 
            key=lambda x: x[1], 
            reverse=True
        )
        
        return jsonify({
            'success': True,
            'model': {
                'type': 'Random Forest Classifier',
                'n_estimators': model_data['model'].n_estimators,
                'n_features': len(model_data['feature_names']),
                'features': model_data['feature_names'],
                'feature_importance': dict(sorted_features)
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/train', methods=['POST'])
def train_model():
    """
    Train a new model (for demonstration purposes)
    In production, this would be a separate offline process
    """
    try:
        from utils.model_trainer import ModelTrainer
        from sklearn.model_selection import train_test_split
        
        # Get parameters
        data = request.get_json() or {}
        n_samples = data.get('n_samples', 5000)
        malware_ratio = data.get('malware_ratio', 0.3)
        
        # Train model
        trainer = ModelTrainer()
        X, y = trainer.generate_synthetic_dataset(n_samples, malware_ratio)
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        trainer.train(X_train, y_train)
        accuracy, _ = trainer.evaluate(X_test, y_test)
        trainer.save_model('models/malware_detector.pkl')
        
        # Reload model
        load_model()
        
        return jsonify({
            'success': True,
            'message': 'Model trained successfully',
            'accuracy': float(accuracy),
            'samples': {
                'total': n_samples,
                'train': len(X_train),
                'test': len(X_test)
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

if __name__ == '__main__':
    print('╔═══════════════════════════════════════════════════════╗')
    print('║    ML Prediction Service - Malware Detection         ║')
    print('╚═══════════════════════════════════════════════════════╝')
    print('')
    
    # Load model
    model_loaded = load_model()
    
    if not model_loaded:
        print("\n⚠ WARNING: Model not loaded!")
        print("  To train a model, run: python utils/model_trainer.py")
        print("  Or use the /train endpoint after starting the server")
        print("")
    
    # Start server
    port = int(os.environ.get('ML_SERVICE_PORT', 5001))
    print(f'✓ Starting ML service on port {port}')
    print(f'✓ Endpoints:')
    print(f'  - POST http://localhost:{port}/predict')
    print(f'  - GET  http://localhost:{port}/model/info')
    print(f'  - GET  http://localhost:{port}/health')
    print(f'  - POST http://localhost:{port}/train')
    print('')
    print('Press Ctrl+C to stop the server')
    print('═══════════════════════════════════════════════════════')
    
    app.run(host='0.0.0.0', port=port, debug=False)