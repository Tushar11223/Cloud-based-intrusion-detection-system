# utils/feature_extraction.py
# Feature extraction from network flow logs for ML model

import numpy as np
import pandas as pd

class FeatureExtractor:
    """
    Extract features from network flow logs for malware detection
    
    Features are based on network flow characteristics that can
    distinguish between normal and malicious traffic patterns.
    """
    
    def __init__(self):
        # Feature names for documentation
        self.feature_names = [
            'duration',
            'protocol',
            'src_port',
            'dst_port',
            'packets',
            'bytes',
            'bytes_per_packet',
            'packets_per_second',
            'bytes_per_second',
            'is_tcp',
            'is_udp',
            'is_common_port',
            'port_ratio',
            'packet_size_variance'
        ]
    
    def extract_features(self, flow_data):
        """
        Extract features from a single flow or batch of flows
        
        Args:
            flow_data: dict or list of dicts containing flow information
            
        Returns:
            numpy array of features
        """
        if isinstance(flow_data, dict):
            return self._extract_single(flow_data)
        elif isinstance(flow_data, list):
            return np.array([self._extract_single(flow) for flow in flow_data])
        else:
            raise ValueError("flow_data must be dict or list of dicts")
    
    def _extract_single(self, flow):
        """Extract features from a single flow"""
        
        # Basic features
        duration = float(flow.get('duration', 0))
        protocol = int(flow.get('protocol', 6))
        src_port = int(flow.get('srcPort', 0))
        dst_port = int(flow.get('dstPort', 0))
        packets = int(flow.get('packets', 0))
        bytes_val = int(flow.get('bytes', 0))
        
        # Derived features
        bytes_per_packet = bytes_val / max(packets, 1)
        packets_per_second = packets / max(duration, 0.01)
        bytes_per_second = bytes_val / max(duration, 0.01)
        
        # Protocol indicators
        is_tcp = 1 if protocol == 6 else 0
        is_udp = 1 if protocol == 17 else 0
        
        # Port analysis
        common_ports = [80, 443, 53, 22, 21, 25, 110, 143]
        is_common_port = 1 if dst_port in common_ports else 0
        
        # Port ratio (higher number = less common port)
        port_ratio = dst_port / 65535.0
        
        # Packet size variance indicator
        # (In real implementation, would need packet size distribution)
        # For simulation, estimate based on avg packet size
        if bytes_per_packet < 100 or bytes_per_packet > 10000:
            packet_size_variance = 1  # High variance
        else:
            packet_size_variance = 0  # Normal variance
        
        features = [
            duration,
            protocol,
            src_port,
            dst_port,
            packets,
            bytes_val,
            bytes_per_packet,
            packets_per_second,
            bytes_per_second,
            is_tcp,
            is_udp,
            is_common_port,
            port_ratio,
            packet_size_variance
        ]
        
        return np.array(features, dtype=float)
    
    def get_feature_names(self):
        """Return list of feature names"""
        return self.feature_names
    
    def extract_batch_dataframe(self, flows):
        """
        Extract features and return as pandas DataFrame
        
        Args:
            flows: list of flow dictionaries
            
        Returns:
            pandas DataFrame with features
        """
        features = self.extract_features(flows)
        return pd.DataFrame(features, columns=self.feature_names)
    
    def explain_features(self, flow):
        """
        Explain what each feature value represents
        
        Args:
            flow: single flow dictionary
            
        Returns:
            dict with feature explanations
        """
        features = self._extract_single(flow)
        
        explanations = {}
        for name, value in zip(self.feature_names, features):
            if name == 'duration':
                explanations[name] = f"{value:.2f} seconds"
            elif name == 'protocol':
                proto_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
                explanations[name] = proto_map.get(int(value), 'Unknown')
            elif name in ['src_port', 'dst_port']:
                explanations[name] = int(value)
            elif name == 'packets':
                explanations[name] = f"{int(value)} packets"
            elif name == 'bytes':
                explanations[name] = f"{int(value)} bytes ({self._format_bytes(value)})"
            elif name in ['bytes_per_packet', 'packets_per_second', 'bytes_per_second']:
                explanations[name] = f"{value:.2f}"
            elif name in ['is_tcp', 'is_udp', 'is_common_port', 'packet_size_variance']:
                explanations[name] = "Yes" if value == 1 else "No"
            elif name == 'port_ratio':
                explanations[name] = f"{value:.4f}"
            else:
                explanations[name] = value
        
        return explanations
    
    def _format_bytes(self, bytes_val):
        """Format bytes for human readability"""
        if bytes_val < 1024:
            return f"{bytes_val} B"
        elif bytes_val < 1024 * 1024:
            return f"{bytes_val/1024:.2f} KB"
        else:
            return f"{bytes_val/(1024*1024):.2f} MB"


# Example usage
if __name__ == "__main__":
    # Test feature extraction
    extractor = FeatureExtractor()
    
    # Sample flow
    sample_flow = {
        'duration': 2.5,
        'protocol': 6,
        'srcPort': 54321,
        'dstPort': 443,
        'packets': 150,
        'bytes': 75000
    }
    
    features = extractor.extract_features(sample_flow)
    print("Extracted features:")
    print(features)
    
    print("\nFeature explanations:")
    explanations = extractor.explain_features(sample_flow)
    for name, explanation in explanations.items():
        print(f"  {name}: {explanation}")