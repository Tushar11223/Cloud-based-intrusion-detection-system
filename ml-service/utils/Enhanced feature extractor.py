#!/usr/bin/env python3
"""
Enhanced Feature Extraction - 50+ Features
Extracts comprehensive features from CIC-IDS 2017 dataset
"""

import pandas as pd
import numpy as np
from datetime import datetime
from scipy import stats

class EnhancedFeatureExtractor:
    """Extract 50+ features from network flow data"""
    
    def __init__(self):
        self.feature_names = []
        
    def extract_from_cicids(self, df):
        """
        Extract features from CIC-IDS 2017 dataset
        
        CIC-IDS has 78 features, we'll select and engineer the most important ones
        """
        print("🔬 Extracting enhanced features from CIC-IDS 2017...")
        
        features_df = pd.DataFrame()
        
        # ===== BASIC FLOW FEATURES (10) =====
        print("  ✓ Basic flow features...")
        features_df['flow_duration'] = df.get('Flow Duration', 0)
        features_df['total_fwd_packets'] = df.get('Total Fwd Packets', df.get('Total Fwd Packet', 0))
        features_df['total_bwd_packets'] = df.get('Total Backward Packets', df.get('Total Backward Packet', 0))
        features_df['total_packets'] = features_df['total_fwd_packets'] + features_df['total_bwd_packets']
        
        features_df['total_fwd_bytes'] = df.get('Total Length of Fwd Packets', df.get('Total Length of Fwd Packet', 0))
        features_df['total_bwd_bytes'] = df.get('Total Length of Bwd Packets', df.get('Total Length of Bwd Packet', 0))
        features_df['total_bytes'] = features_df['total_fwd_bytes'] + features_df['total_bwd_bytes']
        
        features_df['src_port'] = df.get('Source Port', 0)
        features_df['dst_port'] = df.get('Destination Port', 0)
        features_df['protocol'] = df.get('Protocol', 0)
        
        # ===== PACKET SIZE FEATURES (8) =====
        print("  ✓ Packet size statistics...")
        features_df['fwd_packet_length_max'] = df.get('Fwd Packet Length Max', 0)
        features_df['fwd_packet_length_min'] = df.get('Fwd Packet Length Min', 0)
        features_df['fwd_packet_length_mean'] = df.get('Fwd Packet Length Mean', 0)
        features_df['fwd_packet_length_std'] = df.get('Fwd Packet Length Std', 0)
        
        features_df['bwd_packet_length_max'] = df.get('Bwd Packet Length Max', 0)
        features_df['bwd_packet_length_min'] = df.get('Bwd Packet Length Min', 0)
        features_df['bwd_packet_length_mean'] = df.get('Bwd Packet Length Mean', 0)
        features_df['bwd_packet_length_std'] = df.get('Bwd Packet Length Std', 0)
        
        # ===== FLOW RATE FEATURES (6) =====
        print("  ✓ Flow rate features...")
        features_df['flow_bytes_per_second'] = df.get('Flow Bytes/s', 0)
        features_df['flow_packets_per_second'] = df.get('Flow Packets/s', 0)
        
        features_df['fwd_packets_per_second'] = df.get('Fwd Packets/s', 0)
        features_df['bwd_packets_per_second'] = df.get('Bwd Packets/s', 0)
        
        # Derived rates
        features_df['avg_packet_size'] = np.where(
            features_df['total_packets'] > 0,
            features_df['total_bytes'] / features_df['total_packets'],
            0
        )
        
        features_df['packet_size_variance'] = np.where(
            features_df['total_packets'] > 1,
            ((features_df['fwd_packet_length_std'] ** 2 + 
              features_df['bwd_packet_length_std'] ** 2) / 2),
            0
        )
        
        # ===== IAT (Inter-Arrival Time) FEATURES (8) =====
        print("  ✓ Inter-arrival time features...")
        features_df['flow_iat_mean'] = df.get('Flow IAT Mean', 0)
        features_df['flow_iat_std'] = df.get('Flow IAT Std', 0)
        features_df['flow_iat_max'] = df.get('Flow IAT Max', 0)
        features_df['flow_iat_min'] = df.get('Flow IAT Min', 0)
        
        features_df['fwd_iat_mean'] = df.get('Fwd IAT Mean', 0)
        features_df['fwd_iat_std'] = df.get('Fwd IAT Std', 0)
        features_df['bwd_iat_mean'] = df.get('Bwd IAT Mean', 0)
        features_df['bwd_iat_std'] = df.get('Bwd IAT Std', 0)
        
        # ===== TCP FLAG FEATURES (6) =====
        print("  ✓ TCP flag features...")
        features_df['fin_flag_count'] = df.get('FIN Flag Count', 0)
        features_df['syn_flag_count'] = df.get('SYN Flag Count', 0)
        features_df['rst_flag_count'] = df.get('RST Flag Count', 0)
        features_df['psh_flag_count'] = df.get('PSH Flag Count', 0)
        features_df['ack_flag_count'] = df.get('ACK Flag Count', 0)
        features_df['urg_flag_count'] = df.get('URG Flag Count', 0)
        
        # ===== WINDOW & HEADER FEATURES (4) =====
        print("  ✓ Window and header features...")
        features_df['fwd_header_length'] = df.get('Fwd Header Length', 0)
        features_df['bwd_header_length'] = df.get('Bwd Header Length', 0)
        features_df['init_win_bytes_forward'] = df.get('Init_Win_bytes_forward', df.get('Init Fwd Win Bytes', 0))
        features_df['init_win_bytes_backward'] = df.get('Init_Win_bytes_backward', df.get('Init Bwd Win Bytes', 0))
        
        # ===== BULK & SEGMENT FEATURES (6) =====
        print("  ✓ Bulk and segment features...")
        features_df['fwd_avg_bytes_bulk'] = df.get('Fwd Avg Bytes/Bulk', 0)
        features_df['fwd_avg_packets_bulk'] = df.get('Fwd Avg Packets/Bulk', 0)
        features_df['fwd_avg_bulk_rate'] = df.get('Fwd Avg Bulk Rate', 0)
        
        features_df['bwd_avg_bytes_bulk'] = df.get('Bwd Avg Bytes/Bulk', 0)
        features_df['bwd_avg_packets_bulk'] = df.get('Bwd Avg Packets/Bulk', 0)
        features_df['bwd_avg_bulk_rate'] = df.get('Bwd Avg Bulk Rate', 0)
        
        # ===== SUBFLOW FEATURES (4) =====
        print("  ✓ Subflow features...")
        features_df['subflow_fwd_packets'] = df.get('Subflow Fwd Packets', 0)
        features_df['subflow_fwd_bytes'] = df.get('Subflow Fwd Bytes', 0)
        features_df['subflow_bwd_packets'] = df.get('Subflow Bwd Packets', 0)
        features_df['subflow_bwd_bytes'] = df.get('Subflow Bwd Bytes', 0)
        
        # ===== ACTIVE/IDLE TIME FEATURES (4) =====
        print("  ✓ Active/idle time features...")
        features_df['active_mean'] = df.get('Active Mean', 0)
        features_df['active_std'] = df.get('Active Std', 0)
        features_df['idle_mean'] = df.get('Idle Mean', 0)
        features_df['idle_std'] = df.get('Idle Std', 0)
        
        # ===== DERIVED RATIO FEATURES (10) =====
        print("  ✓ Derived ratio features...")
        
        # Forward/Backward ratios
        features_df['fwd_bwd_packet_ratio'] = np.where(
            features_df['total_bwd_packets'] > 0,
            features_df['total_fwd_packets'] / features_df['total_bwd_packets'],
            features_df['total_fwd_packets']
        )
        
        features_df['fwd_bwd_bytes_ratio'] = np.where(
            features_df['total_bwd_bytes'] > 0,
            features_df['total_fwd_bytes'] / features_df['total_bwd_bytes'],
            features_df['total_fwd_bytes']
        )
        
        # Port ratios
        features_df['port_src_dst_ratio'] = np.where(
            features_df['dst_port'] > 0,
            features_df['src_port'] / features_df['dst_port'],
            features_df['src_port']
        )
        
        # Header to payload ratio
        total_header_length = features_df['fwd_header_length'] + features_df['bwd_header_length']
        features_df['header_payload_ratio'] = np.where(
            features_df['total_bytes'] > 0,
            total_header_length / features_df['total_bytes'],
            0
        )
        
        # Packet efficiency
        features_df['packet_efficiency'] = np.where(
            features_df['total_packets'] > 0,
            features_df['total_bytes'] / (features_df['total_packets'] * 1500),  # MTU = 1500
            0
        )
        
        # Flag density
        total_flags = (features_df['syn_flag_count'] + features_df['fin_flag_count'] + 
                      features_df['rst_flag_count'] + features_df['psh_flag_count'] + 
                      features_df['ack_flag_count'] + features_df['urg_flag_count'])
        
        features_df['flag_density'] = np.where(
            features_df['total_packets'] > 0,
            total_flags / features_df['total_packets'],
            0
        )
        
        # Symmetry measure
        features_df['flow_symmetry'] = 1 - abs(
            features_df['total_fwd_packets'] - features_df['total_bwd_packets']
        ) / (features_df['total_packets'] + 1)
        
        # Burstiness
        features_df['burstiness'] = np.where(
            features_df['flow_iat_mean'] > 0,
            features_df['flow_iat_std'] / features_df['flow_iat_mean'],
            0
        )
        
        # Duration per byte
        features_df['duration_per_byte'] = np.where(
            features_df['total_bytes'] > 0,
            features_df['flow_duration'] / features_df['total_bytes'],
            0
        )
        
        # Duration per packet
        features_df['duration_per_packet'] = np.where(
            features_df['total_packets'] > 0,
            features_df['flow_duration'] / features_df['total_packets'],
            0
        )
        
        # ===== BEHAVIORAL FEATURES (5) =====
        print("  ✓ Behavioral features...")
        
        # Is common port (HTTP, HTTPS, DNS, SSH, FTP)
        common_ports = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080]
        features_df['is_common_port'] = features_df['dst_port'].isin(common_ports).astype(int)
        
        # Is privileged port
        features_df['is_privileged_port'] = (features_df['dst_port'] < 1024).astype(int)
        
        # Is well-known protocol (TCP=6, UDP=17, ICMP=1)
        features_df['is_tcp'] = (features_df['protocol'] == 6).astype(int)
        features_df['is_udp'] = (features_df['protocol'] == 17).astype(int)
        
        # Packet size anomaly (very small or very large)
        features_df['has_size_anomaly'] = (
            (features_df['avg_packet_size'] < 60) |  # Too small
            (features_df['avg_packet_size'] > 1400)  # Too large
        ).astype(int)
        
        # ===== LABEL (TARGET) =====
        if 'label' in df.columns:
            # Map all attack types to binary classification
            features_df['label'] = df['label'].apply(
                lambda x: 0 if x == 'BENIGN' else 1
            )
            
            # Keep attack type for reference
            features_df['attack_type'] = df['label']
        
        # Clean data
        print("  ✓ Cleaning features...")
        features_df = features_df.replace([np.inf, -np.inf], 0)
        features_df = features_df.fillna(0)
        
        # Store feature names
        self.feature_names = [col for col in features_df.columns if col not in ['label', 'attack_type']]
        
        print(f"\n✓ Extracted {len(self.feature_names)} features")
        
        return features_df
    
    def get_feature_importance_groups(self):
        """Group features by category for analysis"""
        return {
            'Basic Flow': [
                'flow_duration', 'total_fwd_packets', 'total_bwd_packets', 
                'total_packets', 'total_fwd_bytes', 'total_bwd_bytes', 
                'total_bytes', 'src_port', 'dst_port', 'protocol'
            ],
            'Packet Size': [
                'fwd_packet_length_max', 'fwd_packet_length_min', 
                'fwd_packet_length_mean', 'fwd_packet_length_std',
                'bwd_packet_length_max', 'bwd_packet_length_min',
                'bwd_packet_length_mean', 'bwd_packet_length_std'
            ],
            'Flow Rate': [
                'flow_bytes_per_second', 'flow_packets_per_second',
                'fwd_packets_per_second', 'bwd_packets_per_second',
                'avg_packet_size', 'packet_size_variance'
            ],
            'Inter-Arrival Time': [
                'flow_iat_mean', 'flow_iat_std', 'flow_iat_max', 'flow_iat_min',
                'fwd_iat_mean', 'fwd_iat_std', 'bwd_iat_mean', 'bwd_iat_std'
            ],
            'TCP Flags': [
                'fin_flag_count', 'syn_flag_count', 'rst_flag_count',
                'psh_flag_count', 'ack_flag_count', 'urg_flag_count'
            ],
            'Ratios & Derived': [
                'fwd_bwd_packet_ratio', 'fwd_bwd_bytes_ratio', 'port_src_dst_ratio',
                'header_payload_ratio', 'packet_efficiency', 'flag_density',
                'flow_symmetry', 'burstiness', 'duration_per_byte', 'duration_per_packet'
            ],
            'Behavioral': [
                'is_common_port', 'is_privileged_port', 'is_tcp', 'is_udp', 'has_size_anomaly'
            ]
        }
    
    def print_feature_summary(self):
        """Print summary of extracted features"""
        groups = self.get_feature_importance_groups()
        
        print("\n" + "=" * 60)
        print("FEATURE SUMMARY")
        print("=" * 60)
        
        total = 0
        for group_name, features in groups.items():
            count = len(features)
            total += count
            print(f"\n{group_name}: {count} features")
            for i, feat in enumerate(features, 1):
                print(f"  {i}. {feat}")
        
        print(f"\n{'='*60}")
        print(f"TOTAL FEATURES: {total}")
        print(f"{'='*60}\n")


# Example usage
if __name__ == '__main__':
    print("""
╔══════════════════════════════════════════════════════════╗
║     Enhanced Feature Extraction                          ║
║     50+ Features from CIC-IDS 2017                       ║
╚══════════════════════════════════════════════════════════╝
    """)
    
    extractor = EnhancedFeatureExtractor()
    extractor.print_feature_summary()
    
    print("\nNext step: Run setup_cicids_dataset.py to process the dataset!")