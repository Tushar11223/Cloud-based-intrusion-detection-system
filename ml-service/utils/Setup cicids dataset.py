#!/usr/bin/env python3
"""
Integrated Dataset Processor
Works with your EXISTING malware detection project
Converts CIC-IDS 2017 to your FlowLog format
"""

import pandas as pd
import numpy as np
import json
from datetime import datetime, timedelta
from pathlib import Path

class IntegratedDatasetProcessor:
    """Convert CIC-IDS to your existing FlowLog MongoDB format"""
    
    def __init__(self):
        self.protocol_map = {
            'tcp': 6,
            'udp': 17,
            'icmp': 1
        }
    
    def cicids_to_flowlog(self, df):
        """
        Convert CIC-IDS 2017 DataFrame to your FlowLog format
        Matches your existing MongoDB schema exactly
        """
        print(f"🔄 Converting {len(df):,} CIC-IDS rows to FlowLog format...")
        
        flow_logs = []
        base_time = datetime.now()
        
        for idx, row in df.iterrows():
            if idx % 1000 == 0:
                print(f"  Progress: {idx:,}/{len(df):,} ({idx/len(df)*100:.1f}%)", end='\r')
            
            # Generate FlowLog matching your schema
            flow_log = {
                # MongoDB will add _id automatically
                'flowId': f'cicids-{idx}-{datetime.now().timestamp()}',
                'timestamp': (base_time + timedelta(seconds=idx)).isoformat(),
                
                # Source/Destination
                'srcAddr': row.get('Source IP', row.get('Src IP', '192.168.1.1')),
                'dstAddr': row.get('Destination IP', row.get('Dst IP', '8.8.8.8')),
                'srcPort': int(row.get('Source Port', row.get('Src Port', 0))),
                'dstPort': int(row.get('Destination Port', row.get('Dst Port', 0))),
                
                # Protocol
                'protocol': int(row.get('Protocol', 6)),  # Default TCP
                
                # Traffic metrics
                'packets': int(
                    float(row.get('Total Fwd Packets', row.get('Total Fwd Packet', 0))) + 
                    float(row.get('Total Backward Packets', row.get('Total Backward Packet', 0)))
                ),
                'bytes': int(
                    float(row.get('Total Length of Fwd Packets', row.get('Total Length of Fwd Packet', 0))) + 
                    float(row.get('Total Length of Bwd Packets', row.get('Total Length of Bwd Packet', 0)))
                ),
                
                # Duration (convert from microseconds to seconds)
                'duration': float(row.get('Flow Duration', 0)) / 1000000.0,
                
                # Action (assume accepted unless explicitly rejected)
                'action': 'ACCEPT',
                
                # TCP Flags
                'tcpFlags': self._extract_tcp_flags(row),
                
                # Label (ground truth)
                'actualLabel': 'BENIGN' if row.get('Label', '').strip() == 'BENIGN' else 'MALWARE',
                
                # Pattern type (for reference)
                'patternType': self._map_attack_type(row.get('Label', 'UNKNOWN')),
                
                # Analysis fields (initially unanalyzed)
                'analyzed': False,
                'detectedAs': 'PENDING',
                'mlPrediction': None,
                'mlConfidence': None,
                'ruleMatches': [],
                
                # Source indicator
                'source': 'CIC-IDS-2017'
            }
            
            flow_logs.append(flow_log)
        
        print(f"\n✅ Converted {len(flow_logs):,} flow logs")
        return flow_logs
    
    def _extract_tcp_flags(self, row):
        """Extract TCP flags from CIC-IDS row"""
        flags = []
        
        if int(row.get('SYN Flag Count', 0)) > 0:
            flags.append('SYN')
        if int(row.get('FIN Flag Count', 0)) > 0:
            flags.append('FIN')
        if int(row.get('RST Flag Count', 0)) > 0:
            flags.append('RST')
        if int(row.get('PSH Flag Count', 0)) > 0:
            flags.append('PSH')
        if int(row.get('ACK Flag Count', 0)) > 0:
            flags.append('ACK')
        if int(row.get('URG Flag Count', 0)) > 0:
            flags.append('URG')
        
        return ','.join(flags) if flags else ''
    
    def _map_attack_type(self, label):
        """Map CIC-IDS labels to your pattern types"""
        label = str(label).strip()
        
        if label == 'BENIGN':
            return 'BENIGN'
        elif 'PortScan' in label:
            return 'PORT_SCAN'
        elif 'Bot' in label:
            return 'C2_BEACONING'
        elif 'Infiltration' in label:
            return 'DATA_EXFILTRATION'
        elif 'DoS' in label or 'DDoS' in label:
            return 'DOS_ATTACK'
        elif 'Brute Force' in label or 'FTP-Patator' in label or 'SSH-Patator' in label:
            return 'BRUTE_FORCE'
        elif 'Web Attack' in label:
            return 'WEB_ATTACK'
        else:
            return 'MALWARE'  # Generic malware for others
    
    def load_and_convert(self, csv_path, output_path=None, sample_size=None):
        """
        Load CIC-IDS CSV and convert to FlowLog format
        
        Args:
            csv_path: Path to CIC-IDS CSV file
            output_path: Where to save JSON (optional)
            sample_size: Number of samples to use (None = all)
        """
        print(f"\n📂 Loading CIC-IDS dataset from {csv_path}...")
        
        # Load CSV
        df = pd.read_csv(csv_path, encoding='latin-1', low_memory=False)
        
        print(f"✅ Loaded {len(df):,} rows")
        
        # Clean column names
        df.columns = df.columns.str.strip()
        
        # Handle infinite values
        df = df.replace([np.inf, -np.inf], 0)
        df = df.fillna(0)
        
        # Sample if requested
        if sample_size and sample_size < len(df):
            print(f"📊 Sampling {sample_size:,} rows...")
            df = df.sample(n=sample_size, random_state=42)
        
        # Show label distribution
        print("\n📊 Label Distribution:")
        label_counts = df['Label'].value_counts() if 'Label' in df.columns else df[' Label'].value_counts()
        for label, count in label_counts.items():
            print(f"  {label}: {count:,}")
        
        # Convert to FlowLog format
        flow_logs = self.cicids_to_flowlog(df)
        
        # Save to JSON if path provided
        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            print(f"\n💾 Saving to {output_path}...")
            with open(output_path, 'w') as f:
                json.dump(flow_logs, f, indent=2)
            
            file_size = output_path.stat().st_size / (1024 * 1024)
            print(f"✅ Saved {len(flow_logs):,} flow logs ({file_size:.1f} MB)")
        
        return flow_logs
    
    def import_to_mongodb(self, flow_logs, mongo_uri='mongodb://localhost:27017', 
                         db_name='malware_detection', collection_name='flow_logs'):
        """
        Import flow logs directly to MongoDB
        """
        try:
            from pymongo import MongoClient
            
            print(f"\n🔌 Connecting to MongoDB...")
            client = MongoClient(mongo_uri)
            db = client[db_name]
            collection = db[collection_name]
            
            print(f"📥 Inserting {len(flow_logs):,} documents...")
            
            # Insert in batches to avoid memory issues
            batch_size = 1000
            for i in range(0, len(flow_logs), batch_size):
                batch = flow_logs[i:i+batch_size]
                collection.insert_many(batch)
                print(f"  Inserted {min(i+batch_size, len(flow_logs)):,}/{len(flow_logs):,}", end='\r')
            
            print(f"\n✅ Successfully imported to MongoDB!")
            print(f"   Database: {db_name}")
            print(f"   Collection: {collection_name}")
            print(f"   Documents: {collection.count_documents({}):,}")
            
            client.close()
            return True
            
        except ImportError:
            print("❌ pymongo not installed. Install with: pip install pymongo")
            return False
        except Exception as e:
            print(f"❌ MongoDB import failed: {e}")
            return False


def main():
    """Main execution"""
    print("""
╔══════════════════════════════════════════════════════════╗
║     CIC-IDS Dataset Integration                          ║
║     Convert to Your Existing FlowLog Format              ║
╚══════════════════════════════════════════════════════════╝
    """)
    
    processor = IntegratedDatasetProcessor()
    
    # Example paths - CHANGE THESE TO YOUR ACTUAL PATHS
    csv_path = 'datasets/cic-ids-2017/raw/Monday-WorkingHours.pcap_ISCX.csv'
    output_json = 'datasets/cic-ids-2017/converted/flowlogs.json'
    
    # Check if file exists
    if not Path(csv_path).exists():
        print(f"❌ File not found: {csv_path}")
        print("\n📥 Please:")
        print("1. Download CIC-IDS 2017 from: https://www.unb.ca/cic/datasets/ids-2017.html")
        print("2. Place CSV files in: datasets/cic-ids-2017/raw/")
        print("3. Update csv_path in this script")
        print("\n💡 Or use a smaller sample for testing:")
        print("   - Just download Monday's file (~500MB)")
        print("   - Update csv_path above")
        return
    
    # Convert dataset
    flow_logs = processor.load_and_convert(
        csv_path=csv_path,
        output_path=output_json,
        sample_size=10000  # Start with 10K samples for testing
    )
    
    # Import to MongoDB (optional)
    print("\n❓ Import to MongoDB? (y/n): ", end='')
    choice = input().lower()
    
    if choice == 'y':
        processor.import_to_mongodb(flow_logs)
    
    print("\n" + "="*60)
    print("✅ CONVERSION COMPLETE!")
    print("="*60)
    print(f"\n📄 JSON file: {output_json}")
    print(f"📊 Flow logs: {len(flow_logs):,}")
    print("\nNext steps:")
    print("1. Import to MongoDB (if not done)")
    print("2. Run analysis with your existing backend")
    print("3. Compare with synthetic logs")
    print("="*60)


if __name__ == '__main__':
    main()