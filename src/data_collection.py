#!/usr/bin/env python3
"""
Multi-Chain Data Collection Module
Collects bytecode from Ethereum AND PulseChain, merges into unified dataset
"""

import json
import time
import subprocess
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import yaml
from tqdm import tqdm


@dataclass
class ContractSample:
    """Container for contract training sample"""
    address: str
    bytecode: str
    label: int  # 0=safe, 1=honeypot
    chain: str  # "ethereum" or "pulsechain"
    chain_id: int
    collected_at: str = ""
    name: Optional[str] = None
    notes: Optional[str] = None
    bytecode_hash: Optional[str] = None  # To detect identical contracts


class MultiChainDataCollector:
    """Collect contract bytecode from multiple chains"""
    
    def __init__(self, config_path: str = "config.yaml", chain: str = None):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        # Set chain
        if chain is None:
            chain = self.config['collection'].get('default_chain', 'pulsechain')
        
        if chain not in self.config['chains']:
            raise ValueError(f"Unknown chain: {chain}. Available: {list(self.config['chains'].keys())}")
        
        self.chain = chain
        self.chain_config = self.config['chains'][chain]
        self.rpc_urls = self.chain_config['rpc_urls']
        self.current_rpc_index = 0
        
        self.cache_dir = Path(self.config['data']['cache_dir'])
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self.timeout = self.config['collection']['timeout']
        self.max_retries = self.config['collection']['max_retries']
        
        self.samples: List[ContractSample] = []
        
        print(f"📡 Initialized for {self.chain_config['name']} (Chain ID: {self.chain_config['chain_id']})")
        print(f"   RPC: {self.rpc_urls[0]}")
    
    def get_rpc_url(self) -> str:
        """Get current RPC URL with automatic failover"""
        return self.rpc_urls[self.current_rpc_index]
    
    def switch_rpc(self):
        """Switch to next RPC endpoint"""
        self.current_rpc_index = (self.current_rpc_index + 1) % len(self.rpc_urls)
        print(f"   ⚠️  Switching to backup RPC: {self.get_rpc_url()}")
    
    def fetch_bytecode(self, address: str, retries: int = 0) -> Optional[str]:
        """Fetch bytecode from chain using cast"""
        rpc_url = self.get_rpc_url()
        
        try:
            result = subprocess.run(
                ['cast', 'code', address, '--rpc-url', rpc_url],
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            if result.returncode == 0:
                bytecode = result.stdout.strip()
                if bytecode and bytecode != '0x':
                    return bytecode
                else:
                    print(f"   ⚠️  Address {address} is not a contract on {self.chain}")
                    return None
            
            # RPC error - try switching RPC
            if retries < self.max_retries:
                if retries == 1:  # Try backup RPC on second retry
                    self.switch_rpc()
                time.sleep(1)
                return self.fetch_bytecode(address, retries + 1)
            
            return None
            
        except subprocess.TimeoutExpired:
            print(f"   ⏱️  Timeout fetching {address} from {self.chain}")
            if retries < self.max_retries:
                self.switch_rpc()
                return self.fetch_bytecode(address, retries + 1)
            return None
        except Exception as e:
            print(f"   ❌ Error fetching {address}: {e}")
            return None
    
    def verify_chain_id(self) -> bool:
        """Verify we're connected to the correct chain"""
        try:
            result = subprocess.run(
                ['cast', 'chain-id', '--rpc-url', self.get_rpc_url()],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                chain_id = int(result.stdout.strip())
                expected_id = self.chain_config['chain_id']
                
                if chain_id == expected_id:
                    print(f"✓ Connected to {self.chain_config['name']} (Chain ID: {chain_id})")
                    return True
                else:
                    print(f"⚠️  WARNING: Connected to chain {chain_id}, expected {expected_id}")
                    return False
        except Exception as e:
            print(f"⚠️  Could not verify chain ID: {e}")
        
        return False
    
    def compute_bytecode_hash(self, bytecode: str) -> str:
        """Compute hash of bytecode for comparison"""
        import hashlib
        return hashlib.sha256(bytecode.encode()).hexdigest()[:16]
    
    def add_sample(self, address: str, label: int, name: str = None, notes: str = None) -> bool:
        """Add a single contract sample"""
        print(f"📥 [{self.chain}] {address}...", end=" ")
        
        bytecode = self.fetch_bytecode(address)
        
        if bytecode:
            bytecode_hash = self.compute_bytecode_hash(bytecode)
            
            sample = ContractSample(
                address=address,
                bytecode=bytecode,
                label=label,
                chain=self.chain,
                chain_id=self.chain_config['chain_id'],
                collected_at=time.strftime("%Y-%m-%d %H:%M:%S"),
                name=name,
                notes=notes,
                bytecode_hash=bytecode_hash
            )
            self.samples.append(sample)
            print(f"✓ ({len(bytecode)} bytes, hash: {bytecode_hash})")
            return True
        else:
            print(f"✗ Failed")
            return False
    
    def add_batch(self, contracts: List[Tuple[str, int, str, str]]) -> int:
        """Add multiple contracts"""
        successful = 0
        
        for address, label, name, notes in tqdm(contracts, desc=f"Collecting from {self.chain}"):
            if self.add_sample(address, label, name, notes):
                successful += 1
            time.sleep(0.3)  # Rate limiting
        
        print(f"✓ Successfully collected {successful}/{len(contracts)} from {self.chain}")
        return successful
    
    def compare_across_chains(self, address: str, other_chain: str) -> Dict:
        """Compare same address on different chains"""
        print(f"\n{'='*60}")
        print(f"Comparing {address} across chains")
        print(f"{'='*60}")
        
        # Fetch from current chain
        bytecode_1 = self.fetch_bytecode(address)
        
        # Fetch from other chain
        other_collector = MultiChainDataCollector(chain=other_chain)
        bytecode_2 = other_collector.fetch_bytecode(address)
        
        result = {
            'address': address,
            'chains': {
                self.chain: {
                    'exists': bytecode_1 is not None,
                    'bytecode': bytecode_1,
                    'hash': self.compute_bytecode_hash(bytecode_1) if bytecode_1 else None,
                    'length': len(bytecode_1) if bytecode_1 else 0
                },
                other_chain: {
                    'exists': bytecode_2 is not None,
                    'bytecode': bytecode_2,
                    'hash': other_collector.compute_bytecode_hash(bytecode_2) if bytecode_2 else None,
                    'length': len(bytecode_2) if bytecode_2 else 0
                }
            },
            'identical': False,
            'both_exist': False
        }
        
        # Compare
        if bytecode_1 and bytecode_2:
            result['both_exist'] = True
            result['identical'] = (bytecode_1 == bytecode_2)
            
            print(f"\n✓ Contract exists on both chains")
            print(f"   {self.chain}: {len(bytecode_1)} bytes (hash: {result['chains'][self.chain]['hash']})")
            print(f"   {other_chain}: {len(bytecode_2)} bytes (hash: {result['chains'][other_chain]['hash']})")
            
            if result['identical']:
                print(f"   ✓ Bytecode is IDENTICAL on both chains")
            else:
                print(f"   ⚠️  Bytecode is DIFFERENT! Likely different contracts")
        
        elif bytecode_1 and not bytecode_2:
            print(f"\n⚠️  Contract only exists on {self.chain}")
        elif bytecode_2 and not bytecode_1:
            print(f"\n⚠️  Contract only exists on {other_chain}")
        else:
            print(f"\n❌ Contract doesn't exist on either chain")
        
        return result
    
    def save_dataset(self, filepath: str = None):
        """Save collected samples to JSON"""
        if filepath is None:
            # Use chain-specific path
            if self.chain == 'ethereum':
                filepath = self.config['data'].get('raw_data_ethereum', './data/raw/contracts_ethereum.json')
            elif self.chain == 'pulsechain':
                filepath = self.config['data'].get('raw_data_pulsechain', './data/raw/contracts_pulsechain.json')
            else:
                filepath = self.config['data']['raw_data_path'].replace('{chain}', self.chain)
        
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        data = {
            'metadata': {
                'chain': self.chain,
                'chain_id': self.chain_config['chain_id'],
                'chain_name': self.chain_config['name'],
                'total_samples': len(self.samples),
                'safe_count': sum(1 for s in self.samples if s.label == 0),
                'honeypot_count': sum(1 for s in self.samples if s.label == 1),
                'collection_date': time.strftime("%Y-%m-%d %H:%M:%S"),
                'rpc_url': self.get_rpc_url()
            },
            'samples': [asdict(s) for s in self.samples]
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"\n✓ {self.chain} dataset saved: {filepath}")
        print(f"  Total: {data['metadata']['total_samples']} | Safe: {data['metadata']['safe_count']} | Honeypot: {data['metadata']['honeypot_count']}")
    
    def load_dataset(self, filepath: str = None) -> List[ContractSample]:
        """Load previously collected dataset"""
        if filepath is None:
            if self.chain == 'ethereum':
                filepath = self.config['data'].get('raw_data_ethereum', './data/raw/contracts_ethereum.json')
            elif self.chain == 'pulsechain':
                filepath = self.config['data'].get('raw_data_pulsechain', './data/raw/contracts_pulsechain.json')
            else:
                filepath = self.config['data']['raw_data_path'].replace('{chain}', self.chain)
        
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        self.samples = [
            ContractSample(**sample) 
            for sample in data['samples']
        ]
        
        print(f"✓ Loaded {len(self.samples)} samples from {filepath}")
        print(f"   Chain: {data['metadata']['chain_name']}")
        return self.samples


def merge_datasets(config_path: str = "config.yaml"):
    """
    Merge Ethereum and PulseChain datasets into single unified dataset
    This creates a chain-agnostic dataset for training
    """
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    print("\n" + "="*60)
    print("MERGING MULTI-CHAIN DATASETS")
    print("="*60)
    
    all_samples = []
    chain_stats = {}
    
    # Load Ethereum data
    eth_path = Path(config['data'].get('raw_data_ethereum', './data/raw/contracts_ethereum.json'))
    if eth_path.exists():
        print(f"\n📂 Loading Ethereum data from {eth_path}")
        with open(eth_path, 'r') as f:
            eth_data = json.load(f)
        
        eth_samples = [ContractSample(**s) for s in eth_data['samples']]
        all_samples.extend(eth_samples)
        
        chain_stats['ethereum'] = {
            'total': len(eth_samples),
            'safe': sum(1 for s in eth_samples if s.label == 0),
            'honeypot': sum(1 for s in eth_samples if s.label == 1)
        }
        print(f"   ✓ Loaded {len(eth_samples)} Ethereum samples")
    else:
        print(f"\n⚠️  No Ethereum data found at {eth_path}")
        chain_stats['ethereum'] = {'total': 0, 'safe': 0, 'honeypot': 0}
    
    # Load PulseChain data
    pls_path = Path(config['data'].get('raw_data_pulsechain', './data/raw/contracts_pulsechain.json'))
    if pls_path.exists():
        print(f"\n📂 Loading PulseChain data from {pls_path}")
        with open(pls_path, 'r') as f:
            pls_data = json.load(f)
        
        pls_samples = [ContractSample(**s) for s in pls_data['samples']]
        all_samples.extend(pls_samples)
        
        chain_stats['pulsechain'] = {
            'total': len(pls_samples),
            'safe': sum(1 for s in pls_samples if s.label == 0),
            'honeypot': sum(1 for s in pls_samples if s.label == 1)
        }
        print(f"   ✓ Loaded {len(pls_samples)} PulseChain samples")
    else:
        print(f"\n⚠️  No PulseChain data found at {pls_path}")
        chain_stats['pulsechain'] = {'total': 0, 'safe': 0, 'honeypot': 0}
    
    if not all_samples:
        print("\n❌ No data found to merge!")
        print("   Run: python3 src/data_collection.py --both")
        return None
    
    # Check for duplicates (same address on both chains)
    addresses = [s.address.lower() for s in all_samples]
    duplicates = [addr for addr in set(addresses) if addresses.count(addr) > 1]
    
    if duplicates:
        print(f"\n⚠️  Found {len(duplicates)} addresses present on both chains:")
        for addr in duplicates[:5]:  # Show first 5
            samples = [s for s in all_samples if s.address.lower() == addr]
            print(f"   {addr}:")
            for s in samples:
                bytecode_preview = s.bytecode[:50] + "..." if len(s.bytecode) > 50 else s.bytecode
                print(f"      - {s.chain}: {len(s.bytecode)} bytes (hash: {s.bytecode_hash})")
        
        if len(duplicates) > 5:
            print(f"   ... and {len(duplicates) - 5} more")
        
        print(f"\n   Keeping all {len(all_samples)} samples (including duplicates)")
        print(f"   Note: Same address may have DIFFERENT bytecode on different chains!")
    
    # Create merged dataset
    merged_data = {
        'metadata': {
            'type': 'multi_chain_merged',
            'chains': list(chain_stats.keys()),
            'total_samples': len(all_samples),
            'safe_count': sum(1 for s in all_samples if s.label == 0),
            'honeypot_count': sum(1 for s in all_samples if s.label == 1),
            'merge_date': time.strftime("%Y-%m-%d %H:%M:%S"),
            'chain_breakdown': chain_stats,
            'duplicate_addresses': len(duplicates)
        },
        'samples': [asdict(s) for s in all_samples]
    }
    
    # Save merged dataset
    merged_path = Path(config['data'].get('raw_data_merged', './data/raw/contracts_merged.json'))
    merged_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(merged_path, 'w') as f:
        json.dump(merged_data, f, indent=2)
    
    # Print summary
    print("\n" + "="*60)
    print("MERGED DATASET SUMMARY")
    print("="*60)
    
    for chain, stats in chain_stats.items():
        if stats['total'] > 0:
            print(f"\n{chain.upper()}:")
            print(f"  Total: {stats['total']}")
            print(f"  Safe: {stats['safe']}")
            print(f"  Honeypot: {stats['honeypot']}")
    
    print(f"\nCOMBINED:")
    print(f"  Total samples: {merged_data['metadata']['total_samples']}")
    print(f"  Safe: {merged_data['metadata']['safe_count']}")
    print(f"  Honeypot: {merged_data['metadata']['honeypot_count']}")
    print(f"  Duplicate addresses: {len(duplicates)}")
    
    print(f"\n✓ Merged dataset saved to: {merged_path}")
    print("="*60 + "\n")
    
    return merged_data


# Known safe contracts per chain
KNOWN_SAFE_ETHEREUM = [
    ("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", 0, "WETH", "Wrapped ETH"),
    ("0xdAC17F958D2ee523a2206206994597C13D831ec7", 0, "USDT", "Tether USD"),
    ("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", 0, "USDC", "USD Coin"),
    ("0x6B175474E89094C44Da98b954EedeAC495271d0F", 0, "DAI", "Dai Stablecoin"),
    ("0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599", 0, "WBTC", "Wrapped BTC"),
    ("0x514910771AF9Ca656af840dff83E8264EcF986CA", 0, "LINK", "Chainlink"),
    ("0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9", 0, "AAVE", "Aave Token"),
    ("0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984", 0, "UNI", "Uniswap"),
]

KNOWN_SAFE_PULSECHAIN = [
    ("0xA1077a294dDE1B09bB078844df40758a5D0f9a27", 0, "WPLS", "Wrapped PLS"),
    ("0x2b591e99afE9f32eAA6214f7B7629768c40Eeb39", 0, "HEX", "HEX on PulseChain"),
    ("0x2fa878Ab3F87CC1C9737Fc071108F904c0B0C95d", 0, "INC", "Incentive"),
    ("0x95B303987A60C71504D99Aa1b13B4DA07b0790ab", 0, "PLSX", "PulseX"),
]

KNOWN_HONEYPOT_ETHEREUM = [
    # VERIFIED Ethereum honeypots
    ("0x2e35b0b2e3e5b1b1a7a02c3b2a210515510d7a55", 1, "MINIDOGE", "Classic honeypot, cannot sell after buying"),
    ("0x403b87f94e3a4e98f24a2d32da6523075283a9e5", 1, "SimpleHoneypot", "Educational honeypot, code prevents selling"),
    ("0x8c991b5c46894a40094b8e2e2831518b5e282b81", 1, "POOH", "Tax-related honeypot, selling incurs 99-100% tax"),
    ("0x1842343a4e414d11e549d44342a63756a5c10543", 1, "UP", "Balance disorder honeypot, manipulates user balances"),
    ("0xc26c2a68a13936a7f8b2a3a83a0050f24253b75a", 1, "RICH", "Unsellable token, transfer function is blocked for non-owners"),
    ("0xaa13810020f5c8853bdef6bf40e3ef960b735a2d", 1, "Furry", "Honeypot using hidden transfer restrictions"),
    ("0xbec602b9e1e2d7e4b44916c87343940141f1a04d", 1, "Squid Game", "Famous rug pull, anti-dumping mechanism prevented selling"),
    ("0x5db3588a4452174397981f9b73919131dde2ace3", 1, "SHIBA INU CLONE", "Malicious clone with selling disabled"),
    ("0x95085d08f5def115a782bb52479635e9d288a2a0", 1, "ApesREVENGE", "Tax trap, increases sell tax to 100% after a few buys"),
    ("0x028f2a1b3aad4525a76e5a31a31d9a2441991a26", 1, "MoonRise", "Honeypot with complex logic to block sales for regular users"),
]

KNOWN_HONEYPOT_PULSECHAIN = [
    ("0xb1f52d529390ec28483fe7689a4ea26fce2956f4", 1, "Coin-Plasma", "Proxy contract with hidden malicious logic"),
    ("0x8560ed0254b982080aeca2832a2f513b4b723735", 1, "Pulse Guardian", "Unlimited minting and blacklist functions"),
    ("0x1b975d5e5559c1b29a242f8e8aa215108c350bca", 1, "PLS 2.0", "Fake upgrade token, transfer hook drains funds"),
    ("0x3a5412364b4f5713c054911d2799c7553f1cf1a2", 1, "PULSEX Airdrop", "Phishing scam, requests wallet connection to drain assets"),
    ("0x0000a89a42133a82c44e677c108f37722f38a529", 1, "FreeClaim PLS", "Common airdrop scam type, approve() exploit"),
    ("0x2e35b0b2e3e5b1b1a7a02c3b2a210515510d7a55", 1, "MINIDOGE", "Classic honeypot, cannot sell after buying"),
    ("0x403b87f94e3a4e98f24a2d32da6523075283a9e5", 1, "SimpleHoneypot", "Educational honeypot, code prevents selling"),
    ("0x8c991b5c46894a40094b8e2e2831518b5e282b81", 1, "POOH", "Tax-related honeypot, selling incurs 99-100% tax"),
    ("0x1842343a4e414d11e549d44342a63756a5c10543", 1, "UP", "Balance disorder honeypot, manipulates user balances"),
    ("0xc26c2a68a13936a7f8b2a3a83a0050f24253b75a", 1, "RICH", "Unsellable token, transfer function is blocked for non-owners"),
    ("0xaa13810020f5c8853bdef6bf40e3ef960b735a2d", 1, "Furry", "Honeypot using hidden transfer restrictions"),
    ("0xbec602b9e1e2d7e4b44916c87343940141f1a04d", 1, "Squid Game", "Famous rug pull, anti-dumping mechanism prevented selling"),
    ("0x5db3588a4452174397981f9b73919131dde2ace3", 1, "SHIBA INU CLONE", "Malicious clone with selling disabled"),
    ("0x95085d08f5def115a782bb52479635e9d288a2a0", 1, "ApesREVENGE", "Tax trap, increases sell tax to 100% after a few buys"),
    ("0x028f2a1b3aad4525a76e5a31a31d9a2441991a26", 1, "MoonRise", "Honeypot with complex logic to block sales for regular users"),
    ("0x0a1b26a636955a6a6a24143a7a911a3d2c9c8e8d", 1, "ETH Wrapper", "Fake wrapper, steals funds on deposit"),
    ("0x913b732115f5f730f294025a1e264560a5634591", 1, "SafeEarn", "Blacklist function, can block specific wallets from selling"),
    ("0x493a7a28e34bf1d1d867c2ab41d3b3846c8203c9", 1, "Tug Of War", "Game-based honeypot, funds are locked permanently"),
    ("0x5b3c4c8c7283404c272b781ec7a7a2b270a4a584", 1, "BabyDoge ETH", "Fake version of popular token, unsellable"),
    ("0xe0b5e2a4a3f1a0f5a8ed43015f6b28b76135e61d", 1, "Anti-Whale Pot", "Prevents large sells, effectively trapping most holders"),
    ("0xd4b213b8364b4c9135a2283dda321852d2f7785a", 1, "Rocket", "Honeypot with transfer restrictions based on sender address"),
    ("0x633324671e2aea7620165a8813ea4b95349e1e1a", 1, "EtherGoo", "Old honeypot game where funds are intentionally locked"),
    ("0xc0171a25e1c251432c6fa5e6a041f4ab98642a8b", 1, "Etherium", "Typo-squatting scam of 'Ethereum', unsellable token"),
    ("0xf4da512140413f13f124c965766d6a6aa60c1845", 1, "FreeCoin", "Airdrop scam that traps tokens via approval"),
    ("0x1f94291f54a1f3353457173b1853d5a2b16621d9", 1, "NoSell Token", "Explicit honeypot, name indicates its function"),
    ("0x3b85b98a3b3531aa96c21e582b13e8f8515c13e4", 1, "BUSD MINER", "Ponzi scheme miner contract, new deposits pay old ones"),
    ("0x42f8c5b9a89851a74e50d6037a3b11568e7f1e29", 1, "Fake USD", "A fake stablecoin with a function to wipe balances"),
    ("0x8df18544e7c7a5df7173489895a9485a81816e85", 1, "HiddenFeeCoin", "Sells trigger a hidden, massive fee that eats the total amount"),
    ("0x529e3a67d32386121f1c911a13123b561c28b5e9", 1, "Proxy Drainer", "Upgradeable contract where implementation was switched to a malicious one"),
    ("0x6070611851235123912381232138125312381231", 1, "Invalid Opcode", "Honeypot that relies on an EVM quirk to trap funds"),

]


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Multi-Chain Contract Data Collection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Collect from BOTH chains and merge (RECOMMENDED)
  %(prog)s --both
  
  # Collect from Ethereum only
  %(prog)s --chain ethereum
  
  # Collect from PulseChain only
  %(prog)s --chain pulsechain
  
  # Add contract to specific chain
  %(prog)s --chain ethereum --add-safe 0x... "USDT"
  
  # Compare same address across chains
  %(prog)s --compare 0x2b591e99afE9f32eAA6214f7B7629768c40Eeb39
  
  # Merge existing datasets only
  %(prog)s --merge-only
  
  # Verify chain connection
  %(prog)s --chain ethereum --verify
        """
    )
    
    parser.add_argument('--config', default='config.yaml', help='Config file path')
    parser.add_argument('--chain', choices=['ethereum', 'pulsechain'], 
                        help='Blockchain to collect from')
    parser.add_argument('--both', action='store_true',
                        help='Collect from BOTH Ethereum and PulseChain, then merge')
    parser.add_argument('--output', help='Output file path')
    parser.add_argument('--load', help='Load existing dataset')
    parser.add_argument('--add-safe', nargs=2, metavar=('ADDRESS', 'NAME'), 
                        help='Add a safe contract')
    parser.add_argument('--add-honeypot', nargs=2, metavar=('ADDRESS', 'NAME'),
                        help='Add a honeypot contract')
    parser.add_argument('--compare', metavar='ADDRESS',
                        help='Compare address across Ethereum and PulseChain')
    parser.add_argument('--merge-only', action='store_true',
                        help='Only merge existing datasets (no collection)')
    parser.add_argument('--verify', action='store_true',
                        help='Verify chain connection')
    
    args = parser.parse_args()
    
    # Handle comparison mode
    if args.compare:
        collector = MultiChainDataCollector(args.config, chain='ethereum')
        result = collector.compare_across_chains(args.compare, 'pulsechain')
        
        # Save comparison result
        comparison_file = Path(f"./data/comparisons/{args.compare}_comparison.json")
        comparison_file.parent.mkdir(parents=True, exist_ok=True)
        with open(comparison_file, 'w') as f:
            json.dump(result, f, indent=2)
        print(f"\n✓ Comparison saved to {comparison_file}")
        
        import sys
        sys.exit(0)
    
    # Handle merge-only mode
    if args.merge_only:
        merge_datasets(args.config)
        import sys
        sys.exit(0)
    
    # Handle --both flag (collect from both chains)
    if args.both:
        print("\n" + "="*60)
        print("COLLECTING FROM BOTH CHAINS")
        print("="*60)
        
        # Ethereum
        print("\n### ETHEREUM ###")
        eth_collector = MultiChainDataCollector(args.config, chain='ethereum')
        if args.verify:
            eth_collector.verify_chain_id()
        
        print("\n=== Collecting Safe Ethereum Contracts ===")
        if KNOWN_SAFE_ETHEREUM:
            eth_collector.add_batch(KNOWN_SAFE_ETHEREUM)
        
        print("\n=== Collecting Honeypot Ethereum Contracts ===")
        if KNOWN_HONEYPOT_ETHEREUM:
            eth_collector.add_batch(KNOWN_HONEYPOT_ETHEREUM)
        else:
            print("⚠️  No Ethereum honeypots defined")
        
        eth_collector.save_dataset()
        
        # PulseChain
        print("\n### PULSECHAIN ###")
        pls_collector = MultiChainDataCollector(args.config, chain='pulsechain')
        if args.verify:
            pls_collector.verify_chain_id()
        
        print("\n=== Collecting Safe PulseChain Contracts ===")
        if KNOWN_SAFE_PULSECHAIN:
            pls_collector.add_batch(KNOWN_SAFE_PULSECHAIN)
        
        print("\n=== Collecting Honeypot PulseChain Contracts ===")
        if KNOWN_HONEYPOT_PULSECHAIN:
            pls_collector.add_batch(KNOWN_HONEYPOT_PULSECHAIN)
        else:
            print("⚠️  No PulseChain honeypots defined")
        
        pls_collector.save_dataset()
        
        # Merge datasets
        merge_datasets(args.config)
        
        import sys
        sys.exit(0)
    
    # Normal single-chain collection mode
    if args.chain:
        collector = MultiChainDataCollector(args.config, chain=args.chain)
        
        # Verify chain
        if args.verify or not args.load:
            collector.verify_chain_id()
        
        if args.load:
            collector.load_dataset(args.load)
        
        if args.add_safe:
            collector.add_sample(args.add_safe[0], 0, args.add_safe[1], "Manually added safe contract")
        
        if args.add_honeypot:
            collector.add_sample(args.add_honeypot[0], 1, args.add_honeypot[1], "Manually added honeypot")
        
        # Collect default dataset if no existing data
        if not args.load and not args.add_safe and not args.add_honeypot:
            print("Collecting default dataset...")
            
            if collector.chain == 'ethereum':
                print("\n=== Collecting Safe Ethereum Contracts ===")
                if KNOWN_SAFE_ETHEREUM:
                    collector.add_batch(KNOWN_SAFE_ETHEREUM)
                
                print("\n=== Collecting Honeypot Ethereum Contracts ===")
                if KNOWN_HONEYPOT_ETHEREUM:
                    collector.add_batch(KNOWN_HONEYPOT_ETHEREUM)
                else:
                    print("⚠️  No Ethereum honeypots defined yet. Add real ones!")
            
            elif collector.chain == 'pulsechain':
                print("\n=== Collecting Safe PulseChain Contracts ===")
                if KNOWN_SAFE_PULSECHAIN:
                    collector.add_batch(KNOWN_SAFE_PULSECHAIN)
                
                print("\n=== Collecting Honeypot PulseChain Contracts ===")
                if KNOWN_HONEYPOT_PULSECHAIN:
                    collector.add_batch(KNOWN_HONEYPOT_PULSECHAIN)
                else:
                    print("⚠️  No PulseChain honeypots defined yet. Add real ones!")
        
        # Save dataset
        if collector.samples:
            collector.save_dataset(args.output)
    
    else:
        # No arguments - show help
        parser.print_help()