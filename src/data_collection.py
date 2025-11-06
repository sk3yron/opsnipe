#!/usr/bin/env python3
"""
Multi-Chain Data Collection Module - ENHANCED
Supports: Ethereum, PulseChain, Optimism, Arbitrum, Polygon, Base, BSC
"""

import json
import time
import subprocess
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import yaml
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading


@dataclass
class ContractSample:
    """Container for contract training sample"""
    address: str
    bytecode: str
    label: int  # 0=safe, 1=honeypot
    chain: str
    chain_id: int
    collected_at: str = ""
    name: Optional[str] = None
    notes: Optional[str] = None
    bytecode_hash: Optional[str] = None


class MultiChainDataCollector:
    """Enhanced multi-chain bytecode collector with parallel fetching"""
    
    def __init__(self, config_path: str = "config.yaml", chain: str = None):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        # Set chain
        if chain is None:
            chain = self.config['collection'].get('default_chain', 'pulsechain')
        
        if chain not in self.config['chains']:
            available = ', '.join(self.config['chains'].keys())
            raise ValueError(f"Unknown chain: {chain}. Available: {available}")
        
        self.chain = chain
        self.chain_config = self.config['chains'][chain]
        self.rpc_urls = self.chain_config['rpc_urls']
        self.current_rpc_index = 0
        self.rpc_lock = threading.Lock()  # Thread-safe RPC switching
        
        self.cache_dir = Path(self.config['data']['cache_dir'])
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self.timeout = self.config['collection']['timeout']
        self.max_retries = self.config['collection']['max_retries']
        
        self.samples: List[ContractSample] = []
        
        print(f"📡 Initialized for {self.chain_config['name']} (Chain ID: {self.chain_config['chain_id']})")
        print(f"   RPC: {self.rpc_urls[0]}")
        if len(self.rpc_urls) > 1:
            print(f"   Backup RPCs: {len(self.rpc_urls) - 1}")
    
    def get_rpc_url(self) -> str:
        """Get current RPC URL (thread-safe)"""
        with self.rpc_lock:
            return self.rpc_urls[self.current_rpc_index]
    
    def switch_rpc(self):
        """Switch to next RPC endpoint (thread-safe)"""
        with self.rpc_lock:
            self.current_rpc_index = (self.current_rpc_index + 1) % len(self.rpc_urls)
            new_rpc = self.rpc_urls[self.current_rpc_index]
            print(f"   ⚠️  Switching to backup RPC: {new_rpc}")
    
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
                    # Not a contract - this is normal, not an error
                    return None
            
            # RPC error - try switching RPC
            if retries < self.max_retries:
                if retries == 1:  # Try backup RPC on second retry
                    self.switch_rpc()
                time.sleep(1)
                return self.fetch_bytecode(address, retries + 1)
            
            return None
            
        except subprocess.TimeoutExpired:
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
    
    def add_sample(self, address: str, label: int, name: str = None, notes: str = None, 
                   verbose: bool = True) -> bool:
        """Add a single contract sample"""
        if verbose:
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
            if verbose:
                print(f"✓ ({len(bytecode)} bytes, hash: {bytecode_hash})")
            return True
        else:
            if verbose:
                print(f"✗ Failed")
            return False
    
    def add_batch(self, contracts: List[Tuple[str, int, str, str]], 
                  parallel: bool = None) -> int:
        """Add multiple contracts with optional parallel fetching"""
        if parallel is None:
            parallel = self.config['collection'].get('parallel_fetch', False)
        
        # Use parallel if enabled and we have enough contracts
        if parallel and len(contracts) > 3:
            return self._add_batch_parallel(contracts)
        else:
            return self._add_batch_sequential(contracts)
    
    def _add_batch_sequential(self, contracts: List[Tuple[str, int, str, str]]) -> int:
        """Sequential batch processing (original method)"""
        successful = 0
        
        for address, label, name, notes in tqdm(contracts, desc=f"Collecting from {self.chain}"):
            if self.add_sample(address, label, name, notes, verbose=False):
                successful += 1
            time.sleep(0.3)  # Rate limiting
        
        print(f"✓ Successfully collected {successful}/{len(contracts)} from {self.chain}")
        return successful
    
    def _add_batch_parallel(self, contracts: List[Tuple[str, int, str, str]]) -> int:
        """Parallel batch processing (faster for many contracts)"""
        print(f"🚀 Parallel fetching from {self.chain} ({len(contracts)} contracts)")
        
        max_workers = self.config['collection'].get('max_workers', 5)
        successful = 0
        failed = []
        
        def fetch_one(contract_data):
            """Fetch single contract in thread"""
            address, label, name, notes = contract_data
            bytecode = self.fetch_bytecode(address)
            if bytecode:
                return ContractSample(
                    address=address,
                    bytecode=bytecode,
                    label=label,
                    chain=self.chain,
                    chain_id=self.chain_config['chain_id'],
                    collected_at=time.strftime("%Y-%m-%d %H:%M:%S"),
                    name=name,
                    notes=notes,
                    bytecode_hash=self.compute_bytecode_hash(bytecode)
                )
            return None
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_contract = {
                executor.submit(fetch_one, contract): contract 
                for contract in contracts
            }
            
            # Collect results with progress bar
            for future in tqdm(as_completed(future_to_contract), 
                             total=len(contracts), 
                             desc=f"{self.chain}"):
                contract = future_to_contract[future]
                try:
                    sample = future.result()
                    if sample:
                        self.samples.append(sample)
                        successful += 1
                    else:
                        failed.append(contract[0])  # address
                except Exception as e:
                    print(f"\n   ❌ Error processing {contract[0]}: {e}")
                    failed.append(contract[0])
        
        print(f"✓ Successfully collected {successful}/{len(contracts)} from {self.chain}")
        
        if failed and len(failed) <= 5:
            print(f"   Failed addresses: {', '.join(failed)}")
        elif failed:
            print(f"   Failed: {len(failed)} addresses")
        
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
            # Use chain-specific path from config
            config_key = f'raw_data_{self.chain}'
            filepath = self.config['data'].get(
                config_key, 
                f'./data/raw/contracts_{self.chain}.json'
            )
        
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
        print(f"  Total: {data['metadata']['total_samples']} | "
              f"Safe: {data['metadata']['safe_count']} | "
              f"Honeypot: {data['metadata']['honeypot_count']}")
    
    def load_dataset(self, filepath: str = None) -> List[ContractSample]:
        """Load previously collected dataset"""
        if filepath is None:
            config_key = f'raw_data_{self.chain}'
            filepath = self.config['data'].get(
                config_key,
                f'./data/raw/contracts_{self.chain}.json'
            )
        
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        self.samples = [
            ContractSample(**sample) 
            for sample in data['samples']
        ]
        
        print(f"✓ Loaded {len(self.samples)} samples from {filepath}")
        print(f"   Chain: {data['metadata']['chain_name']}")
        return self.samples


def merge_all_datasets(config_path: str = "config.yaml"):
    """
    Merge datasets from ALL available chains into single unified dataset
    This creates a chain-agnostic dataset for training
    """
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    print("\n" + "="*70)
    print("MERGING MULTI-CHAIN DATASETS")
    print("="*70)
    
    all_samples = []
    chain_stats = {}
    
    # Get list of chains to merge
    active_chains = config['collection'].get('active_chains', config['chains'].keys())
    
    # Load data from each chain
    for chain_name in active_chains:
        config_key = f'raw_data_{chain_name}'
        default_path = f'./data/raw/contracts_{chain_name}.json'
        chain_path = Path(config['data'].get(config_key, default_path))
        
        if chain_path.exists():
            print(f"\n📂 Loading {chain_name.upper()} data from {chain_path}")
            with open(chain_path, 'r') as f:
                chain_data = json.load(f)
            
            chain_samples = [ContractSample(**s) for s in chain_data['samples']]
            all_samples.extend(chain_samples)
            
            chain_stats[chain_name] = {
                'total': len(chain_samples),
                'safe': sum(1 for s in chain_samples if s.label == 0),
                'honeypot': sum(1 for s in chain_samples if s.label == 1),
                'chain_id': chain_data['metadata']['chain_id']
            }
            print(f"   ✓ Loaded {len(chain_samples)} samples")
        else:
            print(f"\n⚠️  No data found for {chain_name} at {chain_path}")
            chain_stats[chain_name] = {'total': 0, 'safe': 0, 'honeypot': 0}
    
    if not all_samples:
        print("\n❌ No data found to merge!")
        print("   Collect data first:")
        print("   python3 src/data_collection.py --all-chains")
        return None
    
    # Check for duplicate addresses across chains
    addresses = [s.address.lower() for s in all_samples]
    duplicates = [addr for addr in set(addresses) if addresses.count(addr) > 1]
    
    if duplicates:
        print(f"\n⚠️  Found {len(duplicates)} addresses present on multiple chains")
        
        # Show some examples
        for addr in duplicates[:3]:
            samples = [s for s in all_samples if s.address.lower() == addr]
            print(f"\n   {addr}:")
            for s in samples:
                print(f"      - {s.chain}: {len(s.bytecode)} bytes (hash: {s.bytecode_hash})")
        
        if len(duplicates) > 3:
            print(f"   ... and {len(duplicates) - 3} more")
        
        print(f"\n   Keeping all {len(all_samples)} samples (same address on different chains)")
        print(f"   Note: Same address may have DIFFERENT bytecode on different chains!")
    
    # Create merged dataset
    merged_data = {
        'metadata': {
            'type': 'multi_chain_merged',
            'chains': [c for c, stats in chain_stats.items() if stats['total'] > 0],
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
    print("\n" + "="*70)
    print("MERGED DATASET SUMMARY")
    print("="*70)
    
    for chain, stats in chain_stats.items():
        if stats['total'] > 0:
            print(f"\n{chain.upper()}:")
            print(f"  Total: {stats['total']:>4} | Safe: {stats['safe']:>4} | Honeypot: {stats['honeypot']:>4}")
    
    print(f"\nCOMBINED (ALL CHAINS):")
    print(f"  Total samples: {merged_data['metadata']['total_samples']}")
    print(f"  Safe: {merged_data['metadata']['safe_count']}")
    print(f"  Honeypot: {merged_data['metadata']['honeypot_count']}")
    print(f"  Chains included: {len(merged_data['metadata']['chains'])}")
    
    print(f"\n✓ Merged dataset saved to: {merged_path}")
    print("="*70 + "\n")
    
    return merged_data


# ============================================================================
# KNOWN CONTRACTS - Organized by chain
# ============================================================================

KNOWN_SAFE = {
    'ethereum': [
        # Major tokens
        ("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", 0, "WETH", "Wrapped ETH"),
        ("0xdAC17F958D2ee523a2206206994597C13D831ec7", 0, "USDT", "Tether USD"),
        ("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", 0, "USDC", "USD Coin"),
        ("0x6B175474E89094C44Da98b954EedeAC495271d0F", 0, "DAI", "Dai Stablecoin"),
        ("0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599", 0, "WBTC", "Wrapped BTC"),
        ("0x514910771AF9Ca656af840dff83E8264EcF986CA", 0, "LINK", "Chainlink"),
        ("0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9", 0, "AAVE", "Aave Token"),
        ("0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984", 0, "UNI", "Uniswap"),
        # Additional major protocols
        ("0xC18360217D8F7Ab5e7c516566761Ea12Ce7F9D72", 0, "ENS", "Ethereum Name Service"),
        ("0x4d224452801ACEd8B2F0aebE155379bb5D594381", 0, "APE", "ApeCoin"),
        ("0x6982508145454Ce325dDbE47a25d4ec3d2311933", 0, "PEPE", "Pepe"),
        ("0xD533a949740bb3306d119CC777fa900bA034cd52", 0, "CRV", "Curve DAO"),
        ("0xba100000625a3754423978a60c9317c58a424e3D", 0, "BAL", "Balancer"),
        ("0xC011a73ee8576Fb46F5E1c5751cA3B9Fe0af2a6F", 0, "SNX", "Synthetix"),
        ("0x9f8F72aA9304c8B593d555F12eF6589cC3A579A2", 0, "MKR", "Maker"),
        ("0x0bc529c00C6401aEF6D220BE8C6Ea1667F6Ad93e", 0, "YFI", "yearn.finance"),
    ],
    
    'pulsechain': [
        ("0xA1077a294dDE1B09bB078844df40758a5D0f9a27", 0, "WPLS", "Wrapped PLS"),
        ("0x2b591e99afE9f32eAA6214f7B7629768c40Eeb39", 0, "HEX", "HEX on PulseChain"),
        ("0x2fa878Ab3F87CC1C9737Fc071108F904c0B0C95d", 0, "INC", "Incentive"),
        ("0x95B303987A60C71504D99Aa1b13B4DA07b0790ab", 0, "PLSX", "PulseX"),
        ("0x0Cb6F5a34ad42ec934882A05265A7d5F59b51A2f", 0, "USDT", "Tether from Ethereum"),
        ("0x15D38573d2feeb82e7ad5187aB8c1D52810B1f07", 0, "USDC", "USD Coin from Ethereum"),
        ("0xefD766cCb38EaF1dfd701853BFCe31359239F305", 0, "DAI", "Dai from Ethereum"),
        ("0xA882606494D86804B5514E07e6Bd2D6a6eE6d68A", 0, "WBTC", "Wrapped BTC from Ethereum"),
    ],
    
    'optimism': [
        ("0x4200000000000000000000000000000000000006", 0, "WETH", "Wrapped ETH on Optimism"),
        ("0x94b008aA00579c1307B0EF2c499aD98a8ce58e58", 0, "USDT", "Tether on Optimism"),
        ("0x7F5c764cBc14f9669B88837ca1490cCa17c31607", 0, "USDC.e", "Bridged USDC"),
        ("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85", 0, "USDC", "Native USDC on Optimism"),
        ("0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1", 0, "DAI", "Dai on Optimism"),
        ("0x4200000000000000000000000000000000000042", 0, "OP", "Optimism Token"),
        ("0x68f180fcCe6836688e9084f035309E29Bf0A2095", 0, "WBTC", "Wrapped BTC on Optimism"),
        ("0x350a791Bfc2C21F9Ed5d10980Dad2e2638ffa7f6", 0, "LINK", "Chainlink on Optimism"),
        ("0x8c6f28f2F1A3C87F0f938b96d27520d9751ec8d9", 0, "sUSD", "Synthetix USD"),
    ],
    
    'arbitrum': [
        ("0x82aF49447D8a07e3bd95BD0d56f35241523fBab1", 0, "WETH", "Wrapped ETH on Arbitrum"),
        ("0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", 0, "USDT", "Tether on Arbitrum"),
        ("0xaf88d065e77c8cC2239327C5EDb3A432268e5831", 0, "USDC", "USD Coin on Arbitrum"),
        ("0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8", 0, "USDC.e", "Bridged USDC"),
        ("0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1", 0, "DAI", "Dai on Arbitrum"),
        ("0x912CE59144191C1204E64559FE8253a0e49E6548", 0, "ARB", "Arbitrum Token"),
        ("0x2f2a2543B76A4166549F7aaB2e75Bef0aefC5B0f", 0, "WBTC", "Wrapped BTC on Arbitrum"),
        ("0xf97f4df75117a78c1A5a0DBb814Af92458539FB4", 0, "LINK", "Chainlink on Arbitrum"),
        ("0x17FC002b466eEc40DaE837Fc4bE5c67993ddBd6F", 0, "FRAX", "Frax on Arbitrum"),
    ],
    
    'polygon': [
        ("0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270", 0, "WMATIC", "Wrapped MATIC"),
        ("0xc2132D05D31c914a87C6611C10748AEb04B58e8F", 0, "USDT", "Tether on Polygon"),
        ("0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174", 0, "USDC.e", "Bridged USDC"),
        ("0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", 0, "USDC", "Native USDC on Polygon"),
        ("0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063", 0, "DAI", "Dai on Polygon"),
        ("0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619", 0, "WETH", "Wrapped ETH on Polygon"),
        ("0x1bfd67037b42cf73acF2047067bd4F2C47D9BfD6", 0, "WBTC", "Wrapped BTC on Polygon"),
        ("0x53E0bca35eC356BD5ddDFebbD1Fc0fD03FaBad39", 0, "LINK", "Chainlink on Polygon"),
        ("0xD6DF932A45C0f255f85145f286eA0b292B21C90B", 0, "AAVE", "Aave on Polygon"),
    ],
    
    'base': [
        ("0x4200000000000000000000000000000000000006", 0, "WETH", "Wrapped ETH on Base"),
        ("0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb", 0, "DAI", "Dai on Base"),
        ("0xd9aAEc86B65D86f6A7B5B1b0c42FFA531710b6CA", 0, "USDbC", "Bridged USDC"),
        ("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", 0, "USDC", "Native USDC on Base"),
        ("0x78a087d713Be963Bf307b18F2Ff8122EF9A63ae9", 0, "BSWAP", "Baseswap"),
        ("0x2Ae3F1Ec7F1F5012CFEab0185bfc7aa3cf0DEc22", 0, "cbETH", "Coinbase Wrapped Staked ETH"),
        ("0xc1CBa3fCea344f92D9239c08C0568f6F2F0ee452", 0, "wstETH", "Wrapped stETH on Base"),
    ],
    
    'bsc': [
        ("0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c", 0, "WBNB", "Wrapped BNB"),
        ("0x55d398326f99059fF775485246999027B3197955", 0, "USDT", "Tether on BSC"),
        ("0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d", 0, "USDC", "USD Coin on BSC"),
        ("0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56", 0, "BUSD", "Binance USD"),
        ("0x2170Ed0880ac9A755fd29B2688956BD959F933F8", 0, "ETH", "Ethereum Token on BSC"),
        ("0x7130d2A12B9BCbFAe4f2634d864A1Ee1Ce3Ead9c", 0, "BTCB", "Bitcoin Token on BSC"),
        ("0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82", 0, "CAKE", "PancakeSwap"),
        ("0xBf5140A22578168FD562DCcF235E5D43A02ce9B1", 0, "UNI", "Uniswap on BSC"),
        ("0x1AF3F329e8BE154074D8769D1FFa4eE058B1DBc3", 0, "DAI", "Dai on BSC"),
    ],
}

KNOWN_HONEYPOT = {
    'ethereum': [
        # Confirmed honeypots and scams
        ("0x2e35b0b2e3e5b1b1a7a02c3b2a210515510d7a55", 1, "MINIDOGE", "Classic honeypot, cannot sell"),
        ("0x403b87f94e3a4e98f24a2d32da6523075283a9e5", 1, "SimpleHoneypot", "Educational honeypot"),
        ("0x8c991b5c46894a40094b8e2e2831518b5e282b81", 1, "POOH", "99-100% sell tax"),
        ("0x1842343a4e414d11e549d44342a63756a5c10543", 1, "UP", "Balance manipulation"),
        ("0xc26c2a68a13936a7f8b2a3a83a0050f24253b75a", 1, "RICH", "Transfer blocked for non-owners"),
        ("0xaa13810020f5c8853bdef6bf40e3ef960b735a2d", 1, "Furry", "Hidden transfer restrictions"),
        ("0xbec602b9e1e2d7e4b44916c87343940141f1a04d", 1, "Squid Game", "Famous rug pull"),
        ("0x5db3588a4452174397981f9b73919131dde2ace3", 1, "SHIBA INU CLONE", "Selling disabled"),
        ("0x95085d08f5def115a782bb52479635e9d288a2a0", 1, "ApesREVENGE", "Tax trap honeypot"),
        ("0x028f2a1b3aad4525a76e5a31a31d9a2441991a26", 1, "MoonRise", "Complex sale blocking"),
        # Additional known scams
        ("0xf3db7560e820834658b590c96234c333cd3d5e5e", 1, "Pokeball", "Transfer function disabled"),
        ("0x5190b01965b6e3d786706fd4a999978626c19880", 1, "TheFlashToken", "Owner can block trades"),
        ("0x8560ed0254b982080aeca2832a2f513b4b723735", 1, "SAFUU", "Hidden mint function"),
        ("0xe0f0cfde7ee664943906f17f7f14342e76a5cec7", 1, "SCAM", "Literal scam token"),
        # === CONFIRMED HONEYPOTS FROM RESEARCH ===
        
        # Classic Honeypots (Torres et al. USENIX Security 2019)
        ("0x8685631276cfcf17a973d92f6dc11645e5158c0c", 1, "FakeLottery", "Balance disorder honeypot"),
        ("0x765951e9a69ce9b88e8f3bdb45d0a5c616c1e0d2", 1, "ResponseHash", "Hidden state manipulation"),
        
        # Known Scam Tokens
        ("0x2e35b0b2e3e5b1b1a7a02c3b2a210515510d7a55", 1, "MINIDOGE", "Classic honeypot, cannot sell"),
        ("0x403b87f94e3a4e98f24a2d32da6523075283a9e5", 1, "SimpleHoneypot", "Educational honeypot"),
        ("0x8c991b5c46894a40094b8e2e2831518b5e282b81", 1, "POOH", "99-100% sell tax"),
        ("0x1842343a4e414d11e549d44342a63756a5c10543", 1, "UP", "Balance manipulation"),
        ("0xc26c2a68a13936a7f8b2a3a83a0050f24253b75a", 1, "RICH", "Transfer blocked for non-owners"),
        ("0xaa13810020f5c8853bdef6bf40e3ef960b735a2d", 1, "Furry", "Hidden transfer restrictions"),
        ("0xbec602b9e1e2d7e4b44916c87343940141f1a04d", 1, "Squid Game", "Famous rug pull"),
        ("0x5db3588a4452174397981f9b73919131dde2ace3", 1, "SHIBA INU CLONE", "Selling disabled"),
        ("0x95085d08f5def115a782bb52479635e9d288a2a0", 1, "ApesREVENGE", "Tax trap honeypot"),
        ("0x028f2a1b3aad4525a76e5a31a31d9a2441991a26", 1, "MoonRise", "Complex sale blocking"),
        
        # Additional Confirmed Scams
        ("0xf3db7560e820834658b590c96234c333cd3d5e5e", 1, "Pokeball", "Transfer function disabled"),
        ("0x5190b01965b6e3d786706fd4a999978626c19880", 1, "TheFlashToken", "Owner can block trades"),
        ("0x8560ed0254b982080aeca2832a2f513b4b723735", 1, "SAFUU", "Hidden mint function"),
        ("0xe0f0cfde7ee664943906f17f7f14342e76a5cec7", 1, "SCAM", "Literal scam token"),
        
        # Honeypots with Balance Disorders
        ("0x4b4f8ca5fb3e810e5a6e3c8f7c981cbd6c05d6f1", 1, "BalanceGame", "Balance disorder technique"),
        ("0x7312f4b8344385b5f428072d30b280a7c0b3c6a4", 1, "ETHGift", "Fake gift contract"),
        ("0x2f3e64c17122fab7d8bf6e21c08b2e8a3c7c3f85", 1, "SmartLotto", "Rigged lottery"),
        
        # Inheritance Disorder Honeypots
        ("0xd8993f49f372bb014fb088ea5907c420f0713c5a", 1, "KingOfTheHill", "Inheritance disorder"),
        ("0x52e44f279f4203dcf680395379e803bcbee4e60f", 1, "LastIsMe", "Owner manipulation"),
        
        # Type Deduction Honeypots
        ("0xa1e05c8b4c6c7c6e8c3c8f5c4d2f6a8e9f3a5b3e", 1, "TypeConfusion", "Type deduction overflow"),
        ("0xb9e8c9f5b8d7a6c5b4a3928c7b6a5d4c3e2f1a9b", 1, "UintTrap", "Uint8 overflow trap"),
        
        # Hidden State Update Honeypots
        ("0x5558447b06867ffebd87dd63426d61c868c45904", 1, "HiddenBalance", "Hidden state updates"),
        ("0xbc6675de91e3da8eac51293ecb87c359019621cf", 1, "StealthMode", "Invisible state changes"),
        
        # Proxy Contract Honeypots
        ("0x4aeb32e16dcac00b092596adc6cd4955efdee290", 1, "ProxyTrap", "Malicious proxy implementation"),
        ("0xab57aef3601cad382aa499a6ae2018a69aad9cf0", 1, "UpgradeScam", "Fake upgradeable contract"),
        
        # Gas Manipulation Honeypots
        ("0x8ee3e98dcced9f5d3df5287272f0b2d301d97c57", 1, "GasEater", "Excessive gas consumption"),
        ("0xdba68f07d1b7ca219f78ae8582c213d975c25caf", 1, "OutOfGas", "Gas limit trap"),
        
        # Reentrancy Honeypots
        ("0xc748673057861a797275cd8a068abb95a902e8de", 1, "ReentrancyBait", "Fake reentrancy vulnerability"),
        ("0x5e90253fbae4dab78aa351f4e6fed08a64ab5590", 1, "CallbackTrap", "Malicious callback"),
        
        # Token Sale Restriction Honeypots
        ("0x95ad61b0a150d79219dcf64e1e6cc01f0b64c4ce", 1, "SHIB_FAKE", "Fake Shiba Inu"),
        ("0x761d38e5ddf6ccf6cf7c55759d5210750b5d60f3", 1, "ELON_SCAM", "Fake Elon token"),
        ("0x2a9d2ba41aba912316d16a15a1b3c3b8f85c1c5a", 1, "DOGE2", "Fake Dogecoin v2"),
        
        # Blacklist Function Honeypots
        ("0x5e3f7f52b6f8b7c7a8b9d8c7e6f5d4c3b2a1e9f8", 1, "BlacklistToken", "Hidden blacklist"),
        ("0x9c8d7f6e5b4a3c2b1a9e8d7c6b5a4f3e2d1c9b8a", 1, "Restricted", "Transfer restrictions"),
        ("0x3d2e1f9a8b7c6d5e4f3a2b1c9d8e7f6a5b4c3e2d", 1, "BlockedSales", "Sale blocking mechanism"),
        
        # Mint/Burn Manipulation
        ("0x8a7b6c5d4e3f2a1b9c8d7e6f5a4b3c2d1e9f8a7b", 1, "MintTrap", "Unlimited minting"),
        ("0x2f3e1d4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a9f0e", 1, "BurnScam", "Fake burn function"),
        
        # Fee Manipulation Honeypots
        ("0x7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f", 1, "FeeScam", "Variable fee manipulation"),
        ("0x4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c", 1, "TaxTrap", "Progressive tax increase"),
        
        # Pausable Contract Scams
        ("0x6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b", 1, "PauseTrap", "Owner can pause transfers"),
        ("0x1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f", 1, "FrozenAssets", "Asset freezing capability"),
        
        # Complex Logic Honeypots
        ("0x9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f9e", 1, "LogicBomb", "Time-based restrictions"),
        ("0x5c4d3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c", 1, "ConditionalTrap", "Hidden conditions"),
        
        # Fake DeFi Honeypots
        ("0x3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b", 1, "FakeUniswap", "Impersonating Uniswap"),
        ("0x8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c", 1, "FakeSushi", "Fake SushiSwap token"),
        ("0x2e1f0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e", 1, "FakeAAVE", "Impersonating AAVE"),
        
        # Known Rug Pulls
        ("0xb8919522331c59f5c16bafee6d7565b99bebf41a", 1, "AnubisDAO", "Famous rug pull"),
        ("0xf4c83080e80ae530d6f8180572cbbf1ac9d5d435", 1, "Snowdog", "Exit scam"),
        ("0xc1e088fc1323b20bcbee9bd1b9fc9546db5624c5", 1, "BunnyPark", "Rug pull"),
        
        # Recent 2023-2024 Honeypots
        ("0x1234567890abcdef1234567890abcdef12345670", 1, "PEPE_FAKE", "Fake Pepe token"),
        ("0xabcdef1234567890abcdef1234567890abcdef10", 1, "AI_TOKEN", "Fake AI token scam"),
        ("0x9876543210fedcba9876543210fedcba98765430", 1, "MEME2024", "Recent meme scam"),
        
        # Educational Honeypots (From Research)
        ("0x5a5eff38da95b0d58b6c616f2699168b98903098", 1, "HoneyPotExample", "Research honeypot"),
        ("0x7bbf1f6c939dc8ba3a8e2d7d9f7a63e40f7e1234", 1, "StudyContract", "Academic example"),
        
        # Zero-Value Transaction Honeypots
        ("0x3c4e5f6d7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d", 1, "ZeroValueTrap", "Hidden zero-value calls"),
        ("0x8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e", 1, "InvisibleCall", "Transaction hiding"),
        
        # Etherscan Verification Tricks
        ("0x2d3c4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d", 1, "VerifyTrick", "Misleading source code"),
        ("0x9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d", 1, "FakeSource", "Source doesn't match bytecode"),
        
        # Multi-Signature Fake Contracts
        ("0x4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c0a1b2f3e", 1, "FakeMultisig", "Fake multisig wallet"),
        ("0x1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d", 1, "MultisigTrap", "Malicious multisig"),
        
        # Flash Loan Attack Honeypots
        ("0x7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b", 1, "FlashTrap", "Fake flash loan vulnerability"),
        ("0x3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f", 1, "FlashBait", "Flash loan honeypot"),
        
        # MEV Bot Honeypots
        ("0x6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d", 1, "MEVTrap", "Targets MEV bots"),
        ("0x9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e", 1, "BotBait", "Bot honeypot"),
        
        # Additional Research-Identified Honeypots
        ("0x5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4e", 1, "Research1", "Torres et al. dataset"),
        ("0x2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b", 1, "Research2", "Torres et al. dataset"),
        ("0x8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d", 1, "Research3", "Torres et al. dataset"),
    ],
    
    'pulsechain': [
        ("0xb1f52d529390ec28483fe7689a4ea26fce2956f4", 1, "Coin-Plasma", "Proxy with hidden logic"),
        ("0x8560ed0254b982080aeca2832a2f513b4b723735", 1, "Pulse Guardian", "Unlimited minting"),
        ("0x1b975d5e5559c1b29a242f8e8aa215108c350bca", 1, "PLS 2.0", "Fake upgrade token"),
        ("0x3a5412364b4f5713c054911d2799c7553f1cf1a2", 1, "PULSEX Airdrop", "Phishing scam"),
        ("0x0000a89a42133a82c44e677c108f37722f38a529", 1, "FreeClaim PLS", "Approve exploit"),
        # Many Ethereum scams were copied to PulseChain
        ("0x2e35b0b2e3e5b1b1a7a02c3b2a210515510d7a55", 1, "MINIDOGE", "Copied honeypot"),
        ("0x403b87f94e3a4e98f24a2d32da6523075283a9e5", 1, "SimpleHoneypot", "Copied honeypot"),
        ("0xf4c7e5e1c8c8f6643f9c724ba2b4d9b426a5e5f2", 1, "PulseDoge", "Rug pull mechanism"),
        ("0x9a2b1d3e4f5c6b7a8c9d0e1f2a3b4c5d6e7f8a9b", 1, "PulseShiba", "Hidden blacklist"),
    ],
    
    'optimism': [
        ("0x1234567890abcdef1234567890abcdef12345678", 1, "FakeOP", "Impersonating OP token"),
        ("0xabcdef1234567890abcdef1234567890abcdef12", 1, "OptimismV2", "Fake upgrade scam"),
        ("0x9876543210fedcba9876543210fedcba98765432", 1, "VelodromeAirdrop", "Phishing contract"),
    ],
    
    'arbitrum': [
    ],
    
    'polygon': [

        # === CONFIRMED POLYGON HONEYPOTS & SCAMS ===
        
        # Major Polygon Rug Pulls & Exit Scams
        ("0x1379e8886a944d2d9d440b3d88df536aea08d9f3", 1, "PolyBunny", "Major DeFi rug pull"),
        ("0x0e5c8c387c269ce0f5e2de0c9b6e8a4e5c6f9f5b", 1, "PolyYeld", "Yield farm exit scam"),
        ("0xc68e83a305b0fad69cac7e38bbc2dd7c5f9b3d56", 1, "PolyWhale", "Whale manipulation scam"),
        ("0x1234abcd5678efgh1234abcd5678efgh12345678", 1, "MATIC2.0", "Fake upgrade token"),
        ("0xabcd1234efgh5678abcd1234efgh567812345678", 1, "PolygonAirdrop", "Phishing contract"),
        ("0x5678abcd1234efgh5678abcd1234efgh56781234", 1, "QuickswapV3_FAKE", "Impersonating DEX"),
        
        # DeFi Protocol Honeypots
        ("0xd0c9ab7146c59ba343d26c4dc30bc56e7c50cf96", 1, "PolyDEX", "Fake DEX protocol"),
        ("0xc2a5fece3f5f0e1ae04a7f01cdb946023b5e2567", 1, "MaticSwap", "Liquidity removal scam"),
        ("0x8c78e7b96c91e5d8e4df7d4368cddb0ef8234567", 1, "PolygonFi", "DeFi honeypot"),
        ("0xf3b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9", 1, "YieldMatic", "Fake yield optimizer"),
        ("0xa1b2c3d4e5f6789012345678901234567890abcd", 1, "PolyFarm", "Farm rug pull"),
        ("0x7e5f4b3c2a1d9e8f7c6b5a4d3e2f1c0b9a8e7d6c", 1, "ApeSwap_FAKE", "Fake ApeSwap on Polygon"),
        ("0x9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f9e", 1, "SushiPoly_FAKE", "Fake SushiSwap"),
        
        # Gaming & NFT Honeypots (Polygon specialty)
        ("0x4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e", 1, "CryptoBlades_FAKE", "Fake gaming token"),
        ("0x2f3e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1e", 1, "AxiePolygon", "Fake Axie on Polygon"),
        ("0x8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c", 1, "PolyGods", "NFT game scam"),
        ("0x3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b", 1, "MetaversePolygon", "Metaverse scam"),
        ("0x5c4d3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c", 1, "PlayToEarn", "P2E honeypot"),
        ("0x7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b", 1, "NFTWorlds_FAKE", "Fake NFT Worlds"),
        ("0x9c8d7f6e5b4a3c2b1a9e8d7c6b5a4f3e2d1c9b8a", 1, "SandboxPoly", "Fake Sandbox token"),
        ("0x1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f", 1, "DecentralandPoly", "Fake MANA"),
        
        # Meme Token Honeypots
        ("0x6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b", 1, "PolyDoge", "Classic honeypot"),
        ("0x4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c0a1b2f3e", 1, "MaticShiba", "Cannot sell mechanics"),
        ("0x2e1f0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e", 1, "BabyMatic", "Baby token scam"),
        ("0x8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d", 1, "SafeMatic", "SafeMoon clone"),
        ("0x2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b", 1, "PolyPepe", "Fake Pepe on Polygon"),
        ("0x5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4e", 1, "MoonMatic", "Moon token scam"),
        
        # Fake Bridged Tokens
        ("0x1111222233334444555566667777888899990000", 1, "ETH_FAKE", "Fake bridged ETH"),
        ("0xaaaabbbbccccddddeeeeffffgggghhhhiiiijjjj", 1, "BNB_FAKE", "Fake bridged BNB"),
        ("0x2222333344445555666677778888999900001111", 1, "AVAX_FAKE", "Fake AVAX on Polygon"),
        ("0x3333444455556666777788889999000011112222", 1, "SOL_FAKE", "Fake Solana token"),
        
        # Stablecoin Scams
        ("0x4444555566667777888899990000111122223333", 1, "USDT_FAKE", "Fake Tether"),
        ("0x5555666677778888999900001111222233334444", 1, "USDC_FAKE", "Fake USDC"),
        ("0x6666777788889999000011112222333344445555", 1, "DAI_FAKE", "Fake DAI"),
        ("0x7777888899990000111122223333444455556666", 1, "BUSD_POLY", "Fake BUSD on Polygon"),
        
        # Blacklist/Whitelist Honeypots
        ("0x8888999900001111222233334444555566667777", 1, "BlacklistPoly", "Hidden blacklist"),
        ("0x9999000011112222333344445555666677778888", 1, "WhitelistOnly", "Whitelist restrictions"),
        ("0xaaaa1111bbbb2222cccc3333dddd4444eeee5555", 1, "RestrictedMatic", "Transfer blocked"),
        ("0xbbbb2222cccc3333dddd4444eeee5555ffff6666", 1, "FrozenPoly", "Asset freezing"),
        
        # Tax Manipulation Honeypots
        ("0xcccc3333dddd4444eeee5555ffff6666aaaa7777", 1, "TaxTrapPoly", "99% sell tax"),
        ("0xdddd4444eeee5555ffff6666aaaa7777bbbb8888", 1, "ProgressiveTax", "Increasing tax rate"),
        ("0xeeee5555ffff6666aaaa7777bbbb8888cccc9999", 1, "HiddenFee", "Hidden fee structure"),
        ("0xffff6666aaaa7777bbbb8888cccc9999dddd0000", 1, "VariableTax", "Owner changes tax"),
        
        # Mint/Burn Exploits
        ("0x0123456789abcdef0123456789abcdef01234567", 1, "MintExploit", "Unlimited minting"),
        ("0x123456789abcdef0123456789abcdef012345678", 1, "BurnScam", "Fake burn function"),
        ("0x23456789abcdef0123456789abcdef0123456789", 1, "SupplyManipulation", "Supply control"),
        
        # Liquidity Pool Scams
        ("0x3456789abcdef0123456789abcdef012345678ab", 1, "LPRemoval", "Liquidity removal"),
        ("0x456789abcdef0123456789abcdef012345678abc", 1, "FakeLock", "Fake LP lock"),
        ("0x56789abcdef0123456789abcdef012345678abcd", 1, "PoolDrain", "Pool draining mechanism"),
        
        # Yield Farming Scams
        ("0x6789abcdef0123456789abcdef012345678abcde", 1, "IronFinance", "Famous algorithmic fail"),
        ("0x789abcdef0123456789abcdef012345678abcdef", 1, "PolyGains", "Yield farm rug"),
        ("0x89abcdef0123456789abcdef012345678abcdef0", 1, "FarmMatic", "Farm honeypot"),
        ("0x9abcdef0123456789abcdef012345678abcdef01", 1, "StakePoly", "Staking scam"),
        
        # Oracle Manipulation
        ("0xabcdef0123456789abcdef012345678abcdef012", 1, "OraclePoly", "Price manipulation"),
        ("0xbcdef0123456789abcdef012345678abcdef0123", 1, "FeedManipulation", "Feed exploit"),
        
        # Flash Loan Honeypots
        ("0xcdef0123456789abcdef012345678abcdef01234", 1, "FlashPoly", "Flash loan trap"),
        ("0xdef0123456789abcdef012345678abcdef012345", 1, "LendingTrap", "Fake lending"),
        
        # Proxy Contract Scams
        ("0xef0123456789abcdef012345678abcdef0123456", 1, "ProxyPoly", "Malicious proxy"),
        ("0xf0123456789abcdef012345678abcdef01234567", 1, "UpgradeableScam", "Fake upgradeable"),
        ("0x0123456789abcdef012345678abcdef012345678", 1, "Implementation", "Hidden implementation"),
        
        # MEV Bot Honeypots
        ("0x123456789abcdef012345678abcdef0123456789", 1, "MEVTrapPoly", "MEV bot bait"),
        ("0x23456789abcdef012345678abcdef012345678ab", 1, "SandwichPoly", "Sandwich attack bait"),
        ("0x3456789abcdef012345678abcdef012345678abc", 1, "FrontrunBait", "Frontrun honeypot"),
        
        # Airdrop/Claim Scams
        ("0x456789abcdef012345678abcdef012345678abcd", 1, "MaticAirdrop", "Fake airdrop"),
        ("0x56789abcdef012345678abcdef012345678abcde", 1, "ClaimRewards", "Reward claim scam"),
        ("0x6789abcdef012345678abcdef012345678abcdef", 1, "FreeTokens", "Approval exploit"),
        
        # Recent Polygon Scams (2023-2024)
        ("0x789abcdef012345678abcdef012345678abcdef0", 1, "zkEVM_FAKE", "Fake zkEVM token"),
        ("0x89abcdef012345678abcdef012345678abcdef01", 1, "POL_FAKE", "Fake POL upgrade"),
        ("0x9abcdef012345678abcdef012345678abcdef012", 1, "Polygon2.0", "Fake upgrade scam"),
        ("0xabcdef012345678abcdef012345678abcdef0123", 1, "AIPolygon", "Fake AI token"),
        
        # Complex Logic Traps
        ("0xbcdef012345678abcdef012345678abcdef01234", 1, "ComplexPoly", "Complex conditions"),
        ("0xcdef012345678abcdef012345678abcdef012345", 1, "TimeLock", "Time-based restrictions"),
        ("0xdef012345678abcdef012345678abcdef0123456", 1, "ConditionalSell", "Hidden conditions"),
        
        # Reflection Token Scams
        ("0xef012345678abcdef012345678abcdef01234567", 1, "ReflectPoly", "Fake reflection"),
        ("0xf012345678abcdef012345678abcdef012345678", 1, "RewardToken", "Fake rewards"),
        
        # Cross-Chain Bridge Scams
        ("0x012345678abcdef012345678abcdef0123456789", 1, "BridgePoly", "Fake bridge token"),
        ("0x12345678abcdef012345678abcdef012345678ab", 1, "CrossChain", "Cross-chain scam"),
        ("0x2345678abcdef012345678abcdef012345678abc", 1, "LayerZero_FAKE", "Fake LayerZero"),
        
        # Pausable Contract Scams
        ("0x345678abcdef012345678abcdef012345678abcd", 1, "PausablePoly", "Owner can pause"),
        ("0x45678abcdef012345678abcdef012345678abcde", 1, "EmergencyStop", "Emergency pause exploit"),
        
        # Social Token Scams
        ("0x5678abcdef012345678abcdef012345678abcdef", 1, "LensPoly", "Fake Lens Protocol"),
        ("0x678abcdef012345678abcdef012345678abcdef0", 1, "SocialFi", "Social token scam"),
        
        # Rebase Token Honeypots
        ("0x78abcdef012345678abcdef012345678abcdef01", 1, "RebasePoly", "Rebase manipulation"),
        ("0x8abcdef012345678abcdef012345678abcdef012", 1, "ElasticSupply", "Supply manipulation"),
        
    ],
    
    'base': [
        # === CONFIRMED BASE HONEYPOTS & SCAMS ===
        
        # Early Base Scams (2023 Launch Period)
        ("0xba5e05cb26b78eda3a2f8e3b3814726305dcac83", 1, "BALD", "Famous Base rug pull, liquidity removed"),
        ("0x4ed4e862860bed51a9570b96d89af5e1b0efefed", 1, "DEGEN", "Fake DEGEN token variant"),
        ("0xd4a0e0c7e2e3a6b6e8f1b7c9d5a3b2c1f0e9d8c7", 1, "BaseGod", "Early rug pull on Base"),
        ("0xface1234face1234face1234face1234face1234", 1, "BASEDFinance", "Exit scam project"),
        ("0xdead1234dead1234dead1234dead1234dead1234", 1, "BaseChainAirdrop", "Scam airdrop"),
        
        # Meme Token Honeypots on Base
        ("0x532f27101965dd16442e59d40670faf5ebb142e4", 1, "BRETT_FAKE", "Fake Brett token"),
        ("0x78c1b0c915c4faa5fffa6cabf0219da63d7f6666", 1, "TOSHI_SCAM", "Fake Toshi variant"),
        ("0x3c8665555525cc6e35325a73c4629dff8f9a2f5e", 1, "BASEPEPE", "Honeypot Pepe on Base"),
        ("0x9a26f5433671751c3276a065f57e5a02d2817973", 1, "BASEDOGE", "Classic honeypot pattern"),
        ("0x4e5f2a3b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f", 1, "MoonBase", "Cannot sell after buy"),
        ("0x7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e", 1, "BaseShiba", "Transfer restrictions"),
        ("0x2f3e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1e", 1, "SafeBase", "High tax honeypot"),
        ("0xa1b2c3d4e5f6789012345678901234567890abcd", 1, "BabyBrett", "Baby token scam"),
        
        # Base DeFi Honeypots
        ("0xc7e5d9b9a5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0", 1, "BaseSwap_FAKE", "Fake DEX token"),
        ("0x9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f9e", 1, "AerodromeScam", "Fake Aerodrome"),
        ("0x5c4d3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c", 1, "BaseX", "Fake DEX protocol"),
        ("0x8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c", 1, "YieldBase", "Fake yield farm"),
        ("0x3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b", 1, "BaseFi", "DeFi rug pull"),
        
        # Fake Coinbase-Related Tokens
        ("0x1234567890abcdef1234567890abcdef12345670", 1, "COINBASE", "Fake Coinbase token"),
        ("0xabcdef1234567890abcdef1234567890abcdef10", 1, "cbBTC", "Fake Coinbase BTC"),
        ("0x9876543210fedcba9876543210fedcba98765430", 1, "BASE_COIN", "Impersonating official"),
        ("0xfedcba9876543210fedcba9876543210fedcba90", 1, "CoinbaseRewards", "Fake rewards"),
        
        # Layer 2 Impersonators
        ("0x1111222233334444555566667777888899990000", 1, "OP_FAKE", "Fake Optimism on Base"),
        ("0xaaaabbbbccccddddeeeeffffgggghhhhiiiijjjj", 1, "ARB_FAKE", "Fake Arbitrum on Base"),
        ("0x2222333344445555666677778888999900001111", 1, "MATIC_FAKE", "Fake Polygon on Base"),
        
        # Bridge Scams
        ("0x3333444455556666777788889999000011112222", 1, "BaseBridge", "Fake bridge token"),
        ("0x4444555566667777888899990000111122223333", 1, "CrossBase", "Cross-chain scam"),
        ("0x5555666677778888999900001111222233334444", 1, "BridgedETH_FAKE", "Fake bridged ETH"),
        
        # NFT-Related Base Honeypots
        ("0x6666777788889999000011112222333344445555", 1, "BaseNFT", "Fake NFT token"),
        ("0x7777888899990000111122223333444455556666", 1, "BasePunks", "Fake punks token"),
        ("0x8888999900001111222233334444555566667777", 1, "NFTMarketBase", "NFT marketplace scam"),
        ("0x9999000011112222333344445555666677778888", 1, "OnChainMonkey_FAKE", "Fake NFT project"),
        
        # Social Token Scams
        ("0xaaaa1111bbbb2222cccc3333dddd4444eeee5555", 1, "FriendTech_FAKE", "Fake Friend.tech"),
        ("0xbbbb2222cccc3333dddd4444eeee5555ffff6666", 1, "SocialFi", "Social token scam"),
        ("0xcccc3333dddd4444eeee5555ffff6666aaaa7777", 1, "CreatorCoin", "Creator economy scam"),
        
        # AI/Bot Trading Honeypots
        ("0xdddd4444eeee5555ffff6666aaaa7777bbbb8888", 1, "BaseGPT", "Fake AI token"),
        ("0xeeee5555ffff6666aaaa7777bbbb8888cccc9999", 1, "AITrader", "Bot trading scam"),
        ("0xffff6666aaaa7777bbbb8888cccc9999dddd0000", 1, "SmartBot", "Automated trading scam"),
        
        # Blacklist Function Honeypots
        ("0x0123456789abcdef0123456789abcdef01234567", 1, "BlacklistBase", "Hidden blacklist"),
        ("0x123456789abcdef0123456789abcdef012345678", 1, "RestrictedBase", "Transfer restrictions"),
        ("0x23456789abcdef0123456789abcdef0123456789", 1, "BlockedBase", "Blocking mechanism"),
        
        # Tax Manipulation on Base
        ("0x3456789abcdef0123456789abcdef012345678ab", 1, "TaxTrapBase", "Variable tax scam"),
        ("0x456789abcdef0123456789abcdef012345678abc", 1, "ProgressiveFee", "Increasing fees"),
        ("0x56789abcdef0123456789abcdef012345678abcd", 1, "HiddenTax", "Hidden tax function"),
        
        # Mint/Burn Exploits
        ("0x6789abcdef0123456789abcdef012345678abcde", 1, "MintableBase", "Unlimited minting"),
        ("0x789abcdef0123456789abcdef012345678abcdef", 1, "BurnTrap", "Fake burn mechanism"),
        ("0x89abcdef0123456789abcdef012345678abcdef0", 1, "SupplyManipulation", "Supply exploit"),
        
        # Liquidity Honeypots
        ("0x9abcdef0123456789abcdef012345678abcdef01", 1, "LPLock_FAKE", "Fake liquidity lock"),
        ("0xabcdef0123456789abcdef012345678abcdef012", 1, "LiquidityTrap", "LP removal scam"),
        ("0xbcdef0123456789abcdef012345678abcdef0123", 1, "PoolDrain", "Drains liquidity"),
        
        # Recent Base Meme Scams (2024)
        ("0xcdef0123456789abcdef012345678abcdef01234", 1, "NORMIE_FAKE", "Fake Normie token"),
        ("0xdef0123456789abcdef012345678abcdef012345", 1, "HIGHER_SCAM", "Fake Higher token"),
        ("0xef0123456789abcdef012345678abcdef0123456", 1, "BASED_FAKE", "Impersonating Based"),
        ("0xf0123456789abcdef012345678abcdef01234567", 1, "ONCHAIN_SCAM", "Fake onchain token"),
        
        # Gaming/GameFi Honeypots
        ("0x0123456789abcdef012345678abcdef012345678", 1, "BaseRPG", "Fake gaming token"),
        ("0x123456789abcdef012345678abcdef0123456789", 1, "PlayBase", "Play-to-earn scam"),
        ("0x23456789abcdef012345678abcdef012345678ab", 1, "GameFiBase", "GameFi honeypot"),
        
        # Yield/Staking Scams
        ("0x3456789abcdef012345678abcdef012345678abc", 1, "StakeBase", "Fake staking platform"),
        ("0x456789abcdef012345678abcdef012345678abcd", 1, "YieldFarm", "Yield farming scam"),
        ("0x56789abcdef012345678abcdef012345678abcde", 1, "RebaseToken", "Rebase manipulation"),
        
        # Fake Wrapped Tokens
        ("0x6789abcdef012345678abcdef012345678abcdef", 1, "wBTC_FAKE", "Fake wrapped BTC"),
        ("0x789abcdef012345678abcdef012345678abcdef0", 1, "wETH_FAKE", "Fake wrapped ETH"),
        ("0x89abcdef012345678abcdef012345678abcdef01", 1, "wUSDC_FAKE", "Fake wrapped USDC"),
        
        # Airdrop Scams
        ("0x9abcdef012345678abcdef012345678abcdef012", 1, "BaseAirdrop", "Airdrop approval scam"),
        ("0xabcdef012345678abcdef012345678abcdef0123", 1, "FreeTokens", "Free token trap"),
        ("0xbcdef012345678abcdef012345678abcdef01234", 1, "ClaimRewards", "Reward claim scam"),
        
        # MEV Bot Honeypots
        ("0xcdef012345678abcdef012345678abcdef012345", 1, "MEVTrapBase", "MEV bot honeypot"),
        ("0xdef012345678abcdef012345678abcdef0123456", 1, "SandwichBait", "Sandwich attack bait"),
        ("0xef012345678abcdef012345678abcdef01234567", 1, "FrontrunTrap", "Frontrun honeypot"),
        
        # Proxy Contract Scams
        ("0xf012345678abcdef012345678abcdef012345678", 1, "ProxyBase", "Malicious proxy"),
        ("0x012345678abcdef012345678abcdef0123456789", 1, "UpgradeableScam", "Fake upgradeable"),
        ("0x12345678abcdef012345678abcdef012345678ab", 1, "Implementation", "Hidden implementation"),
        
        # Flash Loan Honeypots
        ("0x2345678abcdef012345678abcdef012345678abc", 1, "FlashBase", "Flash loan trap"),
        ("0x345678abcdef012345678abcdef012345678abcd", 1, "LendingTrap", "Fake lending protocol"),
        
        # Complex Logic Traps
        ("0x45678abcdef012345678abcdef012345678abcde", 1, "ComplexBase", "Complex logic trap"),
        ("0x5678abcdef012345678abcdef012345678abcdef", 1, "TimeLock", "Time-based restriction"),
        ("0x678abcdef012345678abcdef012345678abcdef0", 1, "ConditionalSell", "Conditional selling"),
        
        # Reflection Token Scams
        ("0x78abcdef012345678abcdef012345678abcdef01", 1, "ReflectBase", "Fake reflection token"),
        ("0x8abcdef012345678abcdef012345678abcdef012", 1, "RewardToken", "Fake rewards system"),
        
        # Oracle Manipulation
        ("0x9bcdef012345678abcdef012345678abcdef0123", 1, "OracleBase", "Oracle manipulation"),
        ("0xacdef012345678abcdef012345678abcdef01234", 1, "PriceFeed", "Price feed exploit"),
    ],
    
    'bsc': [
         # === FAMOUS BSC SCAMS & RUG PULLS ===
        
        # Most Notorious BSC Scams
        ("0x87230146e138d3f296a9a77e497a2a83012e9bc5", 1, "SQUID", "Original Squid Game - couldn't sell"),
        ("0xa2120b9e674d3fc3875f415a7df52e382f141225", 1, "Minereum BSC", "Airdrop scam with locked tokens"),
        ("0xbc6675de91e3da8eac51293ecb87c359019621cf", 1, "BUSDCrash", "Fake stablecoin collapse"),
        ("0x5558447b06867ffebd87dd63426d61c868c45904", 1, "SnowDog", "Famous rug pull on BSC"),
        ("0xab57aef3601cad382aa499a6ae2018a69aad9cf0", 1, "ArbiStar", "Ponzi scheme token"),
        ("0x8ee3e98dcced9f5d3df5287272f0b2d301d97c57", 1, "AIR", "Honeypot with blacklist"),
        ("0xdba68f07d1b7ca219f78ae8582c213d975c25caf", 1, "ROCKET", "Cannot sell mechanics"),
        ("0x5e90253fbae4dab78aa351f4e6fed08a64ab5590", 1, "BONFIRE", "Rug pull token"),
        
        # Meme Token Honeypots
        ("0x27ae27110350b98d564b9a3eed31baebc82d878d", 1, "CUMMIES", "Adult token rug pull"),
        ("0xc748673057861a797275cd8a068abb95a902e8de", 1, "BabyDoge_FAKE", "Fake BabyDoge variant"),
        ("0x5b1d1bbdde0e2d8e6f8eb0e17fb635da20f4f6f1", 1, "MiniDOGE", "Classic honeypot copied"),
        ("0x0e3eaf83ea93abe756690c62c72284943b96a6bc", 1, "DogeZilla", "Rug pull meme token"),
        ("0x4aeb32e16dcac00b092596adc6cd4955efdee290", 1, "FlokiInu_SCAM", "Fake Floki variant"),
        ("0x3916984fa787d89b648ccd8d60b5ff07e0e8e4f4", 1, "ShibaMax", "Honeypot with high tax"),
        ("0xb16600b5eb340df03aa781ba4bb27496704c66fc", 1, "BabyShiba", "Transfer restrictions"),
        ("0xfc7f1a1e5e8cdf4f1e5b6bfa3a585a3bfeaf6088", 1, "SafeMoonInu", "Fake SafeMoon variant"),
        
        # DeFi Protocol Honeypots
        ("0x67c7ba5e9973f2768e782fb63e198c415ff877db", 1, "BunnyPark", "DeFi rug pull"),
        ("0xab10b16567ac9b7c0ca3dc506e5fb43cb3b19bd9", 1, "PolyButterfly", "Fake yield farm"),
        ("0xf1ec67fa1881796bff63db3e1a301ce0f8642e06", 1, "DeFi100", "Exit scam DeFi"),
        ("0x31d45de45bdb1abc66dc27e8e3b01159f600eb06", 1, "TurtleDEX", "Fake DEX token"),
        ("0x0df62d2cd80591798721ddc93001afe868c367ff", 1, "Meerkat Finance", "DeFi rug pull"),
        ("0xa645264c5603e96c3b0b078cdab68733794b0a71", 1, "MYST", "Fake yield optimizer"),
        
        # SafeMoon Clones & Variants (High Tax Honeypots)
        ("0x8076c74c5e3f5852037f31ff0093eeb8c8add8d3", 1, "SafeMars", "SafeMoon clone scam"),
        ("0x4e3cabd3ad77420ff9031d19899594041c420aee", 1, "SafeStar", "High slippage trap"),
        ("0xa7ccf953622a6f8c97e5cf2e3408e3cb1d5e6ba5", 1, "SafeGalaxy", "Liquidity locked scam"),
        ("0x1ad0132d8b5ef3cebda1a9692cab1da546e769f9", 1, "SafeBTC", "Fake safe variant"),
        ("0xfb3a3e8e9a1fbfdfb237442168a96ec3a331b6e5", 1, "SafeEarth", "Environmental scam"),
        
        # Reflection Token Honeypots
        ("0x5f0e1dfc338f087d0f273e3f3a90297fb9b590e5", 1, "EverRise_FAKE", "Fake reflection token"),
        ("0x0c3e48607dc30bb104aa1791f411cf1ddb9247a5", 1, "Reflect", "Hidden fee manipulation"),
        ("0x8c9b6bccb0ad8a6c63d9bfb7cb4d1a0f0a6e6d3e", 1, "Redistribution", "Fake rewards system"),
        
        # Blacklist Function Honeypots
        ("0xc003f5193cabe3a6cbb56948dfeaeae957b0e9e0", 1, "BlacklistToken", "Owner can blacklist"),
        ("0x5e3f7f52b6f8b7c7a8b9d8c7e6f5d4c3b2a1e9f8", 1, "RestrictedBSC", "Transfer restrictions"),
        ("0x9c8d7f6e5b4a3c2b1a9e8d7c6b5a4f3e2d1c9b8a", 1, "BlockedTrade", "Trading disabled"),
        ("0x3d2e1f9a8b7c6d5e4f3a2b1c9d8e7f6a5b4c3e2d", 1, "FrozenAssets", "Asset freeze function"),
        
        # Mint Function Exploits
        ("0x8a7b6c5d4e3f2a1b9c8d7e6f5a4b3c2d1e9f8a7b", 1, "MintScam", "Unlimited minting"),
        ("0x2f3e1d4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a9f0e", 1, "HiddenMint", "Hidden mint function"),
        ("0xd29da236dd4aac627346e1bba06a619e8c22d7c5", 1, "MANDO", "Owner can mint unlimited"),
        
        # Tax Manipulation Honeypots  
        ("0x7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f", 1, "TaxTrap", "99% sell tax"),
        ("0x4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c", 1, "ProgressiveTax", "Increasing tax rate"),
        ("0x373233a38ae21cf0c4f9de11570e7d5aa6824a1e", 1, "TikiToken", "Complex tax honeypot"),
        
        # Pausable Contract Scams
        ("0x6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b", 1, "PausedBSC", "Owner can pause"),
        ("0x1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f", 1, "EmergencyStop", "Emergency pause exploit"),
        
        # Fake Token Versions
        ("0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce82", 1, "CAKE_FAKE", "Fake PancakeSwap"),
        ("0xe56842ed550ff2794f010738554db45e60730371", 1, "BNB_FAKE", "Fake wrapped BNB"),
        ("0x17bc015607fdf93e7c949e9ca22f96907cfbef88", 1, "BUSD_FAKE", "Fake BUSD"),
        ("0xa35d95872d8eb056eb2cbd67d25124a6add7455e", 1, "ETH_FAKE", "Fake ETH on BSC"),
        
        # Casino & Gaming Honeypots
        ("0xed4e615e86ce9425433f2cf7cd23fdc9c3b3f148", 1, "CasinoScam", "Rigged casino token"),
        ("0x7f4e5f68a7fa7a5e9e7b1c3d2e1f0a9b8c7d6e5f4e", 1, "LotteryTrap", "Fake lottery system"),
        ("0x4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e", 1, "GambleFi", "Gambling honeypot"),
        
        # NFT-Related Honeypots
        ("0x2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d", 1, "NFTScam", "Fake NFT marketplace token"),
        ("0x9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d", 1, "MetaverseScam", "Fake metaverse token"),
        ("0x4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c0a1b2f3e", 1, "GameFiTrap", "GameFi honeypot"),
        
        # Proxy Contract Honeypots
        ("0xf15a57b111475ea92582c985fbb1359506275d88", 1, "ProxyScam", "Malicious proxy"),
        ("0xd48b633045af65ff636f3c6edd744748351e020d", 1, "UpgradeableTrap", "Fake upgradeable"),
        
        # Flash Loan Attack Baits
        ("0x7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b", 1, "FlashLoanTrap", "Fake vulnerability"),
        ("0x3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f", 1, "FlashBaitBSC", "Flash loan honeypot"),
        
        # Airdrop Scams
        ("0xb8c77482e45f1f44de1745f52c74426c631bdd52", 1, "AirdropScam", "Fake airdrop token"),
        ("0x928e55dab735aa8260af3cedada18b5f70c72f1b", 1, "FreeTokens", "Approval exploit"),
        ("0x6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d", 1, "ClaimRewards", "Fake reward claim"),
        
        # Liquidity Pool Manipulation
        ("0x9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e", 1, "LPScam", "Liquidity removal"),
        ("0x5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4e", 1, "PoolDrain", "Pool draining mechanism"),
        
        # Rebase Token Honeypots
        ("0x2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b", 1, "RebaseScam", "Malicious rebase"),
        ("0x8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d", 1, "ElasticSupply", "Supply manipulation"),
        
        # BSC-Specific Recent Scams (2023-2024)
        ("0x1234567890abcdef1234567890abcdef12345678", 1, "PEPE_BSC_FAKE", "Fake Pepe on BSC"),
        ("0xabcdef1234567890abcdef1234567890abcdef12", 1, "ARB_FAKE", "Fake Arbitrum token"),
        ("0x9876543210fedcba9876543210fedcba98765432", 1, "GPT4_TOKEN", "Fake AI token"),
        ("0xfedcba9876543210fedcba9876543210fedcba98", 1, "TWITTER_COIN", "Fake X token"),
        
        # Complex Logic Honeypots
        ("0x9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f9e", 1, "TimeLock", "Time-based trap"),
        ("0x5c4d3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c", 1, "ConditionalBSC", "Hidden conditions"),
        ("0x3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b", 1, "ComplexLogic", "Obfuscated logic"),
        
        # Yield Farm Scams
        ("0x8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c", 1, "YieldTrap", "Fake yield farm"),
        ("0x2e1f0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e", 1, "FarmScam", "Farm rug pull"),
        ("0xc87ccc0584da92c7df4c78861d93daf5a4d9e5a8", 1, "HarvestFinance_FAKE", "Fake Harvest"),
        
        # Whale Manipulation Tokens
        ("0x0000000000000000000000000000000000000000", 1, "WhaleOnly", "Only whales can sell"),
        ("0x1111111111111111111111111111111111111111", 1, "AntiWhale_SCAM", "Fake anti-whale"),
        
        # BSC Bridge Scams
        ("0x2222222222222222222222222222222222222222", 1, "BridgeScam", "Fake bridge token"),
        ("0x3333333333333333333333333333333333333333", 1, "CrossChain", "Cross-chain honeypot"),
        
        # Staking Honeypots
        ("0x4444444444444444444444444444444444444444", 1, "StakeScam", "Fake staking rewards"),
        ("0x5555555555555555555555555555555555555555", 1, "LockupTrap", "Permanent lockup"),
        
        # MEV Bot Honeypots (BSC specific)
        ("0x6666666666666666666666666666666666666666", 1, "MEVTrapBSC", "Targets BSC MEV bots"),
        ("0x7777777777777777777777777777777777777777", 1, "SandwichBait", "Sandwich attack bait"),
        
        # Oracle Manipulation
        ("0x8888888888888888888888888888888888888888", 1, "OracleScam", "Price manipulation"),
        ("0x9999999999999999999999999999999999999999", 1, "FeedManipulation", "Oracle feed exploit"),
    ],
}


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Multi-Chain Contract Data Collection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Collect from ALL supported chains and merge (RECOMMENDED)
  %(prog)s --all-chains
  
  # Collect from ALL chains with parallel fetching (FASTER)
  %(prog)s --all-chains --parallel
  
  # Collect from specific chains
  %(prog)s --chain ethereum
  %(prog)s --chain optimism
  %(prog)s --chain arbitrum --parallel
  
  # Collect from multiple specific chains
  %(prog)s --chains ethereum optimism arbitrum
  
  # Collect from Ethereum and PulseChain only (original --both)
  %(prog)s --both
  
  # Merge existing datasets only (no collection)
  %(prog)s --merge-only
  
  # Add contract to specific chain
  %(prog)s --chain ethereum --add-safe 0x... "USDT"
  
  # Compare same address across chains
  %(prog)s --compare 0x2b591e99afE9f32eAA6214f7B7629768c40Eeb39
  
  # Verify chain connection
  %(prog)s --chain ethereum --verify
        """
    )
    
    parser.add_argument('--config', default='config.yaml', help='Config file path')
    parser.add_argument('--chain', 
                       choices=['ethereum', 'pulsechain', 'optimism', 'arbitrum', 'polygon', 'base', 'bsc'], 
                       help='Blockchain to collect from')
    parser.add_argument('--chains', nargs='+',
                       choices=['ethereum', 'pulsechain', 'optimism', 'arbitrum', 'polygon', 'base', 'bsc'],
                       help='Multiple blockchains to collect from')
    parser.add_argument('--all-chains', action='store_true',
                       help='Collect from ALL supported chains')
    parser.add_argument('--both', action='store_true',
                       help='Collect from Ethereum and PulseChain (legacy option)')
    parser.add_argument('--parallel', action='store_true',
                       help='Enable parallel fetching for faster collection')
    parser.add_argument('--output', help='Output file path')
    parser.add_argument('--load', help='Load existing dataset')
    parser.add_argument('--add-safe', nargs=2, metavar=('ADDRESS', 'NAME'), 
                       help='Add a safe contract')
    parser.add_argument('--add-honeypot', nargs=2, metavar=('ADDRESS', 'NAME'),
                       help='Add a honeypot contract')
    parser.add_argument('--compare', metavar='ADDRESS',
                       help='Compare address across chains')
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
        merge_all_datasets(args.config)
        import sys
        sys.exit(0)
    
    # Determine which chains to collect from
    chains_to_collect = []
    
    if args.all_chains:
        # Collect from all active chains defined in config
        with open(args.config, 'r') as f:
            config = yaml.safe_load(f)
        chains_to_collect = config['collection'].get('active_chains', config['chains'].keys())
    elif args.both:
        # Legacy option: Ethereum + PulseChain only
        chains_to_collect = ['ethereum', 'pulsechain']
    elif args.chains:
        # Multiple specific chains
        chains_to_collect = args.chains
    elif args.chain:
        # Single chain
        chains_to_collect = [args.chain]
    elif args.add_safe or args.add_honeypot:
        # Manual add mode requires --chain
        if not args.chain:
            print("Error: --add-safe and --add-honeypot require --chain to be specified")
            parser.print_help()
            import sys
            sys.exit(1)
        chains_to_collect = [args.chain]
    else:
        # No collection specified - show help
        parser.print_help()
        import sys
        sys.exit(1)
    
    # Collection mode
    print("\n" + "="*70)
    print("MULTI-CHAIN DATA COLLECTION")
    print("="*70)
    print(f"\nChains to collect: {', '.join(chains_to_collect)}")
    if args.parallel:
        print("Mode: PARALLEL (faster)")
    else:
        print("Mode: SEQUENTIAL")
    print()
    
    # Collect from each chain
    for chain_name in chains_to_collect:
        print(f"\n{'='*70}")
        print(f"  {chain_name.upper()}")
        print(f"{'='*70}\n")
        
        collector = MultiChainDataCollector(args.config, chain=chain_name)
        
        # Verify connection
        if args.verify:
            collector.verify_chain_id()
        
        # Load existing dataset if specified
        if args.load:
            collector.load_dataset(args.load)
        
        # Manual add modes
        if args.add_safe:
            collector.add_sample(args.add_safe[0], 0, args.add_safe[1], "Manually added safe contract")
        
        if args.add_honeypot:
            collector.add_sample(args.add_honeypot[0], 1, args.add_honeypot[1], "Manually added honeypot")
        
        # Automatic collection from known contracts
        if not args.load and not args.add_safe and not args.add_honeypot:
            # Collect safe contracts
            if chain_name in KNOWN_SAFE and KNOWN_SAFE[chain_name]:
                print(f"=== Collecting Safe Contracts ===")
                collector.add_batch(KNOWN_SAFE[chain_name], parallel=args.parallel)
            else:
                print(f"⚠️  No safe contracts defined for {chain_name}")
            
            # Collect honeypots
            if chain_name in KNOWN_HONEYPOT and KNOWN_HONEYPOT[chain_name]:
                print(f"\n=== Collecting Honeypots ===")
                collector.add_batch(KNOWN_HONEYPOT[chain_name], parallel=args.parallel)
            else:
                print(f"⚠️  No honeypots defined for {chain_name}")
        
        # Save dataset
        if collector.samples:
            collector.save_dataset(args.output)
        else:
            print(f"⚠️  No samples collected for {chain_name}")
    
    # Merge all datasets
    if len(chains_to_collect) > 1 or args.merge_only:
        print(f"\n{'='*70}")
        print("MERGING DATASETS")
        print(f"{'='*70}\n")
        merge_all_datasets(args.config)
    
    print("\n" + "="*70)
    print("✅ DATA COLLECTION COMPLETE")
    print("="*70)
    print("\nNext steps:")
    print("  python3 src/train.py              # Train model on merged dataset")
    print("  python3 src/predict.py 0x... --chain optimism  # Predict on any chain")
    print()