#!/usr/bin/env python3
"""
Data Collection Module
Collects bytecode and labels from known contracts
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
    chain: str = "pulsechain"
    collected_at: str = ""
    name: Optional[str] = None
    notes: Optional[str] = None


class DataCollector:
    """Collect contract bytecode for training"""
    
    def __init__(self, config_path: str = "config.yaml"):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.rpc_url = self.config['data']['rpc_url']
        self.cache_dir = Path(self.config['data']['cache_dir'])
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self.timeout = self.config['collection']['timeout']
        self.max_retries = self.config['collection']['max_retries']
        
        self.samples: List[ContractSample] = []
    
    def fetch_bytecode(self, address: str, retries: int = 0) -> Optional[str]:
        """Fetch bytecode from chain using cast"""
        try:
            result = subprocess.run(
                ['cast', 'code', address, '--rpc-url', self.rpc_url],
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            if result.returncode == 0:
                bytecode = result.stdout.strip()
                if bytecode and bytecode != '0x':
                    return bytecode
            
            # Retry on failure
            if retries < self.max_retries:
                time.sleep(1)
                return self.fetch_bytecode(address, retries + 1)
            
            return None
            
        except subprocess.TimeoutExpired:
            print(f"Timeout fetching {address}")
            if retries < self.max_retries:
                return self.fetch_bytecode(address, retries + 1)
            return None
        except Exception as e:
            print(f"Error fetching {address}: {e}")
            return None
    
    def add_sample(self, address: str, label: int, name: str = None, notes: str = None) -> bool:
        """Add a single contract sample"""
        print(f"Collecting {address}...")
        
        bytecode = self.fetch_bytecode(address)
        
        if bytecode:
            sample = ContractSample(
                address=address,
                bytecode=bytecode,
                label=label,
                collected_at=time.strftime("%Y-%m-%d %H:%M:%S"),
                name=name,
                notes=notes
            )
            self.samples.append(sample)
            print(f"✓ Collected {address} ({len(bytecode)} chars)")
            return True
        else:
            print(f"✗ Failed to collect {address}")
            return False
    
    def add_batch(self, contracts: List[Tuple[str, int, str, str]]) -> int:
        """Add multiple contracts"""
        successful = 0
        
        print(f"\nCollecting {len(contracts)} contracts...")
        for address, label, name, notes in tqdm(contracts):
            if self.add_sample(address, label, name, notes):
                successful += 1
            time.sleep(0.5)  # Rate limiting
        
        print(f"\n✓ Successfully collected {successful}/{len(contracts)} contracts")
        return successful
    def save_dataset(self, filepath: str = None):
        """Save collected samples to JSON"""
        if filepath is None:
            filepath = self.config['data']['raw_data_path']
        
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        data = {
            'metadata': {
                'total_samples': len(self.samples),
                'safe_count': sum(1 for s in self.samples if s.label == 0),
                'honeypot_count': sum(1 for s in self.samples if s.label == 1),
                'collection_date': time.strftime("%Y-%m-%d %H:%M:%S"),
                'rpc_url': self.rpc_url
            },
            'samples': [asdict(s) for s in self.samples]
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"\n✓ Dataset saved to {filepath}")
        print(f"  Total samples: {data['metadata']['total_samples']}")
        print(f"  Safe: {data['metadata']['safe_count']}")
        print(f"  Honeypot: {data['metadata']['honeypot_count']}")
    
    def load_dataset(self, filepath: str = None) -> List[ContractSample]:
        """Load previously collected dataset"""
        if filepath is None:
            filepath = self.config['data']['raw_data_path']
        
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        self.samples = [
            ContractSample(**sample) 
            for sample in data['samples']
        ]
        
        print(f"✓ Loaded {len(self.samples)} samples from {filepath}")
        return self.samples


# Known contract addresses for training
KNOWN_SAFE_CONTRACTS = [
    # Ethereum Mainnet - Well-known safe contracts
    ("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", 0, "WETH", "Wrapped ETH"),
    ("0xdAC17F958D2ee523a2206206994597C13D831ec7", 0, "USDT", "Tether USD"),
    ("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", 0, "USDC", "USD Coin"),
    ("0x6B175474E89094C44Da98b954EedeAC495271d0F", 0, "DAI", "Dai Stablecoin"),
    ("0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599", 0, "WBTC", "Wrapped BTC"),
    ("0x514910771AF9Ca656af840dff83E8264EcF986CA", 0, "LINK", "Chainlink"),
    ("0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9", 0, "AAVE", "Aave Token"),
    ("0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984", 0, "UNI", "Uniswap"),
    ("0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE", 0, "SHIB", "Shiba Inu"),
    ("0x4d224452801ACEd8B2F0aebE155379bb5D594381", 0, "APE", "ApeCoin"),
]

KNOWN_HONEYPOT_CONTRACTS = [
    # Add known honeypot addresses here
    # Format: (address, 1, "name", "notes")
    # Example placeholders - replace with real honeypots
    # PulseChain Specific (Examples of common scam vectors)
    ("0xb1f52d529390ec28483fe7689a4ea26fce2956f4", 1, "Coin-Plasma", "Proxy contract with hidden malicious logic"),
    ("0x8560ed0254b982080aeca2832a2f513b4b723735", 1, "Pulse Guardian", "Unlimited minting and blacklist functions"),
    ("0x1b975d5e5559c1b29a242f8e8aa215108c350bca", 1, "PLS 2.0", "Fake upgrade token, transfer hook drains funds"),
    ("0x3a5412364b4f5713c054911d2799c7553f1cf1a2", 1, "PULSEX Airdrop", "Phishing scam, requests wallet connection to drain assets"),
    ("0x0000a89a42133a82c44e677c108f37722f38a529", 1, "FreeClaim PLS", "Common airdrop scam type, approve() exploit"),

    # Ethereum (Pre-PulseChain Fork - Pre May 2023)
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


# Example 
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Collect contract data for ML training')
    parser.add_argument('--config', default='config.yaml', help='Config file path')
    parser.add_argument('--output', help='Output file path')
    parser.add_argument('--load', help='Load existing dataset')
    parser.add_argument('--add-safe', nargs=2, metavar=('ADDRESS', 'NAME'), 
                        help='Add a safe contract')
    parser.add_argument('--add-honeypot', nargs=2, metavar=('ADDRESS', 'NAME'),
                        help='Add a honeypot contract')
    
    args = parser.parse_args()
    
    collector = DataCollector(args.config)
    
    if args.load:
        collector.load_dataset(args.load)
    
    if args.add_safe:
        collector.add_sample(args.add_safe[0], 0, args.add_safe[1], "Manually added safe contract")
    
    if args.add_honeypot:
        collector.add_sample(args.add_honeypot[0], 1, args.add_honeypot[1], "Manually added honeypot")
    
    # Collect default dataset if no existing data
    if not args.load and not args.add_safe and not args.add_honeypot:
        print("Collecting default dataset...")
        print("\n=== Collecting Safe Contracts ===")
        collector.add_batch(KNOWN_SAFE_CONTRACTS)
        
        print("\n=== Collecting Honeypot Contracts ===")
        collector.add_batch(KNOWN_HONEYPOT_CONTRACTS)
    
    # Save dataset
    collector.save_dataset(args.output)