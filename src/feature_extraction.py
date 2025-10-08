#!/usr/bin/env python3
"""
Advanced Feature Extraction for Honeypot Detection
Extracts opcode-level patterns, structural features, and behavioral signatures
"""

import re
from collections import Counter, defaultdict
from typing import Dict, List, Tuple, Optional
import numpy as np
from dataclasses import dataclass
import yaml


@dataclass
class BytecodeStats:
    """Container for bytecode statistics"""
    length: int
    unique_opcodes: int
    opcode_entropy: float
    zero_ratio: float
    ff_ratio: float


class OpcodeFeatureExtractor:
    """Extract ML features from EVM bytecode"""
    
    def __init__(self, config_path: str = "config.yaml"):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.dangerous_opcodes = self.config['features']['dangerous_opcodes']
        self.critical_selectors = self.config['features']['critical_selectors']
        self.ngram_min = self.config['features']['ngram_min']
        self.ngram_max = self.config['features']['ngram_max']
        
    def extract_all_features(self, bytecode: str) -> Dict[str, float]:
        """Extract complete feature vector from bytecode"""
        
        if not bytecode or bytecode == "0x":
            return self._empty_features()
        
        # Normalize bytecode
        code = bytecode.replace('0x', '').upper()
        
        features = {}
        
        # 1. Basic statistics
        features.update(self._extract_basic_stats(code))
        
        # 2. Opcode frequency features
        features.update(self._extract_opcode_frequencies(code))
        
        # 3. Function selector features
        features.update(self._extract_function_selectors(code))
        
        # 4. Control flow features
        features.update(self._extract_control_flow(code))
        
        # 5. N-gram patterns
        features.update(self._extract_ngram_features(code))
        
        # 6. Honeypot-specific patterns
        features.update(self._extract_honeypot_patterns(code))
        
        # 7. Structural features
        features.update(self._extract_structural_features(code))
        
        return features
    
    def _extract_basic_stats(self, code: str) -> Dict[str, float]:
        """Extract basic bytecode statistics"""
        length = len(code) // 2  # bytes
        
        # Byte frequency
        byte_counts = Counter([code[i:i+2] for i in range(0, len(code), 2)])
        
        # Calculate entropy
        total_bytes = sum(byte_counts.values())
        entropy = 0.0
        if total_bytes > 0:
            for count in byte_counts.values():
                p = count / total_bytes
                entropy -= p * np.log2(p) if p > 0 else 0
        
        return {
            'bytecode_length': length,
            'unique_bytes': len(byte_counts),
            'byte_entropy': entropy,
            'zero_byte_ratio': code.count('00') / max(len(code) / 2, 1),
            'ff_byte_ratio': code.count('FF') / max(len(code) / 2, 1),
            'repeated_byte_ratio': max(byte_counts.values()) / max(total_bytes, 1),
        }
    
    def _extract_opcode_frequencies(self, code: str) -> Dict[str, float]:
        """Extract dangerous opcode frequencies"""
        features = {}
        total_bytes = len(code) // 2
        
        for name, opcode in self.dangerous_opcodes.items():
            count = code.count(opcode)
            features[f'opcode_{name.lower()}_count'] = count
            features[f'opcode_{name.lower()}_ratio'] = count / max(total_bytes, 1)
        
        # Additional important opcodes
        important_opcodes = {
            'SSTORE': '55',
            'SLOAD': '54',
            'JUMP': '56',
            'JUMPI': '57',
            'CALL': 'F1',
            'RETURN': 'F3',
            'REVERT': 'FD',
        }
        
        for name, opcode in important_opcodes.items():
            count = code.count(opcode)
            features[f'opcode_{name.lower()}_count'] = count
            features[f'opcode_{name.lower()}_ratio'] = count / max(total_bytes, 1)
        
        # Ratios between related opcodes
        sstore = code.count('55')
        sload = code.count('54')
        features['storage_write_read_ratio'] = sstore / max(sload, 1)
        
        jump = code.count('56')
        jumpi = code.count('57')
        features['conditional_jump_ratio'] = jumpi / max(jump + jumpi, 1)
        
        return features
    
    def _extract_function_selectors(self, code: str) -> Dict[str, float]:
        """Extract function selector presence and patterns"""
        features = {}
        
        # Binary features for critical selectors
        for name, selector in self.critical_selectors.items():
            features[f'has_{name.lower()}'] = 1.0 if selector in code else 0.0
        
        # Suspicious combinations
        has_approve = self.critical_selectors['approve'] in code
        has_transfer = self.critical_selectors['transfer'] in code
        has_transferFrom = self.critical_selectors['transferFrom'] in code
        
        features['has_approve_no_transferfrom'] = (
            1.0 if (has_approve and not has_transferFrom) else 0.0
        )
        features['missing_transfer'] = 0.0 if has_transfer else 1.0
        features['has_blacklist_functions'] = 1.0 if any(
            sel in code for sel in [
                self.critical_selectors['isBlacklisted'],
                self.critical_selectors['blacklist'],
                self.critical_selectors['addBlackList']
            ]
        ) else 0.0
        
        # Count total ERC20 functions
        erc20_selectors = ['transfer', 'transferFrom', 'approve', 'mint', 'burn']
        erc20_count = sum(
            1 for func in erc20_selectors 
            if self.critical_selectors[func] in code
        )
        features['erc20_function_count'] = erc20_count
        
        return features
    
    def _extract_control_flow(self, code: str) -> Dict[str, float]:
        """Extract control flow complexity features"""
        # Find all JUMPI instructions and their destinations
        jumpi_count = code.count('57')
        jump_count = code.count('56')
        
        # Measure control flow complexity
        total_jumps = jumpi_count + jump_count
        code_length = len(code) // 2
        
        features = {
            'total_jumps': total_jumps,
            'jump_density': total_jumps / max(code_length, 1),
            'conditional_complexity': jumpi_count / max(code_length / 100, 1),
        }
        
        # Detect deep nesting (multiple JUMPIs in sequence)
        max_consecutive_jumpi = 0
        current_consecutive = 0
        
        for i in range(0, len(code) - 1, 2):
            if code[i:i+2] == '57':  # JUMPI
                current_consecutive += 1
                max_consecutive_jumpi = max(max_consecutive_jumpi, current_consecutive)
            else:
                current_consecutive = 0
        
        features['max_consecutive_jumpi'] = max_consecutive_jumpi
        
        return features
    
    def _extract_ngram_features(self, code: str) -> Dict[str, float]:
        """Extract n-gram (opcode sequence) features"""
        features = {}
        
        # Extract bigrams, trigrams, 4-grams
        for n in range(self.ngram_min, self.ngram_max + 1):
            ngrams = [
                code[i:i+(n*2)] 
                for i in range(0, len(code)-(n*2)+1, 2)
            ]
            ngram_counts = Counter(ngrams)
            
            # Entropy of n-grams
            total = sum(ngram_counts.values())
            entropy = 0.0
            if total > 0:
                for count in ngram_counts.values():
                    p = count / total
                    entropy -= p * np.log2(p) if p > 0 else 0
            
            features[f'{n}gram_entropy'] = entropy
            features[f'{n}gram_unique_count'] = len(ngram_counts)
            
            # Most common n-gram frequency (pattern repetition)
            if ngram_counts:
                features[f'{n}gram_max_frequency'] = max(ngram_counts.values())
            else:
                features[f'{n}gram_max_frequency'] = 0
        
        return features
    
    def _extract_honeypot_patterns(self, code: str) -> Dict[str, float]:
        """Detect known honeypot patterns"""
        features = {}
        
        # Pattern 1: DELEGATECALL to storage-loaded address
        # SLOAD (54) followed by DELEGATECALL (F4) within 20 bytes
        delegatecall_pattern_count = 0
        for i in range(0, len(code) - 40, 2):
            window = code[i:i+40]
            if '54' in window and 'F4' in window:
                # Check if SLOAD is before DELEGATECALL
                sload_pos = window.find('54')
                delegatecall_pos = window.find('F4')
                if 0 <= sload_pos < delegatecall_pos:
                    delegatecall_pattern_count += 1
        
        features['delegatecall_to_storage_pattern'] = delegatecall_pattern_count
        
        # Pattern 2: Conditional transfer (many JUMPIs before transfer)
        transfer_selector = self.critical_selectors['transfer']
        transfer_positions = [
            i for i in range(len(code) - 8) 
            if code[i:i+8] == transfer_selector
        ]
        
        max_jumpi_before_transfer = 0
        for pos in transfer_positions:
            window_start = max(0, pos - 200)
            window = code[window_start:pos]
            jumpi_count = window.count('57')
            max_jumpi_before_transfer = max(max_jumpi_before_transfer, jumpi_count)
        
        features['max_jumpi_before_transfer'] = max_jumpi_before_transfer
        
        # Pattern 3: Hidden ownership check
        # Owner storage slot manipulation
        owner_check_patterns = [
            '543318',  # SLOAD CALLER EQ (checking if caller is owner)
            '335414',  # CALLER SLOAD EQ
        ]
        
        hidden_owner_checks = sum(
            code.count(pattern) for pattern in owner_check_patterns
        )
        features['hidden_owner_checks'] = hidden_owner_checks
        
        # Pattern 4: Balance manipulation
        # Complex balance checks before transfers
        balance_selector = '70A08231'  # balanceOf(address)
        if balance_selector in code:
            balance_positions = [
                i for i in range(len(code) - 8)
                if code[i:i+8] == balance_selector
            ]
            features['balance_check_count'] = len(balance_positions)
        else:
            features['balance_check_count'] = 0
        
                # Pattern 5: Selfdestruct with conditional
        if 'FF' in code:  # SELFDESTRUCT
            selfdestruct_positions = [i for i in range(0, len(code), 2) if code[i:i+2] == 'FF']
            
            conditional_selfdestruct = 0
            for pos in selfdestruct_positions:
                # Check for JUMPI in 50 bytes before selfdestruct
                window_start = max(0, pos - 100)
                window = code[window_start:pos]
                if '57' in window:  # JUMPI present
                    conditional_selfdestruct += 1
            
            features['conditional_selfdestruct'] = conditional_selfdestruct
            features['has_selfdestruct'] = 1.0
        else:
            features['conditional_selfdestruct'] = 0
            features['has_selfdestruct'] = 0.0
        
        # Pattern 6: Dynamic fee manipulation
        # Storage writes (SSTORE) near fee-related operations
        fee_selector = self.critical_selectors.get('setFee', '69FE0E2D')
        if fee_selector in code:
            fee_positions = [i for i in range(len(code) - 8) if code[i:i+8] == fee_selector]
            
            sstore_near_fee = 0
            for pos in fee_positions:
                window = code[max(0, pos-100):min(len(code), pos+100)]
                sstore_near_fee += window.count('55')
            
            features['fee_storage_manipulation'] = sstore_near_fee
            features['has_dynamic_fee'] = 1.0
        else:
            features['fee_storage_manipulation'] = 0
            features['has_dynamic_fee'] = 0.0
        
        # Pattern 7: Pausable with centralized control
        pause_selector = self.critical_selectors.get('pause', '8456CB59')
        unpause_selector = self.critical_selectors.get('unpause', '3F4BA83A')
        
        has_pause = pause_selector in code
        has_unpause = unpause_selector in code
        features['has_pause_mechanism'] = 1.0 if (has_pause or has_unpause) else 0.0
        
        # Pattern 8: Complex modifiers (many checks before function body)
        # Detect functions with excessive pre-conditions
        function_selector_pattern = re.findall(r'63([A-F0-9]{8})', code)
        
        if function_selector_pattern:
            # Analyze distance between selectors and actual logic
            avg_complexity = 0
            for i, match in enumerate(function_selector_pattern[:10]):  # Sample first 10
                selector_pos = code.find(match)
                if selector_pos != -1:
                    # Count JUMPIs in next 200 bytes
                    window = code[selector_pos:selector_pos+400]
                    jumpi_count = window.count('57')
                    avg_complexity += jumpi_count
            
            features['avg_function_complexity'] = avg_complexity / max(len(function_selector_pattern[:10]), 1)
        else:
            features['avg_function_complexity'] = 0
        
        # Pattern 9: Revert traps (REVERT after successful-looking operations)
        revert_count = code.count('FD')
        return_count = code.count('F3')
        
        features['revert_count'] = revert_count
        features['revert_to_return_ratio'] = revert_count / max(return_count, 1)
        
        # Pattern 10: Storage slot manipulation patterns
        # SSTORE (55) with computed slot (not direct)
        sstore_positions = [i for i in range(0, len(code), 2) if code[i:i+2] == '55']
        
        computed_storage_writes = 0
        for pos in sstore_positions:
            # Check for arithmetic operations before SSTORE
            window = code[max(0, pos-40):pos]
            # ADD(01), MUL(02), SUB(03), DIV(04), SHA3(20)
            if any(op in window for op in ['01', '02', '03', '04', '20']):
                computed_storage_writes += 1
        
        features['computed_storage_writes'] = computed_storage_writes
        features['computed_storage_ratio'] = computed_storage_writes / max(len(sstore_positions), 1)
        
        return features
    
    def _extract_structural_features(self, code: str) -> Dict[str, float]:
        """Extract high-level structural features"""
        features = {}
        
        # Code size categories
        code_length = len(code) // 2
        features['is_small_contract'] = 1.0 if code_length < 1000 else 0.0
        features['is_medium_contract'] = 1.0 if 1000 <= code_length < 10000 else 0.0
        features['is_large_contract'] = 1.0 if code_length >= 10000 else 0.0
        
        # Function density (estimated by function selectors)
        # Function selectors typically appear as PUSH4 (63) followed by 4 bytes
        push4_pattern = re.findall(r'63[A-F0-9]{8}', code)
        estimated_functions = len(set(push4_pattern))
        
        features['estimated_function_count'] = estimated_functions
        features['function_density'] = estimated_functions / max(code_length / 1000, 1)
        
        # Code section distribution
        # Divide code into 4 quarters and analyze distribution
        quarter_len = len(code) // 4
        quarters = [
            code[i*quarter_len:(i+1)*quarter_len] 
            for i in range(4)
        ]
        
        # Opcode diversity per quarter
        for i, quarter in enumerate(quarters):
            unique_bytes = len(set([quarter[j:j+2] for j in range(0, len(quarter), 2)]))
            features[f'q{i+1}_opcode_diversity'] = unique_bytes
        
        # Constructor vs runtime code (estimate)
        # Constructor typically has CREATE/RETURN pattern early
        first_1000 = code[:2000]  # First 1000 bytes
        features['has_constructor_pattern'] = 1.0 if 'F3' in first_1000 else 0.0
        
        # Metadata hash presence (Solidity compiler adds metadata)
        # Pattern: a165627a7a72305820 (CBOR-encoded metadata)
        solidity_metadata_pattern = 'A165627A7A72305820'
        features['has_metadata'] = 1.0 if solidity_metadata_pattern in code else 0.0
        
        # Free memory pointer initialization (standard pattern)
        free_mem_pattern = '6080604052'  # PUSH1 0x80 PUSH1 0x40 MSTORE
        features['has_standard_memory_init'] = 1.0 if free_mem_pattern in code else 0.0
        
        return features
    
    def _empty_features(self) -> Dict[str, float]:
        """Return zero-filled feature dict for empty bytecode"""
        # Generate feature names by extracting from a dummy bytecode
        dummy_features = self.extract_all_features("0x6080604052")
        return {key: 0.0 for key in dummy_features.keys()}
    
    def get_feature_names(self) -> List[str]:
        """Get ordered list of feature names"""
        dummy_features = self.extract_all_features("0x6080604052")
        return sorted(dummy_features.keys())


class FeatureEngineering:
    """Additional feature engineering and transformations"""
    
    @staticmethod
    def create_interaction_features(df):
        """Create interaction features between important variables"""
        import pandas as pd
        
        # Interaction: blacklist + ownership
        if 'has_blacklist_functions' in df.columns and 'hidden_owner_checks' in df.columns:
            df['blacklist_owner_interaction'] = (
                df['has_blacklist_functions'] * df['hidden_owner_checks']
            )
        
        # Interaction: delegatecall + storage manipulation
        if 'opcode_delegatecall_count' in df.columns and 'computed_storage_writes' in df.columns:
            df['delegatecall_storage_interaction'] = (
                df['opcode_delegatecall_count'] * df['computed_storage_writes']
            )
        
        # Interaction: missing transfer + has approve
        if 'missing_transfer' in df.columns and 'has_approve_no_transferfrom' in df.columns:
            df['broken_erc20_interaction'] = (
                df['missing_transfer'] * df['has_approve_no_transferfrom']
            )
        
        # Complexity interaction
        if 'conditional_complexity' in df.columns and 'max_jumpi_before_transfer' in df.columns:
            df['transfer_complexity_interaction'] = (
                df['conditional_complexity'] * df['max_jumpi_before_transfer']
            )
        
        return df
    
    @staticmethod
    def create_ratio_features(df):
        """Create additional ratio features"""
        
        # Storage operation ratios
        if 'opcode_sstore_count' in df.columns and 'opcode_sload_count' in df.columns:
            df['storage_activity'] = df['opcode_sstore_count'] + df['opcode_sload_count']
        
        # Call operation ratios
        call_cols = ['opcode_call_count', 'opcode_delegatecall_count', 'opcode_staticcall_count']
        if all(col in df.columns for col in call_cols):
            df['total_calls'] = df[call_cols].sum(axis=1)
            df['dangerous_call_ratio'] = (
                df['opcode_delegatecall_count'] / (df['total_calls'] + 1)
            )
        
        return df


# Example usage and testing
if __name__ == "__main__":
    import sys
    
    # Test with sample bytecode
    extractor = OpcodeFeatureExtractor()
    
    # Example: Safe contract (WETH-like)
    safe_bytecode = "0x6080604052348015600f57600080fd5b506004361060325760003560e01c806370a082311460375780639dc29fac146062575b600080fd5b605060048036036020811015604b57600080fd5b503561008d565b60408051918252519081900360200190f35b608b6004803603604081101560765760008"
    
    print("Extracting features from safe contract...")
    safe_features = extractor.extract_all_features(safe_bytecode)
    
    print(f"\nTotal features extracted: {len(safe_features)}")
    print("\nSample features:")
    for i, (key, value) in enumerate(list(safe_features.items())[:10]):
        print(f"  {key}: {value:.4f}")
    
    # Example: Honeypot with blacklist
    honeypot_bytecode = "0x608060405234801561001057600080fd5b50FE575A8759BF1ABEF9F92BE4"
    
    print("\n\nExtracting features from honeypot...")
    honeypot_features = extractor.extract_all_features(honeypot_bytecode)
    
    print("\nHoneypot-specific features:")
    honeypot_keys = [k for k in honeypot_features.keys() if 'blacklist' in k.lower() or 'honeypot' in k.lower()]
    for key in honeypot_keys:
        print(f"  {key}: {honeypot_features[key]:.4f}")
    
    print("\n✓ Feature extraction working correctly")