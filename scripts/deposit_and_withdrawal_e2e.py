#!/usr/bin/env python3
"""
Clementine Deposit & Withdrawal E2E Test Script

A robust, step-by-step testing script for Clementine deposit and withdrawal flows.
Features:
- Proper error handling and retry logic
- State persistence for resumability
- Detailed logging
- Step-by-step validation
- Compatible with docker-compose.full.regtest.yml
"""

import argparse
import json
import logging
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
import requests
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings for self-signed certs
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('/tmp/clementine_e2e.log')
    ]
)
logger = logging.getLogger(__name__)


OPERATOR_WITHDRAWAL_AMOUNT = 997000000

# Light Client contract constants
LIGHT_CLIENT_CONTRACT = "0x3100000000000000000000000000000000000001"
LIGHT_CLIENT_FUNCTION_SELECTOR = "0xee82ac5e"  # getBlockHash(uint256)

@dataclass
class Config:
    """Configuration for the test run"""
    # Network endpoints
    aggregator_url: str = "https://127.0.0.1:17000"
    bitcoin_rpc_url: str = "http://127.0.0.1:20443/wallet/admin"
    bitcoin_rpc_user: str = "admin"
    bitcoin_rpc_password: str = "admin"
    citrea_rpc_url: str = "http://127.0.0.1:12345"

    # TLS certificates
    ca_cert_path: str = "core/certs/ca/ca.pem"
    client_cert_path: str = "core/certs/aggregator/aggregator.pem"
    client_key_path: str = "core/certs/aggregator/aggregator.key"

    # Deposit parameters
    deposit_amount: str = "10"
    fee_payer_amount: str = "1"
    cpfp_fee_rate: str = "10.0"

    # Withdrawal parameters (optional)
    withdrawal_address: Optional[str] = None
    withdrawal_amount_sats: Optional[str] = None
    withdrawal_id: str = "0"

    # Paths
    clementine_repo_path: str = "/home/ubuntu/clementine"
    state_file: str = "/tmp/clementine_e2e_state.json"

    # Retry settings
    max_retries: int = 60
    retry_delay: int = 2


@dataclass
class State:
    """Persistent state for resumability"""
    completed_steps: List[str] = field(default_factory=list)
    deposit_address: Optional[str] = None
    deposit_txid: Optional[str] = None
    vout_index: Optional[int] = None
    move_tx_raw: Optional[str] = None
    parent_txid: Optional[str] = None
    fee_payer_address: Optional[str] = None
    calldata: Optional[str] = None
    withdrawal_txid: Optional[str] = None
    withdrawal_vout: Optional[int] = None
    output_spk_hex: Optional[str] = None
    output_amount: Optional[str] = None
    input_signature_hex: Optional[str] = None
    # Withdrawal-specific fields
    signer_address: Optional[str] = None
    destination_address: Optional[str] = None
    dust_txid: Optional[str] = None
    withdrawal_utxo: Optional[str] = None
    optimistic_signature: Optional[str] = None
    operator_signature: Optional[str] = None
    withdrawal_txid_citrea: Optional[str] = None
    # Challenge flow fields
    payout_txid: Optional[str] = None
    payout_vout: Optional[int] = None
    kickoff_txid: Optional[str] = None
    challenge_txid: Optional[str] = None
    operator_xonly_pk: Optional[str] = None
    round_idx: Optional[int] = None
    kickoff_idx: Optional[int] = None
    wallet_name: Optional[str] = None
    database_name: Optional[str] = None  # Which database/operator: clementine0, clementine1, etc.

    def save(self, filepath: str):
        """Save state to file"""
        with open(filepath, 'w') as f:
            json.dump(asdict(self), f, indent=2)
        logger.info(f"State saved to {filepath}")

    @staticmethod
    def load(filepath: str) -> 'State':
        """Load state from file"""
        if not os.path.exists(filepath):
            return State()
        with open(filepath, 'r') as f:
            data = json.load(f)
        logger.info(f"State loaded from {filepath}")
        return State(**data)


class ClementineE2E:
    """Main E2E test orchestrator"""

    def __init__(self, config: Config, resume: bool = False, repeat_step: bool = False):
        self.config = config
        self.state = State.load(config.state_file) if resume else State()
        self.repeat_step = repeat_step

        # Change to repo directory
        os.chdir(config.clementine_repo_path)

        # Set environment variables for TLS
        os.environ['CA_CERT_PATH'] = config.ca_cert_path
        os.environ['CLIENT_CERT_PATH'] = config.client_cert_path
        os.environ['CLIENT_KEY_PATH'] = config.client_key_path

        # Suppress Rust compiler warnings
        os.environ['RUSTFLAGS'] = '-Awarnings'

    def run_cli(self, *args, timeout: int = 120) -> str:
        """Run clementine-cli command (from core repo)"""
        cmd = ['cargo', 'run', '--quiet', '--bin', 'clementine-cli', '--']
        cmd.extend(args)

        logger.debug(f"Running: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            logger.error(f"CLI command failed: {e.stderr}")
            raise
        except subprocess.TimeoutExpired:
            logger.error(f"CLI command timed out after {timeout}s")
            raise

    def run_user_cli(self, *args, timeout: int = 120) -> str:
        """Run clementine-cli command (from separate repo)"""
        cmd = ['clementine-cli']
        cmd.extend(args)

        logger.debug(f"Running: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            logger.error(f"User CLI command failed: {e.stderr}")
            raise
        except subprocess.TimeoutExpired:
            logger.error(f"User CLI command timed out after {timeout}s")
            raise

    def bitcoin_cli(self, *args) -> str:
        """Run bitcoin-cli command"""
        cmd = [
            'bitcoin-cli',
            '-regtest',
            '-rpcport=20443',
            f'-rpcuser={self.config.bitcoin_rpc_user}',
            f'-rpcpassword={self.config.bitcoin_rpc_password}',
            '-rpcwallet=admin'
        ]
        cmd.extend(args)

        logger.debug(f"Running: {' '.join(cmd)}")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            logger.error(f"Bitcoin CLI failed: {e.stderr}")
            raise

    def mine_blocks(self, n: int = 1):
        """Mine n blocks on regtest"""
        logger.info(f"Mining {n} block(s)...")
        self.bitcoin_cli('-generate', str(n))

    def query_kickoff_from_db(self, db_name: str = 'clementine0', deposit_outpoint: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Query PostgreSQL database for the latest kickoff transaction using docker exec

        Args:
            db_name: Database name (clementine0, clementine1, clementine2, or clementine3)
            deposit_outpoint: Optional deposit outpoint to filter by (format: txid:vout)

        Returns:
            Dict with txid, round_idx, kickoff_idx, or None if not found
        """
        try:
            # Query for latest Kickoff transaction using docker exec
            # We need to get both the txid (with proper endianness) and tx_metadata
            # tx_type is stored in the tx_metadata JSON field
            # Filter by deposit_outpoint to get the kickoff for our specific withdrawal
            if deposit_outpoint:
                query = (
                    f"SELECT encode(txid, 'hex') as txid_hex, tx_metadata "
                    f"FROM tx_sender_try_to_send_txs "
                    f"WHERE tx_metadata::jsonb->>'tx_type' = 'Kickoff' "
                    f"AND tx_metadata::jsonb->>'deposit_outpoint' = '{deposit_outpoint}' "
                    f"ORDER BY id DESC "
                    f"LIMIT 1;"
                )
            else:
                query = (
                    "SELECT encode(txid, 'hex') as txid_hex, tx_metadata "
                    "FROM tx_sender_try_to_send_txs "
                    "WHERE tx_metadata::jsonb->>'tx_type' = 'Kickoff' "
                    "ORDER BY id DESC "
                    "LIMIT 1;"
                )

            cmd = [
                'docker', 'exec', 'postgres_db_regtest',
                'psql', '-U', 'clementine', '-d', db_name,
                '-t',  # tuples only (no headers)
                '-A',  # unaligned output
                '-F', '|',  # field separator
                '-c', query
            ]

            logger.debug(f"Running psql query on {db_name}...")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                logger.debug(f"Query failed on {db_name}: {result.stderr}")
                return None

            output = result.stdout.strip()
            if not output:
                logger.debug(f"No Kickoff transactions found in database {db_name}")
                return None

            # Parse output: txid_hex|tx_metadata
            parts = output.split('|')
            if len(parts) != 2:
                logger.warning(f"Unexpected query output format: {output}")
                return None

            txid_hex_raw = parts[0].strip()
            tx_metadata_json = parts[1].strip()

            # The txid from database is in internal byte order (little-endian)
            # We need to reverse the bytes to get the standard txid format
            # The hex string is already in the right format from encode(txid, 'hex')
            # But we need to swap byte order: reverse pairs of characters
            txid_hex = ''.join([txid_hex_raw[i:i+2] for i in range(0, len(txid_hex_raw), 2)][::-1])

            # Parse tx_metadata JSON
            tx_metadata = json.loads(tx_metadata_json)

            # Extract round_idx and kickoff_idx from metadata
            round_idx = tx_metadata.get('round_idx')
            kickoff_idx = tx_metadata.get('kickoff_idx')

            logger.info(f"Found kickoff in database {db_name}:")
            logger.info(f"  Txid: {txid_hex}")
            logger.info(f"  Round idx: {round_idx}")
            logger.info(f"  Kickoff idx: {kickoff_idx}")

            return {
                'txid': txid_hex,
                'round_idx': round_idx,
                'kickoff_idx': kickoff_idx,
                'metadata': tx_metadata
            }

        except subprocess.TimeoutExpired:
            logger.error(f"Database query timed out for {db_name}")
            return None
        except Exception as e:
            logger.debug(f"Error querying database {db_name}: {e}")
            return None

    def wait_for_confirmation(self, txid: str, max_attempts: int = 60) -> bool:
        """Wait for a transaction to be confirmed"""
        logger.info(f"Waiting for confirmation of {txid}...")

        for attempt in range(max_attempts):
            try:
                raw_json = self.bitcoin_cli('getrawtransaction', txid, 'true')
                tx_data = json.loads(raw_json)

                if 'blockhash' in tx_data and tx_data['blockhash']:
                    logger.info(f"Transaction confirmed in block {tx_data['blockhash'][:16]}...")
                    return True
            except Exception as e:
                logger.debug(f"Transaction not confirmed yet: {e}")

            self.mine_blocks(1)
            time.sleep(1)

        logger.error(f"Transaction {txid} not confirmed after {max_attempts} attempts")
        return False

    def mark_step_complete(self, step_name: str):
        """Mark a step as completed"""
        if step_name not in self.state.completed_steps:
            self.state.completed_steps.append(step_name)
            logger.info(f"✓ Step completed: {step_name}")
        self.state.save(self.config.state_file)

    def is_step_complete(self, step_name: str) -> bool:
        """Check if a step is already completed"""
        if self.repeat_step:
            return False
        return step_name in self.state.completed_steps

    def check_block_in_light_client(self, block_number: int) -> Tuple[bool, Optional[str]]:
        """Check if a Bitcoin block is proven in the light client

        Args:
            block_number: Bitcoin block height to check

        Returns:
            Tuple of (is_proven, block_hash)
        """
        # Encode the function call: getBlockHash(uint256)
        data = LIGHT_CLIENT_FUNCTION_SELECTOR + hex(block_number)[2:].zfill(64)

        payload = {
            "jsonrpc": "2.0",
            "method": "eth_call",
            "params": [{
                "to": LIGHT_CLIENT_CONTRACT,
                "data": data
            }, "latest"],
            "id": 1
        }

        try:
            response = requests.post(
                self.config.citrea_rpc_url,
                json=payload,
                timeout=10
            )
            result = response.json()

            if "result" in result:
                block_hash = result["result"]
                # If block hash is all zeros, block is not proven
                if block_hash != "0x0000000000000000000000000000000000000000000000000000000000000000":
                    return True, block_hash
            return False, None
        except Exception as e:
            logger.debug(f"Error checking block {block_number} in light client: {e}")
            return False, None

    def get_tx_block_height(self, txid: str) -> Optional[int]:
        """Get the block height where a transaction was confirmed

        Args:
            txid: Transaction ID

        Returns:
            Block height or None if not confirmed
        """
        try:
            raw_json = self.bitcoin_cli('getrawtransaction', txid, 'true')
            tx_data = json.loads(raw_json)

            if 'blockhash' not in tx_data:
                return None

            blockhash = tx_data['blockhash']

            # Get block info to get height
            block_json = self.bitcoin_cli('getblock', blockhash, '1')
            block_data = json.loads(block_json)

            return block_data['height']
        except Exception as e:
            logger.debug(f"Error getting block height for tx {txid}: {e}")
            return None

    def wait_for_light_client_block(self, target_block_height: int, max_attempts: int = 120) -> bool:
        """Wait for light client to prove a specific Bitcoin block

        Args:
            target_block_height: Bitcoin block height to wait for
            max_attempts: Maximum number of polling attempts

        Returns:
            True if block was proven, False if timeout
        """
        logger.info(f"Waiting for light client to prove Bitcoin block {target_block_height}...")

        for attempt in range(max_attempts):
            is_proven, block_hash = self.check_block_in_light_client(target_block_height)

            if is_proven:
                logger.info(f"✓ Block {target_block_height} is proven in light client")
                logger.info(f"  Block hash: {block_hash}")
                return True

            if attempt % 10 == 0 and attempt > 0:
                logger.info(f"Still waiting... (attempt {attempt}/{max_attempts})")
                # Mine a block to help with light client progression
                self.mine_blocks(1)

            time.sleep(2)

        logger.error(f"Light client did not prove block {target_block_height} within {max_attempts} attempts")
        return False

    def step_0_aggregator_setup(self):
        """Step 0: Setup aggregator (optional, run with --setup)"""
        step_name = "aggregator_setup"
        if self.is_step_complete(step_name):
            logger.info(f"[SKIP] Step 0: Aggregator already set up")
            return

        logger.info("="*70)
        logger.info("[0/9] Setting up aggregator...")
        logger.info("="*70)
        logger.info("This may take several minutes as the system initializes...")

        try:
            output = self.run_cli(
                '--node-url', self.config.aggregator_url,
                'aggregator', 'setup',
                timeout=600  # 10 minutes timeout
            )

            logger.info("Aggregator setup output:")
            logger.info(output)

            self.mark_step_complete(step_name)

        except Exception as e:
            logger.error(f"Failed to setup aggregator: {e}")
            logger.error("You may need to reset the docker environment or wait for services to sync")
            raise

    def step_1_get_deposit_address(self):
        """Step 1: Get deposit address from aggregator"""
        step_name = "get_deposit_address"
        if self.is_step_complete(step_name):
            logger.info(f"[SKIP] Step 1: Using cached deposit address: {self.state.deposit_address}")
            return

        logger.info("="*70)
        logger.info("[1/9] Getting deposit address from aggregator...")
        logger.info("="*70)

        try:
            output = self.run_cli(
                '--node-url', self.config.aggregator_url,
                'aggregator', 'get-deposit-address'
            )

            # Parse deposit address (bcrt1...)
            match = re.search(r'(bcrt1[a-zA-Z0-9]+)', output)
            if not match:
                raise ValueError(f"Could not parse deposit address from: {output}")

            self.state.deposit_address = match.group(1)
            logger.info(f"Deposit address: {self.state.deposit_address}")

            self.mark_step_complete(step_name)

        except Exception as e:
            logger.error(f"Failed to get deposit address: {e}")
            raise

    def step_2_fund_deposit(self):
        """Step 2: Fund the deposit address"""
        step_name = "fund_deposit"
        if self.is_step_complete(step_name):
            logger.info(f"[SKIP] Step 2: Using cached deposit txid: {self.state.deposit_txid}")
            return

        logger.info("="*70)
        logger.info(f"[2/9] Funding deposit address with {self.config.deposit_amount} BTC...")
        logger.info("="*70)

        try:
            self.state.deposit_txid = self.bitcoin_cli(
                'sendtoaddress',
                self.state.deposit_address,
                self.config.deposit_amount
            )

            logger.info(f"Deposit txid: {self.state.deposit_txid}")

            # Mine a block to confirm
            self.mine_blocks(1)

            self.mark_step_complete(step_name)

        except Exception as e:
            logger.error(f"Failed to fund deposit: {e}")
            raise

    def step_3_get_vout_index(self):
        """Step 3: Find vout index for deposit address"""
        step_name = "get_vout_index"
        if self.is_step_complete(step_name):
            logger.info(f"[SKIP] Step 3: Using cached vout index: {self.state.vout_index}")
            return

        logger.info("="*70)
        logger.info("[3/9] Finding vout index for deposit address...")
        logger.info("="*70)

        try:
            # Get raw transaction with verbose output
            raw_json = self.bitcoin_cli('getrawtransaction', self.state.deposit_txid, '1')
            tx_data = json.loads(raw_json)

            # Find the vout index that matches our deposit address
            for vout in tx_data.get('vout', []):
                addresses = vout.get('scriptPubKey', {}).get('address')
                if addresses == self.state.deposit_address:
                    self.state.vout_index = vout['n']
                    logger.info(f"Deposit vout index: {self.state.vout_index}")
                    self.mark_step_complete(step_name)
                    return

            raise ValueError(f"Could not find vout for address {self.state.deposit_address}")

        except Exception as e:
            logger.error(f"Failed to get vout index: {e}")
            raise

    def step_4_register_deposit(self):
        """Step 4: Register deposit with aggregator and get move tx"""
        step_name = "register_deposit"
        if self.is_step_complete(step_name):
            logger.info(f"[SKIP] Step 4: Using cached move tx")
            return

        logger.info("="*70)
        logger.info("[4/9] Registering deposit with aggregator...")
        logger.info("="*70)

        try:
            output = self.run_cli(
                '--node-url', self.config.aggregator_url,
                'aggregator', 'new-deposit',
                '--deposit-outpoint-txid', self.state.deposit_txid,
                '--deposit-outpoint-vout', str(self.state.vout_index)
            )

            logger.info("Aggregator response:")
            logger.info(output)

            # Try to extract raw move tx
            raw_match = re.search(r'Raw move tx:\s*([0-9a-fA-F]+)', output)
            manual_match = re.search(r'Please send manually:\s*([0-9a-fA-F]+)', output)
            auto_match = re.search(r'Move txid:\s*([0-9a-fA-F]{64})', output)

            if raw_match:
                self.state.move_tx_raw = raw_match.group(1)
                logger.info(f"Got raw move tx (length: {len(self.state.move_tx_raw)})")
            elif manual_match:
                self.state.move_tx_raw = manual_match.group(1)
                logger.info(f"Got manual move tx (length: {len(self.state.move_tx_raw)})")
            elif auto_match:
                self.state.parent_txid = auto_match.group(1)
                logger.info(f"Aggregator auto-broadcasted, move txid: {self.state.parent_txid}")
            else:
                raise ValueError("Could not parse move tx or txid from aggregator response")

            self.mark_step_complete(step_name)

        except Exception as e:
            logger.error(f"Failed to register deposit: {e}")
            raise

    def step_5_cpfp_broadcast(self):
        """Step 5: CPFP broadcast the move tx (if we have raw tx)"""
        step_name = "cpfp_broadcast"
        if self.is_step_complete(step_name):
            logger.info(f"[SKIP] Step 5: Using cached parent txid: {self.state.parent_txid}")
            return

        logger.info("="*70)
        logger.info("[5/9] CPFP broadcast of move transaction...")
        logger.info("="*70)

        # If aggregator auto-broadcasted, skip CPFP
        if not self.state.move_tx_raw and self.state.parent_txid:
            logger.info("Aggregator auto-broadcasted, skipping CPFP")
            self.mark_step_complete(step_name)
            return

        if not self.state.move_tx_raw:
            raise ValueError("No move tx raw data available for CPFP")

        try:
            # First CPFP attempt to get fee payer address
            logger.info("Creating CPFP transaction (attempt 1)...")
            output1 = self.run_cli(
                '--node-url', self.config.bitcoin_rpc_url,
                'bitcoin', 'send-tx-with-cpfp',
                '--raw-tx', self.state.move_tx_raw,
                '--bitcoin-rpc-user', self.config.bitcoin_rpc_user,
                '--bitcoin-rpc-password', self.config.bitcoin_rpc_password
            )

            logger.info("CPFP output:")
            logger.info(output1)

            # Extract fee payer address
            fee_match = re.search(r'(bcrt1[a-zA-Z0-9]+)', output1)
            if fee_match:
                self.state.fee_payer_address = fee_match.group(1)
                logger.info(f"Fee payer address: {self.state.fee_payer_address}")

                # Fund the fee payer address
                logger.info(f"Funding fee payer with {self.config.fee_payer_amount} BTC...")
                self.bitcoin_cli(
                    'sendtoaddress',
                    self.state.fee_payer_address,
                    self.config.fee_payer_amount
                )
                time.sleep(1)

                # Second CPFP attempt with funded fee payer
                logger.info("Creating CPFP transaction (attempt 2)...")
                output2 = self.run_cli(
                    '--node-url', self.config.bitcoin_rpc_url,
                    'bitcoin', 'send-tx-with-cpfp',
                    '--raw-tx', self.state.move_tx_raw,
                    '--bitcoin-rpc-user', self.config.bitcoin_rpc_user,
                    '--bitcoin-rpc-password', self.config.bitcoin_rpc_password
                )
                logger.info(output2)

            # Extract parent txid from the raw tx
            raw_json = self.bitcoin_cli('decoderawtransaction', self.state.move_tx_raw)
            tx_data = json.loads(raw_json)
            self.state.parent_txid = tx_data['txid']

            logger.info(f"Parent move txid: {self.state.parent_txid}")

            self.mark_step_complete(step_name)

        except Exception as e:
            logger.error(f"CPFP broadcast failed: {e}")
            raise

    def step_6_wait_for_confirmation(self):
        """Step 6: Wait for parent move tx to confirm"""
        step_name = "wait_confirmation"
        if self.is_step_complete(step_name):
            logger.info(f"[SKIP] Step 6: Parent tx already confirmed")
            return

        logger.info("="*70)
        logger.info("[6/9] Waiting for parent move tx confirmation...")
        logger.info("="*70)

        if not self.wait_for_confirmation(self.state.parent_txid):
            raise RuntimeError("Failed to confirm parent move transaction")

        self.mark_step_complete(step_name)

    def step_7_generate_calldata(self):
        """Step 7: Generate deposit calldata"""
        step_name = "generate_calldata"
        if self.is_step_complete(step_name):
            logger.info(f"[SKIP] Step 7: Using cached calldata")
            return

        logger.info("="*70)
        logger.info("[7/9] Generating deposit calldata...")
        logger.info("="*70)

        try:
            # Use clementine-cli from separate repo
            output = self.run_user_cli(
                'deposit', 'get-deposit-params',
                self.state.parent_txid,
                '--network', 'regtest'
            )
            print(output)

            # Parse the output - format is "Deposit parameters hex: <hex>"
            # We need to extract just the hex part
            lines = output.strip().split('\n')
            last_line = lines[-1].strip()

            # Remove "Deposit parameters hex: " prefix if present
            if last_line.startswith('Deposit parameters hex:'):
                self.state.calldata = last_line.split(':', 1)[1].strip()
            else:
                self.state.calldata = last_line

            logger.info(f"Calldata generated (length: {len(self.state.calldata)} bytes)")

            self.mark_step_complete(step_name)

        except Exception as e:
            logger.error(f"Failed to generate calldata: {e}")
            raise

    def step_8_submit_to_citrea(self):
        """Step 8: Submit calldata to Citrea"""
        step_name = "submit_citrea"
        if self.is_step_complete(step_name):
            logger.info(f"[SKIP] Step 8: Calldata already submitted to Citrea")
            return

        logger.info("="*70)
        logger.info("[8/9] Submitting deposit calldata to Citrea...")
        logger.info("="*70)

        if not self.state.parent_txid:
            raise ValueError("Parent move txid not set. Run steps 1-6 first.")

        try:
            # Step 1: Get the block height where parent move tx was confirmed
            logger.info(f"Getting block height for parent move tx: {self.state.parent_txid}")
            parent_block_height = self.get_tx_block_height(self.state.parent_txid)

            if parent_block_height is None:
                logger.error("Parent move tx is not confirmed yet!")
                raise ValueError("Parent move transaction must be confirmed before submitting to Citrea")

            logger.info(f"Parent move tx confirmed at block height: {parent_block_height}")

            # Step 2: Wait for light client to prove the parent tx's block
            logger.info("")
            logger.info("Waiting for Citrea Light Client to prove the parent tx's block...")
            logger.info("This ensures the deposit will be recognized by Citrea.")
            logger.info("")

            if not self.wait_for_light_client_block(parent_block_height, max_attempts=120):
                logger.error("")
                logger.error("Light client did not prove the required block in time!")
                logger.error("You may need to:")
                logger.error("  1. Check if the light client prover is running")
                logger.error("  2. Wait longer for the light client to catch up")
                logger.error("  3. Mine more blocks to trigger light client updates")
                logger.error("")
                raise TimeoutError(f"Light client did not prove block {parent_block_height}")

            # Step 3: Submit the calldata to Citrea
            logger.info("")
            logger.info("Light client is ready! Submitting deposit calldata to Citrea...")

            payload = {
                "jsonrpc": "2.0",
                "method": "citrea_sendRawDepositTransaction",
                "params": [self.state.calldata],
                "id": 1
            }

            response = requests.post(
                self.config.citrea_rpc_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=30
            )

            response.raise_for_status()
            result = response.json()

            logger.info(f"Citrea response: {json.dumps(result, indent=2)}")

            # Check if the response contains an execution reverted error
            result_str = json.dumps(result)
            if "execution reverted" in result_str.lower():
                logger.error("Transaction execution reverted on Citrea")
                raise ValueError(f"Citrea transaction failed: execution reverted. Response: {result}")

            # Mine some blocks to help with inclusion
            logger.info("Mining blocks to help with Citrea inclusion...")
            self.mine_blocks(3)

            logger.info("")
            logger.info("✓ Deposit calldata submitted successfully!")

            self.mark_step_complete(step_name)

        except Exception as e:
            logger.error(f"Failed to submit to Citrea: {e}")
            raise

    def step_9_start_withdrawal(self):
        """Step 9: Start withdrawal and verify addresses"""
        step_name = "start_withdrawal"
        if self.is_step_complete(step_name):
            logger.info(f"[SKIP] Step 9: Withdrawal already started")
            logger.info(f"  Signer address: {self.state.signer_address}")
            logger.info(f"  Destination address: {self.state.destination_address}")
            return

        logger.info("="*70)
        logger.info("[9/17] Starting withdrawal flow...")
        logger.info("="*70)

        try:
            # Get signer address from environment or generate new wallet
            signer_address = os.environ.get('SIGNER_ADDRESS')

            if not signer_address:
                logger.info("SIGNER_ADDRESS not provided, creating new wallet...")

                # Generate wallet name
                import random
                wallet_name = f"withdrawal_{random.randint(10000, 99999)}"
                self.state.wallet_name = wallet_name

                logger.info(f"Creating wallet: {wallet_name}")

                # Get passphrase from environment or use default test passphrase
                passphrase = os.environ.get('PASSPHRASE', '123')

                # Use expect to automate wallet creation
                expect_script = f'''
spawn clementine-cli wallet create --network regtest {wallet_name} withdrawal
expect "Enter passphrase:"
send "{passphrase}\\r"
expect "Confirm passphrase:"
send "{passphrase}\\r"
expect "Press any key"
send "\\r"
expect "Press ESC"
send "\\x1b"
expect eof
'''

                logger.debug("Running wallet create command...")
                result = subprocess.run(
                    ['expect', '-c', expect_script],
                    capture_output=True,
                    text=True,
                    timeout=120
                )

                if result.returncode != 0:
                    logger.error(f"Wallet creation failed: {result.stderr}")
                    raise RuntimeError(f"Failed to create wallet: {result.stderr}")

                output = result.stdout
                logger.info("Wallet creation output:")
                logger.info(output)

                # Parse signer address from output (witbcrt1p...)
                match = re.search(r'(witbcrt1p[a-zA-Z0-9]+)', output)
                if not match:
                    logger.error("Could not parse signer address from wallet creation output")
                    raise ValueError("Failed to parse signer address from wallet creation")

                signer_address = match.group(1)
                logger.info(f"Generated signer address: {signer_address}")

            # Get or generate destination address
            destination_address = os.environ.get('DESTINATION_ADDRESS') or self.config.withdrawal_address

            if not destination_address:
                logger.info("DESTINATION_ADDRESS not provided, generating new address...")
                destination_address = self.bitcoin_cli('getnewaddress', '', 'bech32m')
                logger.info(f"Generated destination address: {destination_address}")

            # Save to state
            self.state.signer_address = signer_address
            self.state.destination_address = destination_address

            logger.info(f"Signer address: {signer_address}")
            logger.info(f"Destination address: {destination_address}")

            # Call clementine-cli withdraw start
            logger.info("Calling withdraw start to get requirements...")
            start_output = self.run_user_cli(
                'withdraw', 'start',
                '--network', 'regtest',
                signer_address,
                destination_address
            )
            logger.info(start_output)

            self.mark_step_complete(step_name)

        except Exception as e:
            logger.error(f"Failed to start withdrawal: {e}")
            raise

    def step_10_send_dust(self):
        """Step 10: Send dust transaction to signer address"""
        step_name = "send_dust"
        if self.is_step_complete(step_name):
            logger.info(f"[SKIP] Step 10: Dust already sent, txid: {self.state.dust_txid}")
            return

        logger.info("="*70)
        logger.info("[10/17] Sending dust transaction...")
        logger.info("="*70)

        if not self.state.signer_address:
            raise ValueError("Signer address not set. Run step 9 first.")

        try:
            # The dust amount is typically 330 sats for withdrawal
            dust_amount_btc = "0.00000330"

            # Remove 'wit' prefix for actual Bitcoin address
            bitcoin_address = self.state.signer_address.replace('wit', '')

            logger.info(f"Sending {dust_amount_btc} BTC to {bitcoin_address}")
            dust_txid = self.bitcoin_cli(
                'sendtoaddress',
                bitcoin_address,
                dust_amount_btc
            )

            self.state.dust_txid = dust_txid
            logger.info(f"Dust txid: {dust_txid}")

            # Mine a block to confirm
            logger.info("Mining block to confirm...")
            self.mine_blocks(1)
            time.sleep(2)

            self.mark_step_complete(step_name)

        except Exception as e:
            logger.error(f"Failed to send dust: {e}")
            raise

    def step_11_scan_utxo(self):
        """Step 11: Scan for withdrawal UTXO using Bitcoin RPC"""
        step_name = "scan_utxo"
        if self.is_step_complete(step_name):
            logger.info(f"[SKIP] Step 11: UTXO already scanned: {self.state.withdrawal_utxo}")
            return

        logger.info("="*70)
        logger.info("[11/17] Scanning for withdrawal UTXO...")
        logger.info("="*70)

        if not self.state.signer_address or not self.state.dust_txid:
            raise ValueError("Signer address or dust txid not set. Run steps 9 and 10 first.")

        try:
            # Get the signer's Bitcoin address (without 'wit' prefix)
            bitcoin_address = self.state.signer_address.replace('wit', '')
            logger.info(f"Looking for UTXO for address: {bitcoin_address}")
            logger.info(f"In dust transaction: {self.state.dust_txid}")

            # Get raw transaction details
            raw_json = self.bitcoin_cli('getrawtransaction', self.state.dust_txid, '1')
            tx_data = json.loads(raw_json)

            # Find the vout index that matches our signer address
            found = False
            for vout in tx_data.get('vout', []):
                addresses = vout.get('scriptPubKey', {}).get('address')
                if addresses == bitcoin_address:
                    vout_index = vout['n']
                    self.state.withdrawal_utxo = f"{self.state.dust_txid}:{vout_index}"
                    logger.info(f"Found withdrawal UTXO: {self.state.withdrawal_utxo}")
                    logger.info(f"  Amount: {vout.get('value')} BTC")
                    found = True
                    self.mark_step_complete(step_name)
                    break

            if not found:
                logger.error(f"Could not find UTXO for address {bitcoin_address} in transaction {self.state.dust_txid}")
                logger.error("Transaction outputs:")
                for vout in tx_data.get('vout', []):
                    logger.error(f"  vout {vout['n']}: {vout.get('scriptPubKey', {}).get('address')} = {vout.get('value')} BTC")
                raise ValueError(f"Could not find UTXO for address {bitcoin_address}")

        except Exception as e:
            logger.error(f"Failed to scan UTXO: {e}")
            raise

    def step_12_generate_signatures(self):
        """Step 12: Generate or verify withdrawal signatures"""
        step_name = "generate_signatures"
        if self.is_step_complete(step_name):
            logger.info(f"[SKIP] Step 12: Signatures already available")
            return

        logger.info("="*70)
        logger.info("[12/17] Generating/verifying withdrawal signatures...")
        logger.info("="*70)

        if not self.state.withdrawal_utxo:
            raise ValueError("Withdrawal UTXO not set. Run step 11 first.")

        try:
            # Check if signatures are provided via environment
            optimistic_sig = os.environ.get('OPTIMISTIC_SIGNATURE')
            operator_sig = os.environ.get('OPERATOR_SIGNATURE')

            if optimistic_sig:
                logger.info("Using signatures from environment variables")
                self.state.optimistic_signature = optimistic_sig
                self.state.operator_signature = operator_sig
                logger.info(f"Optimistic signature: {optimistic_sig[:32]}...")
                if operator_sig:
                    logger.info(f"Operator signature: {operator_sig[:32]}...")
                self.mark_step_complete(step_name)
                return

            # Try to generate signatures automatically
            logger.info("Generating signatures using clementine-cli...")

            # Get passphrase from environment or use default test passphrase
            passphrase = os.environ.get('PASSPHRASE', '123')
            logger.info(f"Using passphrase from environment (PASSPHRASE env var, default: '123')")

            # Build the command
            cmd_line = (
                f"clementine-cli withdraw generate-withdrawal-signatures "
                f"--network regtest "
                f"{self.state.signer_address} "
                f"{self.state.destination_address} "
                f"{self.state.withdrawal_utxo}"
            )

            # Use expect to provide passphrase to the command
            expect_script = f'''
spawn {cmd_line}
expect "passphrase:"
send "{passphrase}\\r"
expect eof
'''

            logger.debug(f"Running: {cmd_line}")

            result = subprocess.run(
                ['expect', '-c', expect_script],
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.returncode != 0:
                logger.error(f"Signature generation failed: {result.stderr}")
                raise RuntimeError(f"Failed to generate signatures: {result.stderr}")

            output = result.stdout
            logger.info("Signature generation output:")
            logger.info(output)

            # Parse signatures from output
            # Expected format includes lines like:
            # Optimistic withdrawal signature hex: <hex>
            # Operator-paid withdrawal signature hex: <hex>
            optimistic_match = re.search(r'[Oo]ptimistic.*?signature.*?hex:\s*([0-9a-fA-F]+)', output, re.IGNORECASE)
            operator_match = re.search(r'[Oo]perator.*?signature.*?hex:\s*([0-9a-fA-F]+)', output, re.IGNORECASE)

            if not optimistic_match:
                logger.error("Could not parse optimistic signature from output")
                raise ValueError("Failed to parse optimistic signature from clementine-cli output")

            self.state.optimistic_signature = optimistic_match.group(1)
            if operator_match:
                self.state.operator_signature = operator_match.group(1)

            logger.info(f"✓ Optimistic signature: {self.state.optimistic_signature[:32]}...")
            if self.state.operator_signature:
                logger.info(f"✓ Operator signature: {self.state.operator_signature[:32]}...")

            self.mark_step_complete(step_name)

        except Exception as e:
            logger.error(f"Failed to generate signatures: {e}")
            logger.info("")
            logger.info("You can manually generate signatures and set them:")
            logger.info("  export OPTIMISTIC_SIGNATURE=<hex>")
            logger.info("  export OPERATOR_SIGNATURE=<hex>  # Optional")
            raise

    def step_13_submit_safe_withdraw(self):
        """Step 13: Submit safe-withdraw to Citrea"""
        step_name = "submit_safe_withdraw"
        if self.is_step_complete(step_name):
            logger.info(f"[SKIP] Step 13: Safe-withdraw already submitted")
            return

        logger.info("="*70)
        logger.info("[13/17] Submitting safe-withdraw to Citrea...")
        logger.info("="*70)

        if not self.state.optimistic_signature:
            raise ValueError("Signatures not set. Run step 12 first.")

        try:
            # Check for SECRET_KEY
            if not os.environ.get('SECRET_KEY'):
                logger.error("SECRET_KEY not set!")
                logger.info("Set: export SECRET_KEY=0x...")
                raise ValueError("SECRET_KEY environment variable required for Citrea transaction")

            logger.info("Calling send-safe-withdraw...")
            safe_withdraw_output = self.run_user_cli(
                'withdraw', 'send-safe-withdraw',
                '--network', 'regtest',
                self.state.signer_address,
                self.state.destination_address,
                self.state.withdrawal_utxo,
                self.state.optimistic_signature
            )

            logger.info("Safe-withdraw output:")
            logger.info(safe_withdraw_output)

            # Try to extract transaction hash
            tx_match = re.search(r'0x[0-9a-fA-F]{64}', safe_withdraw_output)
            if tx_match:
                self.state.withdrawal_txid_citrea = tx_match.group(0)
                logger.info(f"Citrea tx hash: {self.state.withdrawal_txid_citrea}")

            logger.info("Safe-withdraw submitted successfully!")
            self.mark_step_complete(step_name)

        except Exception as e:
            logger.error(f"Failed to submit safe-withdraw: {e}")
            raise

    def step_14_wait_and_finalize(self):
        """Step 14: Wait for Citrea processing and finalize with aggregator"""
        step_name = "wait_and_finalize"
        if self.is_step_complete(step_name):
            logger.info(f"[SKIP] Step 14: Withdrawal already finalized")
            return

        logger.info("="*70)
        logger.info("[14/17] Waiting for Citrea processing and finalizing...")
        logger.info("="*70)

        try:
            logger.info("Waiting for Citrea sequencer + light client prover...")
            logger.info("This requires:")
            logger.info("  1. Citrea sequencer to process the dust UTXO block")
            logger.info("  2. Light client prover to generate proof")
            logger.info("  3. Light client proof to be committed to Bitcoin")
            logger.info("")

            # Parse withdrawal UTXO (format: txid:vout)
            txid, vout = self.state.withdrawal_utxo.split(':')

            # Get scriptPubKey for destination address
            logger.info("Getting scriptPubKey for destination address...")
            addr_info_json = self.bitcoin_cli('getaddressinfo', self.state.destination_address)
            addr_info = json.loads(addr_info_json)
            output_script_pubkey = addr_info['scriptPubKey']
            logger.info(f"Output scriptPubKey: {output_script_pubkey}")

            output_amount = str(OPERATOR_WITHDRAWAL_AMOUNT)

            # Retry loop for up to 5 minutes (20 attempts * 15 seconds)
            max_attempts = 20
            retry_delay = 15

            logger.info(f"Will retry aggregator new-withdrawal every {retry_delay}s for up to {max_attempts * retry_delay}s...")
            logger.info("")

            for attempt in range(max_attempts):
                try:
                    if attempt > 0:
                        logger.debug(f"Retry attempt {attempt + 1}/{max_attempts}...")

                    withdrawal_output = self.run_cli(
                        '--node-url', self.config.aggregator_url,
                        'aggregator', 'new-withdrawal',
                        '--withdrawal-id', self.config.withdrawal_id,
                        '--input-signature', self.state.operator_signature,
                        '--input-outpoint-txid', txid,
                        '--input-outpoint-vout', vout,
                        '--output-script-pubkey', output_script_pubkey,
                        '--output-amount', output_amount,
                        timeout=60
                    )

                    # Check if withdrawal was successful by looking for the success indicator
                    if "response: Some(RawTx(RawSignedTx" in withdrawal_output:
                        logger.info("")
                        logger.info("Aggregator response:")
                        logger.info(withdrawal_output)
                        logger.info("")
                        logger.info("✓ Withdrawal finalized successfully!")
                        self.mark_step_complete(step_name)
                        return
                    else:
                        logger.debug("Withdrawal response did not contain expected success indicator, retrying...")

                except Exception as e:
                    logger.debug(f"Attempt {attempt + 1} failed: {e}")

                # Wait before next attempt (except on last attempt)
                if attempt < max_attempts - 1:
                    time.sleep(retry_delay)
                    # Mine a block to help with progression
                    self.mine_blocks(1)

            # If we get here, all attempts failed
            logger.error("")
            logger.error(f"Failed to finalize withdrawal after {max_attempts} attempts over {max_attempts * retry_delay}s")
            logger.info("This may indicate that Citrea hasn't finalized the withdrawal yet.")
            logger.info("You can retry this step later by running:")
            logger.info(f"  python3 {__file__} --step 14 --resume")
            logger.info("")
            raise TimeoutError(f"Withdrawal not finalized after {max_attempts * retry_delay}s")

        except Exception as e:
            logger.error(f"Finalization failed: {e}")
            logger.info("See state file for saved progress")
            raise

    def step_15_detect_payout_tx(self):
        """Step 15: Detect operator's payout transaction on Bitcoin"""
        step_name = "detect_payout_tx"
        if self.is_step_complete(step_name):
            logger.info(f"[SKIP] Step 15: Payout tx already detected: {self.state.payout_txid}")
            return

        logger.info("="*70)
        logger.info("[15/17] Detecting operator's payout transaction...")
        logger.info("="*70)

        if not self.state.withdrawal_utxo:
            raise ValueError("Withdrawal UTXO not set. Run steps 9-11 first.")

        try:
            # Parse withdrawal UTXO (format: txid:vout)
            dust_txid, dust_vout = self.state.withdrawal_utxo.split(':')
            logger.info(f"Monitoring for payout tx spending: {self.state.withdrawal_utxo}")

            # Poll for payout transaction
            max_attempts = 120  # 2 minutes with 1 second sleep
            for attempt in range(max_attempts):
                try:
                    # Get raw transaction to check if UTXO is spent
                    raw_json = self.bitcoin_cli('getrawtransaction', dust_txid, '1')
                    tx_data = json.loads(raw_json)

                    # Check if the vout is spent by looking at the spending tx
                    for vout_data in tx_data.get('vout', []):
                        if vout_data['n'] == int(dust_vout):
                            # Check if there's a spending txid in mempool or blockchain
                            # We need to scan mempool and recent blocks for transactions spending this UTXO

                            # Get mempool
                            mempool_json = self.bitcoin_cli('getrawmempool', 'true')
                            mempool = json.loads(mempool_json)

                            # Check each mempool transaction
                            for mempool_txid in mempool.keys():
                                mempool_tx_json = self.bitcoin_cli('getrawtransaction', mempool_txid, '1')
                                mempool_tx = json.loads(mempool_tx_json)

                                # Check if this tx spends our withdrawal UTXO
                                for vin in mempool_tx.get('vin', []):
                                    if (vin.get('txid') == dust_txid and
                                        vin.get('vout') == int(dust_vout)):
                                        # Found the payout tx!
                                        self.state.payout_txid = mempool_txid
                                        logger.info(f"✓ Found payout tx in mempool: {mempool_txid}")

                                        # Mine a block to confirm it
                                        logger.info("Mining block to confirm payout tx...")
                                        self.mine_blocks(1)
                                        time.sleep(2)

                                        # Parse payout tx to find the deposit outpoint
                                        # The payout tx should have an input that references the original deposit
                                        logger.info("Analyzing payout tx to find deposit outpoint...")
                                        payout_tx_json = self.bitcoin_cli('getrawtransaction', self.state.payout_txid, '1')
                                        payout_tx = json.loads(payout_tx_json)

                                        # Look for the output that goes to our destination address
                                        for vout_idx, vout in enumerate(payout_tx.get('vout', [])):
                                            addr = vout.get('scriptPubKey', {}).get('address')
                                            if addr == self.state.destination_address:
                                                self.state.payout_vout = vout_idx
                                                logger.info(f"Payout vout index: {vout_idx}")
                                                break

                                        self.mark_step_complete(step_name)
                                        return

                except Exception as e:
                    logger.debug(f"Payout tx not found yet (attempt {attempt+1}/{max_attempts}): {e}")

                time.sleep(1)

                # Mine a block every 10 attempts to help with block production
                if attempt % 10 == 0 and attempt > 0:
                    logger.info(f"Mining block to help with payout tx (attempt {attempt}/{max_attempts})...")
                    self.mine_blocks(1)

            logger.error("Payout tx not detected within timeout period")
            raise TimeoutError("Operator payout transaction not detected. The operator may not have processed the withdrawal yet.")

        except Exception as e:
            logger.error(f"Failed to detect payout tx: {e}")
            raise

    def step_16_detect_kickoff_tx(self):
        """Step 16: Detect operator's kickoff transaction for reimbursement"""
        step_name = "detect_kickoff_tx"
        if self.is_step_complete(step_name):
            logger.info(f"[SKIP] Step 16: Kickoff tx already detected: {self.state.kickoff_txid}")
            return

        logger.info("="*70)
        logger.info("[16/17] Detecting operator's kickoff transaction...")
        logger.info("="*70)

        if not self.state.payout_txid or not self.state.deposit_txid:
            raise ValueError("Payout tx or deposit txid not set. Run steps 2-4 and 15 first.")

        try:
            # Extract operator's xonly public key from payout tx OP_RETURN
            logger.info("Extracting operator public key from payout tx OP_RETURN...")

            payout_tx_json = self.bitcoin_cli('getrawtransaction', self.state.payout_txid, '1')
            payout_tx = json.loads(payout_tx_json)

            # Find OP_RETURN output
            operator_xonly_pk = None
            for vout in payout_tx.get('vout', []):
                script_type = vout.get('scriptPubKey', {}).get('type')
                if script_type == 'nulldata':
                    # OP_RETURN found - extract the data
                    asm = vout.get('scriptPubKey', {}).get('asm', '')
                    # Format: "OP_RETURN <hex_data>"
                    parts = asm.split()
                    if len(parts) >= 2 and parts[0] == 'OP_RETURN':
                        # The operator xonly pk is the 32-byte (64 hex chars) data
                        hex_data = parts[1]
                        if len(hex_data) == 64:
                            operator_xonly_pk = hex_data
                            logger.info(f"✓ Extracted operator xonly pubkey from OP_RETURN: {operator_xonly_pk}")
                            break

            if not operator_xonly_pk:
                logger.error("Could not find operator xonly pubkey in payout tx OP_RETURN")
                raise ValueError("Failed to extract operator xonly pubkey from payout transaction")

            self.state.operator_xonly_pk = operator_xonly_pk

            # Construct deposit_outpoint to filter for our specific withdrawal
            deposit_outpoint = f"{self.state.deposit_txid}:{self.state.vout_index}"
            logger.info(f"Filtering by deposit_outpoint: {deposit_outpoint}")

            # Retry loop for database query (payout needs to be finalized before kickoff lands in DB)
            logger.info("Querying PostgreSQL database for kickoff transaction...")
            logger.info("This will check all operator databases with retry logic...")
            logger.info("")

            max_attempts = 40  # 40 attempts * 5 seconds = 3.3 minutes
            retry_delay = 5

            kickoff_data = None
            found_db_name = None

            for attempt in range(max_attempts):
                if attempt > 0:
                    logger.debug(f"Retry attempt {attempt + 1}/{max_attempts} for kickoff data...")

                for db_name in ['clementine0', 'clementine1', 'clementine2', 'clementine3']:
                    kickoff_data = self.query_kickoff_from_db(db_name, deposit_outpoint)
                    if kickoff_data:
                        found_db_name = db_name
                        logger.info(f"✓ Found kickoff in {db_name}")
                        break

                if kickoff_data:
                    break

                # Wait before next attempt
                if attempt < max_attempts - 1:
                    time.sleep(retry_delay)
                    # Mine a block periodically to help with progression
                    if attempt % 5 == 0 and attempt > 0:
                        self.mine_blocks(1)
            if kickoff_data:
                # Use data from database
                self.state.kickoff_txid = kickoff_data['txid']
                self.state.round_idx = kickoff_data['round_idx']["Round"]
                self.state.kickoff_idx = kickoff_data['kickoff_idx']
                self.state.database_name = found_db_name

                logger.info("")
                logger.info(f"✓ Kickoff tx detected from database:")
                logger.info(f"  Database: {found_db_name}")
                logger.info(f"  Txid: {self.state.kickoff_txid}")
                logger.info(f"  Round index: {self.state.round_idx}")
                logger.info(f"  Kickoff index: {self.state.kickoff_idx}")
                logger.info(f"  Operator xonly pk: {self.state.operator_xonly_pk}")

                # Wait for kickoff transaction to land on chain
                logger.info("")
                logger.info("Waiting for kickoff transaction to be confirmed on Bitcoin chain...")
                if not self.wait_for_confirmation(self.state.kickoff_txid):
                    logger.error(f"Kickoff transaction {self.state.kickoff_txid} not confirmed on chain")
                    raise TimeoutError(f"Kickoff transaction {self.state.kickoff_txid} not confirmed on chain")
                
                self.mark_step_complete(step_name)
                return

            # If we still don't have kickoff data, provide instructions
            logger.error("")
            logger.error(f"Could not detect kickoff transaction after {max_attempts * retry_delay}s")
            raise TimeoutError(f"Kickoff transaction not found after {max_attempts * retry_delay}s")

        except Exception as e:
            logger.error(f"Failed to detect kickoff tx: {e}")
            raise

    def step_17_challenge_kickoff(self):
        """Step 17: Challenge the operator's kickoff transaction"""
        step_name = "challenge_kickoff"
        if self.is_step_complete(step_name):
            logger.info(f"[SKIP] Step 17: Kickoff already challenged: {self.state.challenge_txid}")
            return

        logger.info("="*70)
        logger.info("[17/17] Challenging operator's kickoff transaction...")
        logger.info("="*70)

        if not all([self.state.kickoff_txid is not None, self.state.operator_xonly_pk is not None,
                    self.state.deposit_txid is not None, self.state.vout_index is not None]):
            raise ValueError("Missing required data. Run steps 2-4, 16 first.")

        try:
            logger.info("Creating challenge transaction using verifier internal-create-signed-txs...")
            logger.info(f"Deposit outpoint: {self.state.deposit_txid}:{self.state.vout_index}")
            logger.info(f"Operator xonly pk: {self.state.operator_xonly_pk}")
            logger.info(f"Round index: {self.state.round_idx}")
            logger.info(f"Kickoff index: {self.state.kickoff_idx}")

            # Determine which verifier node to use based on which database the kickoff came from
            # Each operator/database is paired with a corresponding verifier:
            # clementine0 -> verifier 0 -> https://localhost:17001
            # clementine1 -> verifier 1 -> https://localhost:17002
            # clementine2 -> verifier 2 -> https://localhost:17003
            # clementine3 -> verifier 3 -> https://localhost:17004

            verifier_url = os.environ.get('VERIFIER_URL')

            if not verifier_url and self.state.database_name:
                # Map database name to verifier port
                db_to_port = {
                    'clementine0': 17001,
                    'clementine1': 17002,
                    'clementine2': 17003,
                    'clementine3': 17004,
                }
                port = db_to_port.get(self.state.database_name, 17001)
                verifier_url = f'https://localhost:{port}'
                logger.info(f"Mapped {self.state.database_name} to verifier port {port}")

            if not verifier_url:
                verifier_url = 'https://localhost:17001'  # Default to verifier 0

            logger.info(f"Using verifier node: {verifier_url}")

            # Set client cert paths for verifier
            client_cert_path =  'core/certs/client/client.pem'
            client_key_path = 'core/certs/client/client.key'
            os.environ["CLIENT_CERT_PATH"] = client_cert_path
            os.environ["CLIENT_KEY_PATH"] = client_key_path

            logger.info(f"Using client cert: {client_cert_path}")
            logger.info(f"Using client key: {client_key_path}")

            # Call internal-create-signed-txs to create challenge transaction
            # IMPORTANT: Need to add +1 to round_idx for the create-signed-txs parameter
            challenge_round_idx = self.state.round_idx + 1
            logger.info(f"Using challenge round_idx: {challenge_round_idx} (database round_idx + 1)")

            try:
                challenge_output = self.run_cli(
                    '--node-url', verifier_url,
                    'verifier', 'internal-create-signed-txs',
                    '--deposit-outpoint-txid', self.state.deposit_txid,
                    '--deposit-outpoint-vout', str(self.state.vout_index),
                    '--operator-xonly-pk', self.state.operator_xonly_pk,
                    '--round-idx', str(challenge_round_idx),
                    '--kickoff-idx', str(self.state.kickoff_idx),
                    timeout=300  # 5 minutes for challenge creation
                )

                logger.info("Challenge transaction creation output:")
                logger.info(challenge_output)
                logger.info("")

                # Parse the challenge raw transaction hex from output
                # Expected format: "Challenge: <hex>"
                challenge_match = re.search(r'Challenge:\s*([0-9a-fA-F]+)', challenge_output, re.IGNORECASE)
                if not challenge_match:
                    logger.error("Could not parse Challenge transaction hex from output")
                    logger.error("Expected format: 'Challenge: <hex>'")
                    raise ValueError("Failed to parse challenge transaction from verifier output")

                raw_challenge_hex = challenge_match.group(1)
                logger.info(f"Extracted challenge tx hex (length: {len(raw_challenge_hex)} chars)")

                # Step 1: Fund the raw transaction using bitcoin-cli fundrawtransaction
                logger.info("Funding challenge transaction...")
                fund_result_json = self.bitcoin_cli('fundrawtransaction', raw_challenge_hex, '{"changePosition": 1}')
                fund_result = json.loads(fund_result_json)
                funded_hex = fund_result['hex']
                logger.info(f"✓ Transaction funded (fee: {fund_result.get('fee', 'unknown')} BTC)")

                # Step 2: Sign the funded transaction using bitcoin-cli signrawtransactionwithwallet
                logger.info("Signing challenge transaction...")
                sign_result_json = self.bitcoin_cli('signrawtransactionwithwallet', funded_hex)
                sign_result = json.loads(sign_result_json)

                if not sign_result.get('complete'):
                    logger.error("Transaction signing incomplete!")
                    logger.error(f"Sign result: {sign_result}")
                    raise ValueError("Failed to completely sign challenge transaction")

                signed_hex = sign_result['hex']
                logger.info("✓ Transaction signed successfully")

                # Step 3: Broadcast the signed transaction using bitcoin-cli sendrawtransaction
                logger.info("Broadcasting challenge transaction to Bitcoin...")
                try:
                    txid = self.bitcoin_cli('sendrawtransaction', signed_hex)
                    self.state.challenge_txid = txid.strip()
                    logger.info(f"✓ Challenge tx broadcasted: {self.state.challenge_txid}")

                    # Step 4: Confirm the transaction by mining a block
                    logger.info("Mining block to confirm challenge tx...")
                    self.mine_blocks(1)
                    time.sleep(2)

                    logger.info("")
                    logger.info("✓ Challenge successfully sent and confirmed!")
                    logger.info("The operator's kickoff has been challenged.")
                    logger.info("If the challenge is valid, the operator's collateral will be burned.")
                    logger.info("")

                    self.mark_step_complete(step_name)
                    return

                except subprocess.CalledProcessError as e:
                    logger.error(f"Failed to broadcast challenge tx: {e.stderr}")
                    logger.info("This could mean the transaction is invalid or already broadcast")
                    raise

            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to create challenge transaction: {e.stderr}")
                logger.info("")
                logger.info("This could happen if:")
                logger.info("  1. The verifier node is not running or not accessible")
                logger.info("  2. The deposit/kickoff parameters are incorrect")
                logger.info("  3. The verifier doesn't have the necessary keys")
                logger.info("")
                logger.info("You can try manually with:")
                logger.info(f"  CLIENT_CERT_PATH={client_cert_path} \\")
                logger.info(f"  CLIENT_KEY_PATH={client_key_path} \\")
                logger.info(f"  cargo run --bin clementine-cli -- \\")
                logger.info(f"    --node-url {verifier_url} \\")
                logger.info(f"    verifier internal-create-signed-txs \\")
                logger.info(f"    --deposit-outpoint-txid {self.state.deposit_txid} \\")
                logger.info(f"    --deposit-outpoint-vout {self.state.vout_index} \\")
                logger.info(f"    --operator-xonly-pk {self.state.operator_xonly_pk} \\")
                logger.info(f"    --round-idx {challenge_round_idx} \\")
                logger.info(f"    --kickoff-idx {self.state.kickoff_idx}")
                raise

        except Exception as e:
            logger.error(f"Failed to challenge kickoff: {e}")
            raise

    def run_all_steps(self, run_setup: bool = False):
        """Run all test steps"""
        try:
            if run_setup:
                self.step_0_aggregator_setup()

            self.step_1_get_deposit_address()
            self.step_2_fund_deposit()
            self.step_3_get_vout_index()
            self.step_4_register_deposit()
            self.step_5_cpfp_broadcast()
            self.step_6_wait_for_confirmation()
            self.step_7_generate_calldata()
            self.step_8_submit_to_citrea()
            self.step_9_start_withdrawal()
            self.step_10_send_dust()
            self.step_11_scan_utxo()
            self.step_12_generate_signatures()
            self.step_13_submit_safe_withdraw()
            self.step_14_wait_and_finalize()
            self.step_15_detect_payout_tx()
            self.step_16_detect_kickoff_tx()
            self.step_17_challenge_kickoff()

            logger.info("="*70)
            logger.info("✓ All steps completed successfully!")
            logger.info("="*70)
            logger.info("\nSummary:")
            logger.info(f"  Deposit address: {self.state.deposit_address}")
            logger.info(f"  Deposit txid: {self.state.deposit_txid}")
            logger.info(f"  Parent move txid: {self.state.parent_txid}")
            logger.info(f"  Withdrawal UTXO: {self.state.withdrawal_utxo}")
            logger.info(f"  State file: {self.config.state_file}")

            return True

        except Exception as e:
            logger.error(f"Test failed: {e}")
            logger.error(f"State saved to {self.config.state_file}")
            logger.error("You can resume with --resume flag")
            return False


def main():
    parser = argparse.ArgumentParser(
        description='Clementine E2E Deposit & Withdrawal Test',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run deposit flow only
  python3 deposit_and_withdrawal_e2e.py

  # Run with withdrawal
  python3 deposit_and_withdrawal_e2e.py \\
    --withdrawal-address bcrt1p... \\
    --withdrawal-amount-sats 500000

  # Resume from previous failure
  python3 deposit_and_withdrawal_e2e.py --resume

  # Test single step
  python3 deposit_and_withdrawal_e2e.py --step 1

  # Test range of steps
  python3 deposit_and_withdrawal_e2e.py --step-range 9 13

  # Test withdrawal and challenge flow (steps 9-17)
  python3 deposit_and_withdrawal_e2e.py --resume --step 9
        """
    )

    parser.add_argument('--aggregator-url', default='https://127.0.0.1:17000',
                        help='Aggregator URL')
    parser.add_argument('--bitcoin-rpc-url', default='http://127.0.0.1:20443/wallet/admin',
                        help='Bitcoin RPC URL')
    parser.add_argument('--citrea-rpc-url', default='http://127.0.0.1:12345',
                        help='Citrea RPC URL')
    parser.add_argument('--deposit-amount', default='10',
                        help='Deposit amount in BTC')
    parser.add_argument('--withdrawal-address',
                        help='Withdrawal destination address')
    parser.add_argument('--withdrawal-amount-sats',
                        help='Withdrawal amount in satoshis')
    parser.add_argument('--resume', action='store_true',
                        help='Resume from saved state', default=True)
    parser.add_argument('--setup', action='store_true',
                        help='Run aggregator setup before starting (step 0)')
    parser.add_argument('--step', type=int,
                        help='Run only a specific step (0-17, where 0 is aggregator setup, 9-17 is withdrawal/challenge)')
    parser.add_argument('--step-range', type=int, nargs=2, metavar=('START', 'END'),
                        help='Run a range of steps (inclusive), e.g., --step-range 9 13')
    parser.add_argument('--repeat-step', action='store_true',
                        help='Repeat the same step')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug logging')

    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    # Create config
    config = Config(
        aggregator_url=args.aggregator_url,
        bitcoin_rpc_url=args.bitcoin_rpc_url,
        citrea_rpc_url=args.citrea_rpc_url,
        deposit_amount=args.deposit_amount,
        withdrawal_address=args.withdrawal_address,
        withdrawal_amount_sats=args.withdrawal_amount_sats
    )

    # Create E2E test instance
    e2e = ClementineE2E(config, resume=args.resume, repeat_step=args.repeat_step)

    # Define step methods mapping
    step_methods = {
        0: e2e.step_0_aggregator_setup,
        1: e2e.step_1_get_deposit_address,
        2: e2e.step_2_fund_deposit,
        3: e2e.step_3_get_vout_index,
        4: e2e.step_4_register_deposit,
        5: e2e.step_5_cpfp_broadcast,
        6: e2e.step_6_wait_for_confirmation,
        7: e2e.step_7_generate_calldata,
        8: e2e.step_8_submit_to_citrea,
        9: e2e.step_9_start_withdrawal,
        10: e2e.step_10_send_dust,
        11: e2e.step_11_scan_utxo,
        12: e2e.step_12_generate_signatures,
        13: e2e.step_13_submit_safe_withdraw,
        14: e2e.step_14_wait_and_finalize,
        15: e2e.step_15_detect_payout_tx,
        16: e2e.step_16_detect_kickoff_tx,
        17: e2e.step_17_challenge_kickoff,
    }

    # Run specific step, range of steps, or all steps
    if args.step is not None:
        if args.step not in step_methods:
            logger.error(f"Invalid step: {args.step}. Must be 0-17 (0=aggregator setup, 9-17=withdrawal/challenge)")
            sys.exit(1)

        logger.info(f"Running step {args.step} only...")
        try:
            step_methods[args.step]()
            logger.info(f"✓ Step {args.step} completed successfully")
            sys.exit(0)
        except Exception as e:
            logger.error(f"✗ Step {args.step} failed: {e}")
            sys.exit(1)
    elif args.step_range is not None:
        start_step, end_step = args.step_range

        # Validate range
        if start_step < 0 or end_step > 17 or start_step > end_step:
            logger.error(f"Invalid step range: {start_step}-{end_step}. Must be 0-17 and start <= end")
            sys.exit(1)

        logger.info(f"Running steps {start_step} through {end_step}...")
        try:
            for step_num in range(start_step, end_step + 1):
                logger.info(f"\n{'='*70}")
                logger.info(f"Executing step {step_num}...")
                logger.info(f"{'='*70}")
                step_methods[step_num]()
                logger.info(f"✓ Step {step_num} completed successfully")

            logger.info(f"\n{'='*70}")
            logger.info(f"✓ All steps {start_step}-{end_step} completed successfully!")
            logger.info(f"{'='*70}")
            sys.exit(0)
        except Exception as e:
            logger.error(f"✗ Step range {start_step}-{end_step} failed: {e}")
            sys.exit(1)
    else:
        # Run all steps
        success = e2e.run_all_steps(run_setup=args.setup)
        sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
