"""
Solana DeFi Security Patterns - Advanced Vulnerability Detection
Extended patterns for DeFi protocols: AMMs, Lending, Staking, etc.
"""

# =============================================================================
# DEFI-SPECIFIC VULNERABILITIES
# =============================================================================

DEFI_VULNERABILITIES = {
    # =========================================================================
    # FLASH LOAN ATTACKS
    # =========================================================================
    'flash_loan_manipulation': {
        'id': 'DEFI-001',
        'title': 'Flash Loan Price Manipulation',
        'severity': 'CRITICAL',
        'category': 'flash_loan',
        'description': 'Price oracle can be manipulated within a single transaction using flash loans',
        'patterns': [
            r'get_price\(',
            r'oracle.*price',
            r'spot_price',
            r'reserve.*ratio',
            r'calculate_price',
        ],
        'vulnerable_indicators': [
            'Using AMM spot price as oracle',
            'No TWAP (Time-Weighted Average Price)',
            'Single-block price reading',
            'No flash loan guard',
        ],
        'fix': 'Use TWAP oracles (Pyth, Switchboard), add flash loan guards, or require multi-block price confirmation',
        'example_vulnerable': '''
// VULNERABLE: Using spot price directly
pub fn get_collateral_value(pool: &Pool, amount: u64) -> u64 {
    let price = pool.reserve_a / pool.reserve_b;  // Spot price - manipulable!
    amount * price
}
''',
        'example_fixed': '''
// FIXED: Using Pyth oracle with staleness check
pub fn get_collateral_value(
    pyth_price_account: &AccountInfo,
    amount: u64,
    max_staleness: i64,
) -> Result<u64> {
    let price_feed = load_price_feed_from_account_info(pyth_price_account)?;
    let current_price = price_feed.get_price_no_older_than(
        Clock::get()?.unix_timestamp,
        max_staleness
    ).ok_or(ErrorCode::StalePrice)?;
    
    Ok(amount.checked_mul(current_price.price as u64).ok_or(ErrorCode::Overflow)?)
}
'''
    },

    'flash_loan_reentrancy': {
        'id': 'DEFI-002',
        'title': 'Flash Loan Reentrancy',
        'severity': 'CRITICAL',
        'category': 'flash_loan',
        'description': 'State not properly locked during flash loan callback',
        'patterns': [
            r'flash_loan',
            r'callback',
            r'borrow.*repay',
        ],
        'fix': 'Use reentrancy guard, update state before external calls',
    },

    # =========================================================================
    # AMM/DEX VULNERABILITIES
    # =========================================================================
    'amm_slippage_manipulation': {
        'id': 'DEFI-003',
        'title': 'Missing Slippage Protection',
        'severity': 'CRITICAL',
        'category': 'amm',
        'description': 'Swap has no minimum output amount, vulnerable to sandwich attacks',
        'patterns': [
            r'swap\(',
            r'exchange\(',
            r'trade\(',
            r'amount_out',
        ],
        'vulnerable_indicators': [
            'No minimum_amount_out parameter',
            'No slippage tolerance check',
            'No deadline/expiry check',
        ],
        'fix': 'Add minimum_amount_out parameter and deadline',
        'example_vulnerable': '''
// VULNERABLE: No slippage protection
pub fn swap(ctx: Context<Swap>, amount_in: u64) -> Result<()> {
    let amount_out = calculate_output(amount_in, &ctx.accounts.pool);
    transfer_tokens(amount_out)?;  // Attacker can sandwich this!
    Ok(())
}
''',
        'example_fixed': '''
// FIXED: With slippage and deadline protection
pub fn swap(
    ctx: Context<Swap>,
    amount_in: u64,
    minimum_amount_out: u64,
    deadline: i64,
) -> Result<()> {
    require!(Clock::get()?.unix_timestamp <= deadline, ErrorCode::Expired);
    
    let amount_out = calculate_output(amount_in, &ctx.accounts.pool);
    require!(amount_out >= minimum_amount_out, ErrorCode::SlippageExceeded);
    
    transfer_tokens(amount_out)?;
    Ok(())
}
'''
    },

    'constant_product_violation': {
        'id': 'DEFI-004',
        'title': 'Constant Product Invariant Not Enforced',
        'severity': 'CRITICAL',
        'category': 'amm',
        'description': 'AMM does not verify k = x * y invariant after swap',
        'patterns': [
            r'reserve_a.*reserve_b',
            r'constant_product',
            r'invariant',
        ],
        'fix': 'Always verify k_new >= k_old after every swap',
    },

    # =========================================================================
    # LENDING PROTOCOL VULNERABILITIES
    # =========================================================================
    'lending_liquidation_threshold': {
        'id': 'DEFI-005',
        'title': 'Incorrect Liquidation Threshold',
        'severity': 'CRITICAL',
        'category': 'lending',
        'description': 'Liquidation can occur at wrong health factor or be front-run',
        'patterns': [
            r'liquidat',
            r'health_factor',
            r'collateral_ratio',
            r'ltv',
        ],
        'fix': 'Use precise health factor calculation, add liquidation bonus caps',
    },

    'lending_interest_rate_manipulation': {
        'id': 'DEFI-006',
        'title': 'Interest Rate Manipulation',
        'severity': 'WARNING',
        'category': 'lending',
        'description': 'Interest rate model can be gamed through large deposits/withdrawals',
        'patterns': [
            r'interest_rate',
            r'utilization_rate',
            r'borrow_rate',
            r'supply_rate',
        ],
        'fix': 'Use time-weighted utilization, add rate change caps',
    },

    'bad_debt_socialization': {
        'id': 'DEFI-007',
        'title': 'Improper Bad Debt Handling',
        'severity': 'CRITICAL',
        'category': 'lending',
        'description': 'Protocol does not properly handle underwater positions',
        'patterns': [
            r'bad_debt',
            r'shortfall',
            r'underwater',
            r'insolvent',
        ],
        'fix': 'Implement insurance fund, bad debt socialization, or protocol backstop',
    },

    # =========================================================================
    # STAKING VULNERABILITIES
    # =========================================================================
    'staking_reward_calculation': {
        'id': 'DEFI-008',
        'title': 'Incorrect Reward Calculation',
        'severity': 'CRITICAL',
        'category': 'staking',
        'description': 'Reward calculation has precision loss or can be drained',
        'patterns': [
            r'reward',
            r'emission',
            r'distribute',
            r'claim',
        ],
        'vulnerable_indicators': [
            'Division before multiplication',
            'No precision scaling (missing 1e9 or similar)',
            'Reward per token can overflow',
        ],
        'fix': 'Use scaled math (1e9 precision), multiply before divide',
        'example_vulnerable': '''
// VULNERABLE: Precision loss
pub fn calculate_reward(staked: u64, total_staked: u64, rewards: u64) -> u64 {
    (staked / total_staked) * rewards  // Division first = precision loss!
}
''',
        'example_fixed': '''
// FIXED: Scale up for precision
const PRECISION: u128 = 1_000_000_000;

pub fn calculate_reward(staked: u64, total_staked: u64, rewards: u64) -> Result<u64> {
    let scaled_share = (staked as u128)
        .checked_mul(PRECISION)
        .ok_or(ErrorCode::Overflow)?
        .checked_div(total_staked as u128)
        .ok_or(ErrorCode::DivByZero)?;
    
    let reward = scaled_share
        .checked_mul(rewards as u128)
        .ok_or(ErrorCode::Overflow)?
        .checked_div(PRECISION)
        .ok_or(ErrorCode::Overflow)?;
    
    Ok(reward as u64)
}
'''
    },

    'staking_deposit_front_run': {
        'id': 'DEFI-009',
        'title': 'Staking Deposit Front-Running',
        'severity': 'WARNING',
        'category': 'staking',
        'description': 'First depositor can steal from subsequent depositors',
        'patterns': [
            r'deposit.*stake',
            r'first_deposit',
            r'initial_shares',
        ],
        'fix': 'Require minimum initial deposit, or use virtual reserves',
    },

    # =========================================================================
    # ORACLE VULNERABILITIES
    # =========================================================================
    'oracle_stale_price': {
        'id': 'DEFI-010',
        'title': 'Stale Oracle Price',
        'severity': 'CRITICAL',
        'category': 'oracle',
        'description': 'Oracle price staleness not checked',
        'patterns': [
            r'pyth',
            r'switchboard',
            r'chainlink',
            r'oracle',
            r'price_feed',
        ],
        'vulnerable_indicators': [
            'No timestamp check',
            'No confidence interval check',
            'No staleness threshold',
        ],
        'fix': 'Check price timestamp, confidence interval, and set max staleness',
        'example_vulnerable': '''
// VULNERABLE: No staleness check
pub fn get_price(oracle: &AccountInfo) -> Result<i64> {
    let price_feed = load_price_feed(oracle)?;
    Ok(price_feed.price)  // Could be hours old!
}
''',
        'example_fixed': '''
// FIXED: With staleness and confidence check
pub fn get_price(oracle: &AccountInfo, max_staleness_secs: i64) -> Result<i64> {
    let price_feed = load_price_feed(oracle)?;
    let price = price_feed.get_price_no_older_than(
        Clock::get()?.unix_timestamp,
        max_staleness_secs
    ).ok_or(ErrorCode::StalePrice)?;
    
    // Check confidence interval (price uncertainty)
    require!(
        price.conf < (price.price as u64) / 100,  // < 1% confidence
        ErrorCode::PriceUncertain
    );
    
    Ok(price.price)
}
'''
    },

    'oracle_single_source': {
        'id': 'DEFI-011',
        'title': 'Single Oracle Source',
        'severity': 'WARNING',
        'category': 'oracle',
        'description': 'Relying on single oracle without fallback',
        'patterns': [
            r'oracle',
            r'price_feed',
        ],
        'fix': 'Use multiple oracle sources with median/fallback logic',
    },

    # =========================================================================
    # GOVERNANCE VULNERABILITIES
    # =========================================================================
    'governance_flash_loan_voting': {
        'id': 'DEFI-012',
        'title': 'Flash Loan Governance Attack',
        'severity': 'CRITICAL',
        'category': 'governance',
        'description': 'Voting power can be borrowed via flash loan to pass proposals',
        'patterns': [
            r'vote',
            r'proposal',
            r'governance',
            r'voting_power',
        ],
        'fix': 'Use vote escrow (veToken), snapshot voting power at proposal creation',
    },

    'governance_timelock_bypass': {
        'id': 'DEFI-013',
        'title': 'Timelock Bypass',
        'severity': 'CRITICAL',
        'category': 'governance',
        'description': 'Critical functions can be called without timelock delay',
        'patterns': [
            r'timelock',
            r'delay',
            r'admin',
            r'upgrade',
        ],
        'fix': 'Enforce timelock on all admin/upgrade functions',
    },

    # =========================================================================
    # VAULT VULNERABILITIES
    # =========================================================================
    'vault_share_inflation': {
        'id': 'DEFI-014',
        'title': 'Vault Share Inflation Attack',
        'severity': 'CRITICAL',
        'category': 'vault',
        'description': 'First depositor can inflate share price to steal from others',
        'patterns': [
            r'vault',
            r'shares',
            r'deposit.*mint',
            r'total_supply',
        ],
        'vulnerable_indicators': [
            'No minimum deposit',
            'No virtual reserves',
            'First deposit can be tiny',
        ],
        'fix': 'Add minimum initial deposit, dead shares, or virtual reserves',
        'example_vulnerable': '''
// VULNERABLE: Share inflation possible
pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    let shares = if ctx.accounts.vault.total_supply == 0 {
        amount
    } else {
        amount * ctx.accounts.vault.total_supply / ctx.accounts.vault.total_assets
    };
    mint_shares(shares)?;  // First depositor can manipulate!
    Ok(())
}
''',
        'example_fixed': '''
// FIXED: Virtual reserves prevent inflation
const VIRTUAL_RESERVES: u64 = 1_000_000;  // 1e6

pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    let total_supply = ctx.accounts.vault.total_supply + VIRTUAL_RESERVES;
    let total_assets = ctx.accounts.vault.total_assets + VIRTUAL_RESERVES;
    
    let shares = amount
        .checked_mul(total_supply)
        .ok_or(ErrorCode::Overflow)?
        .checked_div(total_assets)
        .ok_or(ErrorCode::DivByZero)?;
    
    require!(shares > 0, ErrorCode::ZeroShares);
    mint_shares(shares)?;
    Ok(())
}
'''
    },
}

# =============================================================================
# DEFI VULNERABILITY CHECKLIST FOR PROMPT
# =============================================================================

DEFI_CHECKLIST = """
### DEFI-SPECIFIC VULNERABILITIES (Additional checks for DeFi protocols)

**Flash Loan Attacks:**
- DEFI-001: Is price derived from on-chain AMM reserves? (Use TWAP/Pyth/Switchboard instead)
- DEFI-002: Is state updated before external calls in flash loan callbacks?

**AMM/DEX Security:**
- DEFI-003: Does swap have minimum_amount_out and deadline parameters?
- DEFI-004: Is constant product invariant (k = x * y) verified after swaps?

**Lending Protocol:**
- DEFI-005: Is liquidation threshold calculation precise? Can it be front-run?
- DEFI-006: Can interest rate be manipulated by large deposits/withdrawals?
- DEFI-007: How is bad debt handled when positions go underwater?

**Staking/Rewards:**
- DEFI-008: Is reward calculation using scaled math (multiply before divide)?
- DEFI-009: Can first depositor steal from subsequent depositors?

**Oracle Security:**
- DEFI-010: Is oracle price staleness checked? Is confidence interval validated?
- DEFI-011: Is there a fallback if primary oracle fails?

**Governance:**
- DEFI-012: Can voting power be flash loaned to pass proposals?
- DEFI-013: Are admin functions protected by timelock?

**Vault Security:**
- DEFI-014: Can first depositor inflate share price? (virtual reserves/dead shares needed)
"""

# =============================================================================
# HELPER FUNCTION
# =============================================================================

def get_defi_vulnerability_ids():
    """Get all DeFi vulnerability IDs"""
    return [v['id'] for v in DEFI_VULNERABILITIES.values()]

def get_defi_vulnerability(vuln_id: str):
    """Get DeFi vulnerability by ID"""
    for v in DEFI_VULNERABILITIES.values():
        if v['id'] == vuln_id:
            return v
    return None

def is_defi_project(file_contents: str) -> bool:
    """Detect if project is likely a DeFi protocol"""
    defi_indicators = [
        'swap', 'amm', 'liquidity', 'pool', 'vault',
        'lend', 'borrow', 'collateral', 'liquidat',
        'stake', 'reward', 'emission', 'claim',
        'oracle', 'price_feed', 'pyth', 'switchboard',
        'governance', 'vote', 'proposal', 'timelock',
        'flash_loan', 'flash'
    ]
    
    content_lower = file_contents.lower()
    matches = sum(1 for indicator in defi_indicators if indicator in content_lower)
    
    return matches >= 3  # At least 3 DeFi indicators
