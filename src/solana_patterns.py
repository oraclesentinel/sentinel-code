"""
Solana Security Patterns - Vulnerability Detection Database
Part of Sentinel Code - Oracle Sentinel Intelligence Layer

This module contains patterns for detecting common Solana/Anchor vulnerabilities.
Reference: https://github.com/coral-xyz/sealevel-attacks
"""

# =============================================================================
# SOLANA PROJECT DETECTION
# =============================================================================

SOLANA_PROJECT_INDICATORS = {
    # Files that indicate a Solana project
    'files': [
        'Anchor.toml',
        'Cargo.toml',  # Combined with solana dependency check
        'Xargo.toml',
    ],
    # Dependencies in Cargo.toml that indicate Solana
    'cargo_dependencies': [
        'anchor-lang',
        'anchor-spl',
        'solana-program',
        'solana-sdk',
        'spl-token',
        'spl-associated-token-account',
        'mpl-token-metadata',
    ],
    # Directory patterns
    'directories': [
        'programs/',
        'target/deploy/',
        'target/idl/',
        'migrations/',
        'tests/',
    ],
    # File content patterns
    'content_patterns': [
        'use anchor_lang::prelude::*',
        'use solana_program::',
        '#[program]',
        '#[derive(Accounts)]',
        'declare_id!',
        'entrypoint!',
    ]
}

# =============================================================================
# FRAMEWORK DETECTION
# =============================================================================

FRAMEWORK_INDICATORS = {
    'anchor': [
        'anchor-lang',
        '#[program]',
        '#[derive(Accounts)]',
        '#[account]',
        'use anchor_lang::prelude::*',
        'Context<',
        'Anchor.toml',
    ],
    'native': [
        'solana_program::entrypoint',
        'entrypoint!',
        'ProgramResult',
        'process_instruction',
        'Pubkey::find_program_address',
    ],
    'seahorse': [
        'from seahorse.prelude import *',
        '@instruction',
        'declare_id',
    ]
}

# =============================================================================
# CRITICAL VULNERABILITIES (Severity: CRITICAL)
# =============================================================================

CRITICAL_VULNERABILITIES = {
    'missing_signer_check': {
        'id': 'SOL-001',
        'title': 'Missing Signer Check',
        'severity': 'CRITICAL',
        'description': 'Instruction does not verify that required accounts have signed the transaction',
        'patterns': [
            # Native Solana
            r'if\s+!\s*\w+\.is_signer',
            r'AccountInfo.*without.*signer',
        ],
        'anti_patterns': [
            # These indicate proper checks
            r'#\[account\(.*signer.*\)\]',
            r'\.is_signer\s*\{',
            r'Signer<',
            r'#\[account\(mut,\s*signer\)\]',
        ],
        'vulnerable_example': '''
// VULNERABLE: No signer check on authority
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    vault.balance -= amount;  // Anyone can call this!
    Ok(())
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub authority: AccountInfo<'info>,  // Missing Signer constraint!
}
''',
        'fixed_example': '''
// FIXED: Added Signer constraint
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    vault.balance -= amount;
    Ok(())
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,  // Now requires signature
}
''',
        'references': [
            'https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/0-signer-authorization',
        ]
    },

    'missing_owner_check': {
        'id': 'SOL-002',
        'title': 'Missing Owner Check',
        'severity': 'CRITICAL',
        'description': 'Account owner is not verified, allowing attacker to pass fake accounts',
        'patterns': [
            r'AccountInfo<',
            r'UncheckedAccount<',
            r'\.to_account_info\(\)',
        ],
        'anti_patterns': [
            r'#\[account\(.*owner\s*=',
            r'Account<.*,\s*\w+>',
            r'Program<',
            r'owner\s*==\s*program_id',
        ],
        'vulnerable_example': '''
// VULNERABLE: No owner check
#[derive(Accounts)]
pub struct Transfer<'info> {
    /// CHECK: No validation
    pub token_account: AccountInfo<'info>,  // Could be any account!
}
''',
        'fixed_example': '''
// FIXED: Using typed Account with owner check
#[derive(Accounts)]
pub struct Transfer<'info> {
    #[account(
        mut,
        token::mint = mint,
        token::authority = authority,
    )]
    pub token_account: Account<'info, TokenAccount>,
}
''',
        'references': [
            'https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/2-owner-checks',
        ]
    },

    'arbitrary_cpi': {
        'id': 'SOL-003',
        'title': 'Arbitrary CPI (Cross-Program Invocation)',
        'severity': 'CRITICAL',
        'description': 'Program ID not validated before CPI, allowing attacker to invoke arbitrary programs',
        'patterns': [
            r'invoke\s*\(',
            r'invoke_signed\s*\(',
            r'CpiContext::new\(',
        ],
        'anti_patterns': [
            r'Program<.*,\s*\w+>',
            r'program\.key\(\)\s*==',
            r'#\[account\(.*address\s*=',
        ],
        'vulnerable_example': '''
// VULNERABLE: No program ID validation
pub fn dangerous_cpi(ctx: Context<DangerousCpi>) -> Result<()> {
    let cpi_program = ctx.accounts.some_program.to_account_info();
    // Attacker can pass any program here!
    invoke(
        &some_instruction,
        &[ctx.accounts.user.to_account_info()],
    )?;
    Ok(())
}
''',
        'fixed_example': '''
// FIXED: Program ID validated via type constraint
#[derive(Accounts)]
pub struct SafeCpi<'info> {
    #[account(address = token::ID)]
    pub token_program: Program<'info, Token>,
}
''',
        'references': [
            'https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/6-arbitrary-cpi',
        ]
    },

    'pda_validation_missing': {
        'id': 'SOL-004',
        'title': 'PDA Validation Missing',
        'severity': 'CRITICAL',
        'description': 'PDA is not re-derived to verify it matches expected seeds',
        'patterns': [
            r'find_program_address',
            r'create_program_address',
            r'seeds\s*=',
        ],
        'anti_patterns': [
            r'#\[account\(.*seeds\s*=.*bump.*\)\]',
            r'Pubkey::find_program_address.*==',
        ],
        'vulnerable_example': '''
// VULNERABLE: PDA not validated
#[derive(Accounts)]
pub struct Withdraw<'info> {
    /// CHECK: PDA not verified!
    #[account(mut)]
    pub vault_pda: AccountInfo<'info>,
}
''',
        'fixed_example': '''
// FIXED: PDA seeds and bump validated
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        seeds = [b"vault", user.key().as_ref()],
        bump = vault.bump,
    )]
    pub vault_pda: Account<'info, Vault>,
}
''',
        'references': [
            'https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/4-pda-validation',
        ]
    },

    'integer_overflow': {
        'id': 'SOL-005',
        'title': 'Integer Overflow/Underflow',
        'severity': 'CRITICAL',
        'description': 'Arithmetic operations without overflow checks can wrap around',
        'patterns': [
            r'\+\s*\d+',
            r'-\s*\d+',
            r'\*\s*\d+',
            r'\+=',
            r'-=',
            r'\*=',
        ],
        'anti_patterns': [
            r'checked_add',
            r'checked_sub',
            r'checked_mul',
            r'checked_div',
            r'saturating_add',
            r'saturating_sub',
            r'overflow-checks\s*=\s*true',
        ],
        'vulnerable_example': '''
// VULNERABLE: No overflow check
pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    vault.total = vault.total + amount;  // Can overflow!
    Ok(())
}
''',
        'fixed_example': '''
// FIXED: Using checked arithmetic
pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    vault.total = vault.total.checked_add(amount)
        .ok_or(ErrorCode::Overflow)?;
    Ok(())
}
''',
        'references': [
            'https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/5-overflow',
        ]
    },

    'account_data_matching': {
        'id': 'SOL-006',
        'title': 'Account Data Matching Attack',
        'severity': 'CRITICAL',
        'description': 'Related accounts not validated against each other',
        'patterns': [
            r'#\[account\(mut\)\]',
            r'Account<.*>',
        ],
        'anti_patterns': [
            r'has_one\s*=',
            r'constraint\s*=',
            r'#\[account\(.*has_one.*\)\]',
        ],
        'vulnerable_example': '''
// VULNERABLE: No relationship check
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub user: Account<'info, User>,
    // No check that user belongs to vault!
}
''',
        'fixed_example': '''
// FIXED: Added has_one constraint
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, has_one = user)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub user: Account<'info, User>,
}
''',
        'references': [
            'https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/3-account-data-matching',
        ]
    },

    'type_cosplay': {
        'id': 'SOL-007',
        'title': 'Type Cosplay Attack',
        'severity': 'CRITICAL',
        'description': 'Account can be deserialized as wrong type due to missing discriminator check',
        'patterns': [
            r'try_from_slice',
            r'deserialize\(',
            r'unpack\(',
        ],
        'anti_patterns': [
            r'#\[account\]',
            r'Account<.*>',
            r'DISCRIMINATOR',
            r'AccountDeserialize',
        ],
        'vulnerable_example': '''
// VULNERABLE: Manual deserialization without discriminator
pub fn process(accounts: &[AccountInfo]) -> ProgramResult {
    let data = Vault::try_from_slice(&accounts[0].data.borrow())?;
    // Attacker can pass User account that deserializes as Vault!
}
''',
        'fixed_example': '''
// FIXED: Use Anchor Account type with automatic discriminator
#[derive(Accounts)]
pub struct Process<'info> {
    #[account()]
    pub vault: Account<'info, Vault>,  // Discriminator checked automatically
}

#[account]
pub struct Vault {
    // Anchor adds 8-byte discriminator
    pub balance: u64,
}
''',
        'references': [
            'https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/7-type-cosplay',
        ]
    },

    'closing_accounts': {
        'id': 'SOL-008',
        'title': 'Improper Account Closing',
        'severity': 'CRITICAL',
        'description': 'Account closed incorrectly allowing revival or data access after close',
        'patterns': [
            r'lamports\s*=\s*0',
            r'close\s*=',
        ],
        'anti_patterns': [
            r'#\[account\(.*close\s*=.*\)\]',
            r'\.close\(',
            r'CLOSED_ACCOUNT_DISCRIMINATOR',
        ],
        'vulnerable_example': '''
// VULNERABLE: Manual close without proper cleanup
pub fn close_account(ctx: Context<CloseAccount>) -> Result<()> {
    let dest = &ctx.accounts.destination;
    let account = &ctx.accounts.account_to_close;
    
    **dest.lamports.borrow_mut() += account.lamports();
    **account.lamports.borrow_mut() = 0;
    // Data not zeroed! Account can be revived in same transaction
    Ok(())
}
''',
        'fixed_example': '''
// FIXED: Use Anchor close constraint
#[derive(Accounts)]
pub struct CloseAccount<'info> {
    #[account(mut, close = destination)]
    pub account_to_close: Account<'info, MyAccount>,
    #[account(mut)]
    pub destination: SystemAccount<'info>,
}
''',
        'references': [
            'https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/9-closing-accounts',
        ]
    },
}

# =============================================================================
# WARNING VULNERABILITIES (Severity: WARNING)
# =============================================================================

WARNING_VULNERABILITIES = {
    'missing_rent_exemption': {
        'id': 'SOL-101',
        'title': 'Missing Rent Exemption Check',
        'severity': 'WARNING',
        'description': 'Account may not be rent-exempt and could be garbage collected',
        'patterns': [
            r'init\s*,',
            r'SystemProgram::create_account',
        ],
        'anti_patterns': [
            r'rent_exempt',
            r'Rent::get',
            r'rent::Rent',
        ],
    },

    'duplicate_mutable_accounts': {
        'id': 'SOL-102',
        'title': 'Duplicate Mutable Accounts',
        'severity': 'WARNING',
        'description': 'Same account passed multiple times as mutable can cause undefined behavior',
        'patterns': [
            r'#\[account\(mut\)\].*#\[account\(mut\)\]',
        ],
        'anti_patterns': [
            r'constraint\s*=.*key\(\)\s*!=',
        ],
    },

    'missing_bump_seed': {
        'id': 'SOL-103',
        'title': 'Missing Bump Seed Storage',
        'severity': 'WARNING',
        'description': 'PDA bump not stored, requiring expensive recalculation',
        'patterns': [
            r'find_program_address',
        ],
        'anti_patterns': [
            r'bump\s*=',
            r'\.bump',
        ],
    },

    'unchecked_return_value': {
        'id': 'SOL-104',
        'title': 'Unchecked Return Value',
        'severity': 'WARNING',
        'description': 'CPI or operation return value not checked',
        'patterns': [
            r'invoke\s*\([^?]*\);',
            r'transfer\s*\([^?]*\);',
        ],
        'anti_patterns': [
            r'\?;',
            r'\.unwrap\(',
            r'\.expect\(',
        ],
    },

    'sysvar_spoofing': {
        'id': 'SOL-105',
        'title': 'Potential Sysvar Spoofing',
        'severity': 'WARNING',
        'description': 'Sysvar account not validated against known address',
        'patterns': [
            r'AccountInfo.*rent',
            r'AccountInfo.*clock',
        ],
        'anti_patterns': [
            r'Sysvar<.*Rent>',
            r'Sysvar<.*Clock>',
            r'rent::id\(\)',
            r'clock::id\(\)',
        ],
    },
}

# =============================================================================
# IMPROVEMENTS (Severity: INFO)
# =============================================================================

IMPROVEMENT_SUGGESTIONS = {
    'use_anchor_constraints': {
        'id': 'SOL-201',
        'title': 'Use Anchor Constraints',
        'severity': 'INFO',
        'description': 'Replace manual checks with Anchor constraint macros',
    },

    'add_error_codes': {
        'id': 'SOL-202',
        'title': 'Add Custom Error Codes',
        'severity': 'INFO',
        'description': 'Use descriptive error codes instead of generic errors',
    },

    'use_pda_authority': {
        'id': 'SOL-203',
        'title': 'Use PDA as Authority',
        'severity': 'INFO',
        'description': 'Consider using PDA instead of keypair for program authority',
    },

    'add_events': {
        'id': 'SOL-204',
        'title': 'Add Event Logging',
        'severity': 'INFO',
        'description': 'Emit events for important state changes',
    },

    'add_access_control': {
        'id': 'SOL-205',
        'title': 'Add Access Control',
        'severity': 'INFO',
        'description': 'Implement role-based access control for admin functions',
    },
}

# =============================================================================
# SOLANA-SPECIFIC KEYWORDS FOR SMART SAMPLING
# =============================================================================

SOLANA_CRITICAL_KEYWORDS = [
    # Core Solana
    'instruction', 'processor', 'entrypoint', 'program',
    # Security-sensitive
    'signer', 'authority', 'admin', 'owner', 'mint', 'vault', 'treasury',
    'withdraw', 'deposit', 'transfer', 'burn', 'close',
    # PDA related
    'pda', 'seeds', 'bump', 'find_program_address',
    # CPI related
    'cpi', 'invoke', 'invoke_signed',
    # Token related
    'token', 'spl_token', 'associated_token', 'metadata',
]

SOLANA_IMPORTANT_KEYWORDS = [
    # Anchor
    'context', 'accounts', 'state', 'error',
    # Structure
    'lib', 'mod', 'handler', 'helper', 'util',
    # Config
    'config', 'constant', 'id', 'key',
]

SOLANA_PRIORITY_DIRS = [
    'programs/',
    'src/instructions/',
    'src/processor/',
    'src/state/',
    'src/contexts/',
    'src/handlers/',
    'src/errors/',
    'instructions/',
    'processor/',
    'state/',
]

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_all_vulnerability_ids():
    """Return all vulnerability IDs"""
    ids = []
    for v in CRITICAL_VULNERABILITIES.values():
        ids.append(v['id'])
    for v in WARNING_VULNERABILITIES.values():
        ids.append(v['id'])
    for v in IMPROVEMENT_SUGGESTIONS.values():
        ids.append(v['id'])
    return ids

def get_vulnerability_by_id(vuln_id: str):
    """Get vulnerability details by ID"""
    for v in CRITICAL_VULNERABILITIES.values():
        if v['id'] == vuln_id:
            return v
    for v in WARNING_VULNERABILITIES.values():
        if v['id'] == vuln_id:
            return v
    for v in IMPROVEMENT_SUGGESTIONS.values():
        if v['id'] == vuln_id:
            return v
    return None

def get_severity_weight(severity: str) -> int:
    """Get numeric weight for severity"""
    weights = {
        'CRITICAL': 100,
        'WARNING': 50,
        'INFO': 10,
    }
    return weights.get(severity, 0)
