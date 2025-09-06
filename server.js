/**
 * server.js
 * Solana Deposit Backend — PostgreSQL-ready, production-oriented
 * Multi-token support (SOL native + SPL tokens)
 *
 * Usage:
 *  - Put configuration in .env (see .env.example)
 *  - npm ci
 *  - pm2 start server.js --name solana-deposit
 *
 * Important env vars required now:
 *  PORT, API_KEY, CALLBACK_HMAC_SECRET, SOLANA_RPC_URL,
 *  SOLANA_DEPOSIT_ADDRESS, WORDPRESS_CALLBACK_URL, PG_POOL_URL, SUPPORTED_TOKENS
 *
 * SUPPORTED_TOKENS should be a JSON string, e.g.:
 *  SUPPORTED_TOKENS={"SOL":"native","USDT":"Es9vMFr...","ST":"6Gh..."}
 */

const express = require('express');
const { Pool } = require('pg');
const axios = require('axios');
const { Connection, PublicKey, LAMPORTS_PER_SOL } = require('@solana/web3.js');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const crypto = require('crypto');
const winston = require('winston');
require('dotenv').config();

// ----------------- Validate env -----------------
const required = [
  'PORT','API_KEY','CALLBACK_HMAC_SECRET','SOLANA_RPC_URL',
  'SOLANA_DEPOSIT_ADDRESS','WORDPRESS_CALLBACK_URL','PG_POOL_URL','SUPPORTED_TOKENS'
];
for (const k of required) {
  if (!process.env[k]) {
    console.error(`Missing env var: ${k}`);
    process.exit(1);
  }
}

const PORT = parseInt(process.env.PORT, 10) || 3000;
const API_KEY = process.env.API_KEY;
const CALLBACK_HMAC_SECRET = process.env.CALLBACK_HMAC_SECRET;
const CALLBACK_API_KEY = process.env.CALLBACK_API_KEY || '';
const SOLANA_RPC_URL = process.env.SOLANA_RPC_URL;
const SOLANA_DEPOSIT_ADDRESS = process.env.SOLANA_DEPOSIT_ADDRESS;
const WORDPRESS_CALLBACK_URL = process.env.WORDPRESS_CALLBACK_URL;
const POLL_INTERVAL_MS = parseInt(process.env.POLL_INTERVAL_MS || '10000', 10);
const SIGNATURE_SCAN_LIMIT = parseInt(process.env.SIGNATURE_SCAN_LIMIT || '100', 10);
const MAX_CALLBACK_RETRIES = parseInt(process.env.MAX_CALLBACK_RETRIES || '10', 10);
const PG_POOL_URL = process.env.PG_POOL_URL;
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ['*'];

// Parse supported tokens map from environment (JSON)
let SUPPORTED_TOKENS = {};
try {
  SUPPORTED_TOKENS = JSON.parse(process.env.SUPPORTED_TOKENS);
  if (typeof SUPPORTED_TOKENS !== 'object' || Array.isArray(SUPPORTED_TOKENS)) throw new Error('SUPPORTED_TOKENS must be JSON object');
} catch (e) {
  console.error('Invalid SUPPORTED_TOKENS JSON in env:', e.message);
  process.exit(1);
}

// Normalize: symbol -> mint string or "native"
for (const k of Object.keys(SUPPORTED_TOKENS)) {
  SUPPORTED_TOKENS[k] = String(SUPPORTED_TOKENS[k]);
}

// ----------------- Logger -----------------
const logger = winston.createLogger({
  level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.printf(({ timestamp, level, message, stack }) => `${timestamp} ${level}: ${stack || message}`)
  ),
  transports: [new winston.transports.Console()],
});

// ----------------- Solana connection -----------------
const connection = new Connection(SOLANA_RPC_URL, 'confirmed');
let DEPOSIT_OWNER;
try {
  DEPOSIT_OWNER = new PublicKey(SOLANA_DEPOSIT_ADDRESS);
} catch (err) {
  logger.error('Invalid SOLANA_DEPOSIT_ADDRESS: ' + err.message);
  process.exit(1);
}

// ----------------- Postgres pool & migrations -----------------
const pool = new Pool({ connectionString: PG_POOL_URL, max: 10 });

async function runMigrations() {
  const client = await pool.connect();
  try {
    // Migrate deposits table: include token_symbol and token_mint
    await client.query(`
      CREATE TABLE IF NOT EXISTS deposits (
        id TEXT PRIMARY KEY,
        request_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        token_symbol TEXT NOT NULL DEFAULT 'SOL',
        token_mint TEXT,
        amount TEXT NOT NULL,
        memo TEXT NOT NULL,
        mint TEXT NOT NULL,
        deposit_owner TEXT NOT NULL,
        solana_pay_link TEXT,
        status TEXT NOT NULL DEFAULT 'pending',
        tx_signature TEXT,
        callback_status TEXT DEFAULT 'pending',
        callback_retries INTEGER DEFAULT 0,
        created_at TIMESTAMPTZ DEFAULT now(),
        updated_at TIMESTAMPTZ DEFAULT now(),
        last_checked_at TIMESTAMPTZ,
        last_scanned_signature TEXT
      );
    `);
    await client.query('CREATE INDEX IF NOT EXISTS idx_deposits_request_id ON deposits(request_id);');
    await client.query("CREATE INDEX IF NOT EXISTS idx_deposits_status ON deposits(status);");
    logger.info('DB migrations applied (including token_symbol/token_mint)');
  } finally {
    client.release();
  }
}

// ----------------- Helpers -----------------
function nowISO() { return new Date().toISOString(); }
function uuidv4() { return crypto.randomUUID(); }

/**
 * Build Solana Pay link.
 * For native SOL, omit spl-token param.
 * For SPL tokens, include spl-token=<mint>.
 */
function buildSolanaPayLink({ recipient, amount, tokenMint, memo }) {
  const base = `solana:${recipient}`;
  const params = new URLSearchParams();
  if (amount) params.set('amount', String(amount));
  if (tokenMint && tokenMint !== 'native') params.set('spl-token', String(tokenMint));
  if (memo) params.set('memo', String(memo));
  return `${base}?${params.toString()}`;
}

function signCallback(payload) {
  return crypto.createHmac('sha256', CALLBACK_HMAC_SECRET).update(JSON.stringify(payload)).digest('hex');
}
function safeEqual(a, b) {
  try { return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)); } catch (e) { return false; }
}

// ----------------- Express app -----------------
const app = express();
app.use(helmet());
app.use(express.json({ verify: (req, res, buf) => { req.rawBody = buf ? buf.toString() : ''; } }));
app.use(express.urlencoded({ extended: true }));
app.use(cors({ origin: ALLOWED_ORIGINS }));
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200 });
app.use(limiter);

function requireApiKey(req, res, next) {
  const key = req.headers['x-api-key'] || req.body.api_key;
  if (!key || key !== API_KEY) return res.status(401).json({ success: false, message: 'Unauthorized (invalid API key)' });
  next();
}

// ----------------- POST /api/initiate-deposit -----------------
/**
 * Request body:
 * {
 *   request_id, user_id, amount, token_symbol, api_key
 * }
 */
app.post('/api/initiate-deposit', requireApiKey, async (req, res) => {
  try {
    const { request_id, user_id, amount, token_symbol } = req.body || {};
    if (!request_id || !user_id || !amount || !token_symbol) {
      return res.status(400).json({ success: false, message: 'request_id, user_id, amount, token_symbol required' });
    }

    // Validate token_symbol is supported
    if (!SUPPORTED_TOKENS[token_symbol]) {
      return res.status(400).json({ success: false, message: 'Unsupported token_symbol' });
    }

    const amountNum = parseFloat(String(amount));
    if (isNaN(amountNum) || amountNum <= 0) return res.status(400).json({ success: false, message: 'Invalid amount' });

    const tokenMint = SUPPORTED_TOKENS[token_symbol]; // 'native' or mint address

    const client = await pool.connect();
    try {
      const r = await client.query('SELECT * FROM deposits WHERE request_id=$1 LIMIT 1', [request_id]);
      if (r.rows.length > 0) {
        const exist = r.rows[0];
        logger.info(`idempotent hit for request_id=${request_id}`);
        return res.json({ success: true, message: 'Already exists', solana_pay_link: exist.solana_pay_link, backend_request_id: exist.id });
      }

      const backend_request_id = uuidv4();
      const memo = String(request_id);

      const solana_pay_link = buildSolanaPayLink({
        recipient: SOLANA_DEPOSIT_ADDRESS,
        amount: amountNum,
        tokenMint: tokenMint,
        memo
      });

      // store token_symbol and token_mint in DB (for scanning)
      await client.query(
        `INSERT INTO deposits
         (id, request_id, user_id, token_symbol, token_mint, amount, memo, mint, deposit_owner, solana_pay_link, created_at, updated_at)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10, now(), now())`,
        [backend_request_id, request_id, user_id, token_symbol, tokenMint, String(amountNum), memo,
         tokenMint === 'native' ? 'native' : tokenMint, DEPOSIT_OWNER.toBase58(), solana_pay_link]
      );

      logger.info(`Created deposit ${backend_request_id} for request ${request_id} token=${token_symbol} amount=${amountNum}`);
      return res.json({ success: true, message: 'Deposit request created successfully', solana_pay_link, backend_request_id });
    } finally {
      client.release();
    }
  } catch (err) {
    logger.error('initiate error: ' + (err.stack || err));
    return res.status(500).json({ success: false, message: 'Internal error' });
  }
});

// ----------------- Local test callback endpoint -----------------
app.post('/api/wordpress-callback', async (req, res) => {
  logger.info('Local wordpress-callback received: ' + (req.rawBody || '').slice(0, 200));
  return res.json({ ok: true });
});

// ----------------- Health -----------------
app.get('/health', (req, res) => res.json({ ok: true, time: nowISO() }));

// ----------------- Chain scanning: find matching transaction -----------------
/**
 * If tokenMint === 'native' => check native SOL balance changes (preBalances/postBalances)
 * Else => check SPL token balances (preTokenBalances/postTokenBalances) for matching mint and owner
 */
async function findMatchingTransaction({ memo, expectedAmount, tokenMint }) {
  // scan recent signatures for DEPOSIT_OWNER
  const sigInfos = await connection.getSignaturesForAddress(DEPOSIT_OWNER, { limit: SIGNATURE_SCAN_LIMIT });
  for (const si of sigInfos) {
    try {
      const sig = si.signature;
      const tx = await connection.getParsedTransaction(sig, { maxSupportedTransactionVersion: 0 });
      if (!tx || !tx.meta) continue;

      // check memo
      let foundMemo = false;
      const instrs = tx.transaction.message.instructions || [];
      for (const ix of instrs) {
        try {
          if (ix.program === 'spl-memo' || String(ix.programId) === 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr') {
            const data = (ix.parsed && ix.parsed.memo) || Buffer.from(ix.data || '', 'base64').toString('utf8');
            if (String(data) === String(memo)) { foundMemo = true; break; }
          }
        } catch (e) { /* ignore */ }
      }
      if (!foundMemo) continue;

      // If native SOL
      if (!tokenMint || tokenMint === 'native') {
        // use preBalances/postBalances (lamports)
        const preBalances = tx.meta.preBalances || [];
        const postBalances = tx.meta.postBalances || [];
        // We need to locate index(es) that belong to DEPOSIT_OWNER's key
        const accountKeys = tx.transaction.message.accountKeys || tx.transaction.message.accountKeys || [];
        // accountKeys may be objects or strings depending on parse; normalize
        const keys = accountKeys.map(k => (typeof k === 'string' ? k : (k.pubkey || k.toString())));

        for (let i = 0; i < keys.length; i++) {
          if (keys[i] === DEPOSIT_OWNER.toBase58()) {
            const pre = preBalances[i] ?? 0;
            const post = postBalances[i] ?? 0;
            const diffLamports = post - pre;
            const diffSol = diffLamports / LAMPORTS_PER_SOL;
            if (Math.abs(diffSol - parseFloat(String(expectedAmount))) < 1e-8) {
              return sig;
            }
          }
        }
        // if not found in accountKeys, continue
      } else {
        // SPL token: check preTokenBalances/postTokenBalances
        const preTB = tx.meta.preTokenBalances || [];
        const postTB = tx.meta.postTokenBalances || [];
        for (const post of postTB) {
          if (post.mint === String(tokenMint) && post.owner === DEPOSIT_OWNER.toBase58()) {
            const postUi = post.uiTokenAmount?.uiAmount ?? null;
            const pre = preTB.find(p => p.accountIndex === post.accountIndex);
            const preUi = pre?.uiTokenAmount?.uiAmount ?? 0;
            if (postUi === null) continue;
            const diff = parseFloat(String(postUi - (preUi || 0)));
            if (Math.abs(diff - parseFloat(String(expectedAmount))) < 1e-8) return sig;
          }
        }
      }
    } catch (e) {
      logger.warn('scan tx err: ' + (e.message || e));
    }
  }
  return null;
}

// ----------------- scan loop -----------------
async function scanAndUpdate() {
  const client = await pool.connect();
  try {
    const { rows } = await client.query("SELECT * FROM deposits WHERE status='pending'");
    for (const row of rows) {
      try {
        logger.debug(`Scanning id=${row.id} token=${row.token_symbol}`);
        const tokenMint = row.token_mint || 'native';
        const sig = await findMatchingTransaction({ memo: row.memo, expectedAmount: row.amount, tokenMint });
        await client.query('UPDATE deposits SET last_checked_at=now(), last_scanned_signature=$1 WHERE id=$2', [sig, row.id]);
        if (sig) {
          await client.query('UPDATE deposits SET status=$1, tx_signature=$2, updated_at=now() WHERE id=$3', ['completed', sig, row.id]);
          logger.info(`Matched ${row.id} sig=${sig}`);
          queueCallback(row.id);
        }
      } catch (e) { logger.warn('scan row err: ' + (e.message || e)); }
    }
  } finally {
    client.release();
  }
}

// ----------------- Callbacks: send to WP with HMAC + retry -----------------
const callbackQueue = new Map();

async function sendCallbackToWP(row) {
  const payload = {
    request_id: row.request_id,
    backend_request_id: row.id,
    user_id: row.user_id,
    token_symbol: row.token_symbol,
    token_mint: row.token_mint,
    amount: row.amount,
    deposit_address: row.deposit_owner,
    status: row.status,
    tx_signature: row.tx_signature,
    processed_at: nowISO()
  };
  const signature = signCallback(payload);
  try {
    const resp = await axios.post(WORDPRESS_CALLBACK_URL, payload, {
      headers: { 'x-callback-signature': signature, 'x-api-key': CALLBACK_API_KEY },
      timeout: 10000
    });
    if (resp.status >= 200 && resp.status < 300) {
      await pool.query('UPDATE deposits SET callback_status=$1, callback_retries=$2, updated_at=now() WHERE id=$3', ['ok', row.callback_retries || 0, row.id]);
      logger.info(`Callback OK ${row.id}`);
      return true;
    }
    throw new Error('Bad status ' + resp.status);
  } catch (e) {
    const retries = (row.callback_retries || 0) + 1;
    await pool.query('UPDATE deposits SET callback_status=$1, callback_retries=$2, updated_at=now() WHERE id=$3', ['failed', retries, row.id]);
    logger.warn(`Callback failed ${row.id} attempt=${retries} err=${e.message || e}`);
    return false;
  }
}

function queueCallback(id) {
  if (callbackQueue.has(id)) return;
  (async () => {
    const client = await pool.connect();
    try {
      const r = await client.query('SELECT * FROM deposits WHERE id=$1', [id]);
      if (r.rows.length === 0) return;
      const row = r.rows[0];
      let attempt = 1;
      while (attempt <= MAX_CALLBACK_RETRIES) {
        const ok = await sendCallbackToWP(row);
        if (ok) break;
        const delay = Math.min(5 * 60 * 1000, 1000 * Math.pow(2, attempt)); // exponential backoff cap
        logger.info(`Scheduling retry #${attempt + 1} for ${id} in ${delay}ms`);
        await new Promise(r => setTimeout(r, delay));
        // refresh row
        const rr = await client.query('SELECT * FROM deposits WHERE id=$1', [id]);
        row.callback_retries = rr.rows[0].callback_retries;
        attempt++;
      }
    } finally {
      client.release();
      callbackQueue.delete(id);
    }
  })();
}

// resume failed callbacks on boot
async function resumeFailedCallbacks() {
  const client = await pool.connect();
  try {
    const { rows } = await client.query("SELECT * FROM deposits WHERE status='completed' AND callback_status!='ok' AND callback_retries < $1", [MAX_CALLBACK_RETRIES]);
    for (const r of rows) queueCallback(r.id);
  } finally {
    client.release();
  }
}

// ----------------- start everything -----------------
runMigrations()
  .then(() => {
    resumeFailedCallbacks();
    setInterval(() => { scanAndUpdate().catch(e => logger.error('scan loop err: ' + (e.stack || e))); }, POLL_INTERVAL_MS);
    app.listen(PORT, () => logger.info(`Solana Deposit Backend (multi-token) listening on port ${PORT}`));
  })
  .catch(e => { logger.error(e.stack || e); process.exit(1); });

// graceful shutdown
process.on('SIGINT', async () => { logger.info('SIGINT received, shutting down...'); await pool.end(); process.exit(0); });
process.on('SIGTERM', async () => { logger.info('SIGTERM received, shutting down...'); await pool.end(); process.exit(0); });
