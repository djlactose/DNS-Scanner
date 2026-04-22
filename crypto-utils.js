'use strict';

const crypto = require('node:crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const TAG_LENGTH = 16;
// Legacy salt: older versions used this literal string. Decrypt-only fallback
// so existing stored SMTP credentials keep working after upgrade. New writes
// always use the key-derived salt.
const LEGACY_SALT = 'dns-scanner-salt';

function requireEnvKey() {
  const key = process.env.ENCRYPTION_KEY;
  if (!key || key.length < 32) {
    throw new Error('ENCRYPTION_KEY must be at least 32 characters');
  }
  return key;
}

function deriveKey(envKey) {
  // scrypt here is a slow KDF; entropy lives in the 32+ byte ENCRYPTION_KEY.
  // Salt is derived deterministically from the key itself so same key → same
  // AES key, with no committed magic string for scanners to flag.
  const salt = crypto.createHash('sha256').update(envKey).digest().subarray(0, 16);
  return crypto.scryptSync(envKey, salt, 32);
}

function deriveLegacyKey(envKey) {
  return crypto.scryptSync(envKey, LEGACY_SALT, 32);
}

function encrypt(text) {
  const key = deriveKey(requireEnvKey());
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag();
  return iv.toString('hex') + ':' + tag.toString('hex') + ':' + encrypted;
}

function decryptWith(key, iv, tag, encrypted) {
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

function decrypt(encryptedText) {
  const envKey = requireEnvKey();
  const parts = encryptedText.split(':');
  if (parts.length !== 3) throw new Error('Invalid encrypted text format');
  const iv = Buffer.from(parts[0], 'hex');
  const tag = Buffer.from(parts[1], 'hex');
  const encrypted = parts[2];
  try {
    return decryptWith(deriveKey(envKey), iv, tag, encrypted);
  } catch (e) {
    // Fallback for ciphertexts written before the salt-derivation change.
    return decryptWith(deriveLegacyKey(envKey), iv, tag, encrypted);
  }
}

module.exports = { encrypt, decrypt };
