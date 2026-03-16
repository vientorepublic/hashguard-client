import { createHash } from 'crypto';

/**
 * Verifies that `SHA-256(preimage) <= targetHex`.
 * Both the hash and target are 64-character lowercase hex strings.
 * Lexicographic comparison works because they are the same length.
 */
export function verifyProof(
  challengeId: string,
  seed: string,
  nonce: string,
  targetHex: string
): boolean {
  const preimage = `${challengeId}:${seed}:${nonce}`;
  const hash = createHash('sha256').update(preimage, 'utf8').digest('hex');
  return hash <= targetHex;
}

/**
 * Computes and returns the SHA-256 hash of the given preimage as a lowercase hex string.
 */
export function sha256hex(preimage: string): string {
  return createHash('sha256').update(preimage, 'utf8').digest('hex');
}
