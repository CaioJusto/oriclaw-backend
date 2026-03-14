import crypto from 'crypto';
import https from 'https';

const selfsigned = require('selfsigned');

export type AgentTlsMaterial = {
  certPem: string;
  certPemB64: string;
  keyPem: string;
  keyPemB64: string;
  fingerprint256: string;
};

function toBase64(content: string): string {
  return Buffer.from(content, 'utf8').toString('base64');
}

export function normalizeFingerprint256(value: string | null | undefined): string | null {
  return typeof value === 'string' && value.trim().length > 0
    ? value.trim().replace(/:/g, '').toUpperCase()
    : null;
}

export function buildPinnedAgentHttpsAgent(certPem: string, fingerprint256: string): https.Agent {
  const normalized = normalizeFingerprint256(fingerprint256);
  if (!normalized) {
    throw new Error('Missing pinned agent TLS fingerprint');
  }

  return new https.Agent({
    ca: certPem,
    rejectUnauthorized: true,
    keepAlive: true,
    checkServerIdentity: (_host, cert) => {
      const peerFingerprint = normalizeFingerprint256(cert.fingerprint256);
      if (!peerFingerprint || peerFingerprint !== normalized) {
        return new Error('Pinned agent TLS fingerprint mismatch');
      }
      return undefined;
    },
  });
}

export function getTlsMaterialFromCertPem(certPem: string): Pick<AgentTlsMaterial, 'certPem' | 'certPemB64' | 'fingerprint256'> {
  const x509 = new crypto.X509Certificate(certPem);
  return {
    certPem,
    certPemB64: toBase64(certPem),
    fingerprint256: x509.fingerprint256,
  };
}

export function createProvisionedAgentTlsMaterial(): AgentTlsMaterial {
  const attrs = [{ name: 'commonName', value: 'oriclaw-vps-agent' }];
  const generated = selfsigned.generate(attrs, {
    algorithm: 'sha256',
    days: 3650,
    keySize: 2048,
  }) as { cert: string; private: string };

  const tls = getTlsMaterialFromCertPem(generated.cert);
  return {
    ...tls,
    keyPem: generated.private,
    keyPemB64: toBase64(generated.private),
  };
}
