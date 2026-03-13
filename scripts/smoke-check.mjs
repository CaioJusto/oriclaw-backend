#!/usr/bin/env node

import axios from 'axios';
import https from 'https';

const backendUrl = process.env.BACKEND_URL || '';
const frontendUrl = process.env.FRONTEND_URL || '';
const agentHost = process.env.AGENT_HOST || '';
const agentSecret = process.env.AGENT_SECRET || '';

const insecureHttps = new https.Agent({ rejectUnauthorized: false });

function normalizeBaseUrl(rawUrl) {
  return rawUrl.replace(/\/+$/, '');
}

async function request(url, options = {}) {
  const response = await axios({
    url,
    validateStatus: () => true,
    httpsAgent: insecureHttps,
    timeout: 15_000,
    ...options,
  });
  return { status: response.status, body: response.data };
}

async function check(name, fn) {
  try {
    await fn();
    console.log(`PASS ${name}`);
    return true;
  } catch (error) {
    console.error(`FAIL ${name}: ${error instanceof Error ? error.message : String(error)}`);
    return false;
  }
}

async function main() {
  const checks = [];

  if (backendUrl) {
    const baseUrl = normalizeBaseUrl(backendUrl);
    checks.push(check('backend /health', async () => {
      const { status, body } = await request(`${baseUrl}/health`);
      if (status < 200 || status >= 300) throw new Error(`HTTP ${status}`);
      if (!body || body.status !== 'ok') {
        throw new Error(`Unexpected body: ${JSON.stringify(body)}`);
      }
    }));
  }

  if (frontendUrl) {
    const baseUrl = normalizeBaseUrl(frontendUrl);
    checks.push(check('frontend root', async () => {
      const { status } = await request(baseUrl);
      if (status < 200 || status >= 300) throw new Error(`HTTP ${status}`);
    }));
  }

  if (agentHost && agentSecret) {
    const baseUrl = `https://${agentHost}:8080`;
    const headers = { 'x-agent-secret': agentSecret };

    checks.push(check('agent /health', async () => {
      const { status, body } = await request(`${baseUrl}/health`, { headers });
      if (status < 200 || status >= 300) throw new Error(`HTTP ${status}`);
      if (!body || body.status !== 'ok') {
        throw new Error(`Unexpected body: ${JSON.stringify(body)}`);
      }
    }));

    checks.push(check('agent /usage/pending', async () => {
      const { status, body } = await request(`${baseUrl}/usage/pending`, { headers });
      if (status < 200 || status >= 300) throw new Error(`HTTP ${status}`);
      if (!body || !Array.isArray(body.events)) {
        throw new Error(`Unexpected body: ${JSON.stringify(body)}`);
      }
    }));

    checks.push(check('agent /usage/ack', async () => {
      const { status, body } = await request(`${baseUrl}/usage/ack`, {
        method: 'POST',
        headers: { ...headers, 'Content-Type': 'application/json' },
        data: { ids: [] },
      });
      if (status < 200 || status >= 300) throw new Error(`HTTP ${status}`);
      if (!body || typeof body.pending !== 'number') {
        throw new Error(`Unexpected body: ${JSON.stringify(body)}`);
      }
    }));

    checks.push(check('agent /credit-status', async () => {
      const { status, body } = await request(`${baseUrl}/credit-status`, {
        method: 'POST',
        headers: { ...headers, 'Content-Type': 'application/json' },
        data: { blocked: false, balance_brl: 1 },
      });
      if (status < 200 || status >= 300) throw new Error(`HTTP ${status}`);
      if (!body || typeof body.credit_blocked !== 'boolean') {
        throw new Error(`Unexpected body: ${JSON.stringify(body)}`);
      }
    }));
  }

  if (checks.length === 0) {
    console.error('No checks were run. Set BACKEND_URL and/or AGENT_HOST + AGENT_SECRET.');
    process.exit(1);
  }

  const results = await Promise.all(checks);
  if (results.every(Boolean)) {
    console.log('Smoke check passed.');
    return;
  }

  process.exit(1);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
