import axios from 'axios';
import { DODroplet, DODropletResponse } from '../types';

const DO_API_BASE = 'https://api.digitalocean.com/v2';

function getHeaders() {
  return {
    Authorization: `Bearer ${process.env.DO_API_TOKEN}`,
    'Content-Type': 'application/json',
  };
}

// NOTE: createDroplet was removed — provisioning uses createDropletWithInit exclusively.

export async function getDroplet(dropletId: number): Promise<DODroplet> {
  const response = await axios.get<DODropletResponse>(
    `${DO_API_BASE}/droplets/${dropletId}`,
    { headers: getHeaders() }
  );

  return response.data.droplet;
}

export async function deleteDroplet(dropletId: number): Promise<void> {
  try {
    await axios.delete(`${DO_API_BASE}/droplets/${dropletId}`, {
      headers: getHeaders(),
    });
  } catch (err: unknown) {
    // Bug fix #3: treat 404 as success — droplet was already deleted (idempotent)
    const axErr = err as { response?: { status?: number } };
    if (axErr.response?.status === 404) return;
    throw err;
  }
}

export function getDropletPublicIP(droplet: DODroplet): string | null {
  const v4 = droplet.networks?.v4 ?? [];
  const publicNet = v4.find((n) => n.type === 'public');
  return publicNet?.ip_address ?? null;
}
