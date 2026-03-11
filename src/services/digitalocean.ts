import axios from 'axios';
import { CLOUD_INIT_SCRIPT } from './cloudInit';
import { DODroplet, DODropletResponse } from '../types';

const DO_API_BASE = 'https://api.digitalocean.com/v2';

function getHeaders() {
  return {
    Authorization: `Bearer ${process.env.DO_API_TOKEN}`,
    'Content-Type': 'application/json',
  };
}

export async function createDroplet(customerId: string): Promise<DODroplet> {
  const dropletConfig = {
    name: `oriclaw-${customerId}`,
    region: 'nyc3',
    size: 's-1vcpu-2gb',
    image: 'ubuntu-22-04-x64',
    user_data: CLOUD_INIT_SCRIPT,
    tags: ['oriclaw', `customer:${customerId}`],
    monitoring: true,
    ipv6: false,
  };

  const response = await axios.post<DODropletResponse>(
    `${DO_API_BASE}/droplets`,
    dropletConfig,
    { headers: getHeaders() }
  );

  return response.data.droplet;
}

export async function getDroplet(dropletId: number): Promise<DODroplet> {
  const response = await axios.get<DODropletResponse>(
    `${DO_API_BASE}/droplets/${dropletId}`,
    { headers: getHeaders() }
  );

  return response.data.droplet;
}

export async function deleteDroplet(dropletId: number): Promise<void> {
  await axios.delete(`${DO_API_BASE}/droplets/${dropletId}`, {
    headers: getHeaders(),
  });
}

export function getDropletPublicIP(droplet: DODroplet): string | null {
  const v4 = droplet.networks?.v4 ?? [];
  const publicNet = v4.find((n) => n.type === 'public');
  return publicNet?.ip_address ?? null;
}
