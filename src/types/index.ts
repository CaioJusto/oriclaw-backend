export interface OriClawInstance {
  id: string;
  created_at: string;
  customer_id: string;
  email: string;
  plan: 'starter' | 'pro' | 'business';
  droplet_id: number | null;
  droplet_ip: string | null;
  status: 'provisioning' | 'running' | 'suspended' | 'deleted';
  stripe_subscription_id: string | null;
  api_key_encrypted: string | null;
  metadata: Record<string, unknown> | null;
}

export interface ProvisionRequest {
  customer_id: string;
  plan: 'starter' | 'pro' | 'business';
  email: string;
  api_key_anthropic?: string;
  stripe_subscription_id?: string;
}

export interface DropletConfig {
  name: string;
  region: string;
  size: string;
  image: string;
  user_data: string;
  tags: string[];
}

export interface DODroplet {
  id: number;
  name: string;
  status: string;
  networks: {
    v4: Array<{
      ip_address: string;
      type: string;
    }>;
  };
}

export interface DODropletResponse {
  droplet: DODroplet;
}
