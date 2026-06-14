export interface ProviderConfig {
  baseUrl: string;
  apiKey: string;
}

export interface AzureProviderConfig extends ProviderConfig {
  deploymentId: string;
  apiVersion?: string;
}

export interface AuliteConfig {
  license?: string;
  server: {
    port: number;
    host: string;
  };
  provider: {
    default: "openai" | "anthropic" | "azure";
    openai?: ProviderConfig;
    anthropic?: ProviderConfig;
    azure?: AzureProviderConfig;
  };
  analysis: {
    mode: "advisory" | "enforcing";
    domains: string[];
    rulesDir?: string;
    llmJudge: {
      enabled: boolean;
      model: string;
      sampleRate: number;
    };
    thresholds: {
      warn: number;
      block: number;
    };
  };
  auth?: {
    apiKeys: string[];
  };
  rateLimit?: {
    requestsPerMinute: number;
  };
  anchor?: {
    enabled: boolean;
    intervalMinutes: number;
    rekorUrl: string;
    keyPath: string;
  };
  logging: {
    database: string;
    retentionDays: number;
  };
}

export const DEFAULT_CONFIG: AuliteConfig = {
  server: {
    port: 3000,
    host: "0.0.0.0",
  },
  provider: {
    default: "anthropic",
  },
  analysis: {
    mode: "advisory",
    domains: ["hr"],
    llmJudge: {
      enabled: false,
      model: "claude-sonnet-4-6",
      sampleRate: 0.1,
    },
    thresholds: {
      warn: 4,
      block: 7,
    },
  },
  anchor: {
    enabled: false,
    intervalMinutes: 60,
    rekorUrl: "https://rekor.sigstore.dev",
    keyPath: "./aulite-signing-key.pem",
  },
  logging: {
    database: "./aulite-audit.db",
    retentionDays: 365,
  },
};
