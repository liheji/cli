export type AuthType = "basic" | "bearer";

export type CredentialStoreType = "keyring" | "file";

export function isCredentialStoreType(value: unknown): value is CredentialStoreType {
  return value === "keyring" || value === "file";
}

export interface BasicCredentials {
  type: "basic";
  username: string;
  password: string;
}

export interface BearerCredentials {
  type: "bearer";
  token: string;
}

export type HaloCredentials = BasicCredentials | BearerCredentials;

export interface StoredHaloAuth {
  type: AuthType;
}

export interface StoredHaloProfile {
  name: string;
  baseUrl: string;
  auth: StoredHaloAuth;
  createdAt: string;
  updatedAt: string;
}

export interface HaloProfile extends Omit<StoredHaloProfile, "auth"> {
  auth: HaloCredentials;
}

export interface HaloConfig {
  activeProfile?: string;
  profiles: Record<string, StoredHaloProfile>;
  credentialStore?: CredentialStoreType;
}

export function toStoredHaloProfile(profile: HaloProfile): StoredHaloProfile {
  return {
    name: profile.name,
    baseUrl: profile.baseUrl,
    auth: {
      type: profile.auth.type,
    },
    createdAt: profile.createdAt,
    updatedAt: profile.updatedAt,
  };
}
