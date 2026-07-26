import { Entry, findCredentials, type Credential } from "@napi-rs/keyring";

import type { HaloCredentials } from "../shared/profile.js";
import { CliError } from "./errors.js";

const HALO_CLI_KEYRING_SERVICE = "@halo-dev/cli";

export function formatProfileLabel(profileName: string): string {
  return `"${profileName}"`;
}

export interface CredentialStore {
  setProfileCredentials(profileName: string, credentials: HaloCredentials): Promise<void>;
  getProfileCredentials(profileName: string): Promise<HaloCredentials | undefined>;
  deleteProfileCredentials(profileName: string): Promise<void>;
}

export function probeKeyringCredentialStore(): void {
  findCredentials(HALO_CLI_KEYRING_SERVICE);
}

function getProfileKeyringEntry(profileName: string): Entry {
  return new Entry(HALO_CLI_KEYRING_SERVICE, `profile:${profileName}`);
}

function findProfileKeyringCredentials(
  profileName: string,
  operation: "read" | "delete",
): Credential[] {
  try {
    const account = `profile:${profileName}`;
    return findCredentials(HALO_CLI_KEYRING_SERVICE).filter(
      (credential) => credential.account === account,
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown keyring error.";
    throw new CliError(
      `Failed to ${operation} credentials for profile ${formatProfileLabel(profileName)}: ${message}`,
    );
  }
}

export function isHaloCredentials(value: unknown): value is HaloCredentials {
  if (!value || typeof value !== "object") {
    return false;
  }

  const auth = value as Partial<HaloCredentials> & Record<string, unknown>;
  if (auth.type === "basic") {
    return typeof auth.username === "string" && typeof auth.password === "string";
  }

  if (auth.type === "bearer") {
    return typeof auth.token === "string";
  }

  return false;
}

export class KeyringCredentialStore implements CredentialStore {
  async setProfileCredentials(profileName: string, credentials: HaloCredentials): Promise<void> {
    try {
      getProfileKeyringEntry(profileName).setPassword(JSON.stringify(credentials));
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown keyring error.";
      throw new CliError(
        `Failed to store credentials for profile ${formatProfileLabel(profileName)}: ${message}`,
      );
    }
  }

  async getProfileCredentials(profileName: string): Promise<HaloCredentials | undefined> {
    const raw = this.getListedPassword(profileName);
    if (raw === undefined) {
      return undefined;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new CliError(
        `Stored credentials for profile ${formatProfileLabel(profileName)} are invalid.`,
      );
    }

    if (!isHaloCredentials(parsed)) {
      throw new CliError(
        `Stored credentials for profile ${formatProfileLabel(profileName)} are invalid.`,
      );
    }

    return parsed;
  }

  async deleteProfileCredentials(profileName: string): Promise<void> {
    const matches = findProfileKeyringCredentials(profileName, "delete");
    if (matches.length === 0) {
      return;
    }
    if (matches.length > 1) {
      throw new CliError(
        `Stored credentials for profile ${formatProfileLabel(profileName)} are ambiguous.`,
      );
    }

    let deleted: boolean;
    try {
      deleted = getProfileKeyringEntry(profileName).deletePassword();
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown keyring error.";
      throw new CliError(
        `Failed to delete credentials for profile ${formatProfileLabel(profileName)}: ${message}`,
      );
    }

    if (deleted || findProfileKeyringCredentials(profileName, "delete").length === 0) {
      return;
    }

    throw new CliError(
      `Credentials for profile ${formatProfileLabel(profileName)} remain in the system keyring after deletion.`,
    );
  }

  private getListedPassword(profileName: string): string | undefined {
    const matches = findProfileKeyringCredentials(profileName, "read");
    if (matches.length === 0) {
      return undefined;
    }
    if (matches.length > 1) {
      throw new CliError(
        `Stored credentials for profile ${formatProfileLabel(profileName)} are ambiguous.`,
      );
    }
    return matches[0].password;
  }
}
