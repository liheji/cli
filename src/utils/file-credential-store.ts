import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { chmod, mkdir, open, readFile, rename, rm, type FileHandle } from "node:fs/promises";
import { join } from "node:path";

import type { HaloCredentials } from "../shared/profile.js";
import { type CredentialStore, formatProfileLabel, isHaloCredentials } from "./credential-store.js";
import { CliError } from "./errors.js";
import { stringifyJson } from "./output.js";

interface FileCredentialRecord {
  profileName?: unknown;
  credentials?: unknown;
}

export interface FileCredentialStoreFileSystem {
  chmod: typeof chmod;
  mkdir: typeof mkdir;
  open: typeof open;
  readFile: typeof readFile;
  rename: typeof rename;
  rm: typeof rm;
}

export interface FileCredentialStoreOptions {
  fileSystem?: Partial<FileCredentialStoreFileSystem>;
}

const DEFAULT_FILE_SYSTEM: FileCredentialStoreFileSystem = {
  chmod,
  mkdir,
  open,
  readFile,
  rename,
  rm,
};

function isFileNotFound(error: unknown): boolean {
  return (error as NodeJS.ErrnoException).code === "ENOENT";
}

export class FileCredentialStore implements CredentialStore {
  readonly credentialsDirectory: string;
  private readonly fileSystem: FileCredentialStoreFileSystem;
  private supportCheck?: Promise<void>;

  constructor(configRoot: string, { fileSystem }: FileCredentialStoreOptions = {}) {
    this.credentialsDirectory = join(configRoot, "credentials");
    this.fileSystem = { ...DEFAULT_FILE_SYSTEM, ...fileSystem };
  }

  async ensureSupported(): Promise<void> {
    let supportCheck = this.supportCheck;
    if (!supportCheck) {
      supportCheck = this.checkSupport();
      this.supportCheck = supportCheck;
    }

    try {
      await supportCheck;
      // Cache the successful result — subsequent calls return immediately.
    } catch {
      // Clear the cache on failure so the next call retries.
      if (this.supportCheck === supportCheck) {
        this.supportCheck = undefined;
      }
      throw supportCheck;
    }
  }

  async setProfileCredentials(profileName: string, credentials: HaloCredentials): Promise<void> {
    await this.ensureSupported();
    const credentialPath = this.getCredentialPath(profileName);
    const temporaryPath = join(
      this.credentialsDirectory,
      `.${this.getProfileHash(profileName)}.tmp-${process.pid}-${randomUUID()}`,
    );
    let handle: FileHandle | undefined;
    let renamed = false;
    let temporaryCreated = false;
    let operationError: unknown;

    try {
      handle = await this.fileSystem.open(
        temporaryPath,
        constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
        0o600,
      );
      temporaryCreated = true;
      await this.tryRestrictPermissions(temporaryPath, 0o600);
      await handle.writeFile(
        stringifyJson({ profileName, credentials } satisfies FileCredentialRecord),
        "utf8",
      );
      await handle.sync();
      await handle.close();
      handle = undefined;

      await this.fileSystem.rename(temporaryPath, credentialPath);
      renamed = true;
    } catch (error) {
      operationError = error;
    } finally {
      if (handle) {
        try {
          await handle.close();
        } catch (error) {
          operationError ??= error;
        }
      }
      if (temporaryCreated && !renamed) {
        try {
          await this.fileSystem.rm(temporaryPath, { force: true });
        } catch (cleanupError) {
          const operationMessage = this.getErrorMessage(operationError);
          const cleanupMessage = this.getErrorMessage(cleanupError);
          operationError = new Error(
            `${operationMessage}; failed to clean up temporary credential file: ${cleanupMessage}`,
          );
        }
      }
    }

    if (operationError) {
      throw new CliError(
        `Failed to store credentials for profile ${formatProfileLabel(profileName)}: ${this.getErrorMessage(operationError)}`,
      );
    }
  }

  async getProfileCredentials(profileName: string): Promise<HaloCredentials | undefined> {
    await this.ensureSupported();
    const credentialPath = this.getCredentialPath(profileName);
    let raw: string;

    try {
      await this.tryRestrictPermissions(credentialPath, 0o600);
      raw = await this.fileSystem.readFile(credentialPath, "utf8");
    } catch (error) {
      if (isFileNotFound(error)) {
        return undefined;
      }
      const message = error instanceof Error ? error.message : "Unknown file storage error.";
      throw new CliError(
        `Failed to read credentials for profile ${formatProfileLabel(profileName)}: ${message}`,
      );
    }

    let parsed: FileCredentialRecord;
    try {
      parsed = JSON.parse(raw) as FileCredentialRecord;
    } catch {
      throw this.invalidCredentialsError(profileName);
    }

    if (parsed.profileName !== profileName || !isHaloCredentials(parsed.credentials)) {
      throw this.invalidCredentialsError(profileName);
    }

    return parsed.credentials;
  }

  async deleteProfileCredentials(profileName: string): Promise<void> {
    await this.ensureSupported();
    try {
      await this.fileSystem.rm(this.getCredentialPath(profileName), { force: true });
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown file storage error.";
      throw new CliError(
        `Failed to delete credentials for profile ${formatProfileLabel(profileName)}: ${message}`,
      );
    }
  }

  private async checkSupport(): Promise<void> {
    await this.fileSystem.mkdir(this.credentialsDirectory, { recursive: true, mode: 0o700 });
    await this.tryRestrictPermissions(this.credentialsDirectory, 0o700);

    // Clean up leftover temp files from previous crashes
    try {
      const { readdir } = await import("node:fs/promises");
      const entries = await readdir(this.credentialsDirectory);
      for (const entry of entries) {
        if (entry.includes(".tmp-")) {
          await this.fileSystem.rm(join(this.credentialsDirectory, entry), { force: true })
            .catch(() => undefined);
        }
      }
    } catch {
      // Directory might not exist or be unreadable — safe to ignore
    }

    const probePath = join(
      this.credentialsDirectory,
      `.permission-probe-${process.pid}-${randomUUID()}`,
    );
    let handle: FileHandle | undefined;

    try {
      handle = await this.fileSystem.open(
        probePath,
        constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
        0o600,
      );
      await this.tryRestrictPermissions(probePath, 0o600);
    } finally {
      if (handle) {
        await handle.close().catch(() => undefined);
      }
      await this.fileSystem.rm(probePath, { force: true }).catch(() => undefined);
    }
  }

  private getErrorMessage(error: unknown): string {
    return error instanceof Error ? error.message : "Unknown file storage error.";
  }

  private async tryRestrictPermissions(path: string, mode: number): Promise<void> {
    try {
      await this.fileSystem.chmod(path, mode);
    } catch {
      // Some platforms and filesystems cannot apply POSIX permissions.
    }
  }

  private getCredentialPath(profileName: string): string {
    return join(this.credentialsDirectory, `${this.getProfileHash(profileName)}.json`);
  }

  private getProfileHash(profileName: string): string {
    return createHash("sha256").update(profileName).digest("hex");
  }

  private invalidCredentialsError(profileName: string): CliError {
    return new CliError(
      `Stored credentials for profile ${formatProfileLabel(profileName)} are invalid.`,
    );
  }
}
