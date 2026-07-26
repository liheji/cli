import { constants } from "node:fs";
import {
  chmod,
  mkdir,
  mkdtemp,
  open,
  readFile,
  rename,
  rm,
  type FileHandle,
} from "node:fs/promises";
import { join } from "node:path";

import type { CredentialStoreType, HaloCredentials } from "../shared/profile.js";
import { isCredentialStoreType } from "../shared/profile.js";
import {
  type CredentialStore,
  KeyringCredentialStore,
  probeKeyringCredentialStore,
} from "./credential-store.js";
import { CliError } from "./errors.js";
import { FileCredentialStore } from "./file-credential-store.js";
import { stringifyJson } from "./output.js";

interface FileCredentialStoreBackend extends CredentialStore {
  ensureSupported(): Promise<void>;
}

export interface ConfiguredCredentialStoreOptions {
  fileStore?: FileCredentialStoreBackend;
  keyringStore?: CredentialStore;
  probeKeyring?: () => void | Promise<void>;
  persistedType?: CredentialStoreType;
  persistSelection?: (type: CredentialStoreType) => Promise<void>;
}

interface CredentialStoreSelection {
  type: CredentialStoreType;
}

function isFileNotFound(error: unknown): boolean {
  return (error as NodeJS.ErrnoException).code === "ENOENT";
}

function isDirectorySyncUnsupported(error: unknown): boolean {
  return ["EACCES", "EBADF", "EISDIR", "EINVAL", "ENOSYS", "ENOTSUP", "EPERM"].includes(
    (error as NodeJS.ErrnoException).code ?? "",
  );
}

export class ConfiguredCredentialStore implements CredentialStore {
  readonly selectionDirectory: string;
  readonly selectionPath: string;
  private readonly configRoot: string;
  private readonly fileStore: FileCredentialStoreBackend;
  private readonly keyringStore: CredentialStore;
  private readonly probeKeyring: () => void | Promise<void>;
  private persistedType?: CredentialStoreType;
  private readonly persistSelection?: (type: CredentialStoreType) => Promise<void>;
  private initialization?: Promise<CredentialStore>;

  constructor(
    configRoot: string,
    {
      fileStore = new FileCredentialStore(configRoot),
      keyringStore = new KeyringCredentialStore(),
      probeKeyring = probeKeyringCredentialStore,
      persistedType,
      persistSelection,
    }: ConfiguredCredentialStoreOptions = {},
  ) {
    this.configRoot = configRoot;
    this.selectionDirectory = join(configRoot, "credential-store");
    this.selectionPath = join(this.selectionDirectory, "selection.json");
    this.fileStore = fileStore;
    this.keyringStore = keyringStore;
    this.probeKeyring = probeKeyring;
    this.persistedType = persistedType;
    this.persistSelection = persistSelection;
  }

  async setProfileCredentials(profileName: string, credentials: HaloCredentials): Promise<void> {
    return (await this.getStore()).setProfileCredentials(profileName, credentials);
  }

  async getProfileCredentials(profileName: string): Promise<HaloCredentials | undefined> {
    return (await this.getStore()).getProfileCredentials(profileName);
  }

  async deleteProfileCredentials(profileName: string): Promise<void> {
    return (await this.getStore()).deleteProfileCredentials(profileName);
  }

  setPersistedType(type: CredentialStoreType): void {
    this.persistedType = type;
  }

  private getStore(): Promise<CredentialStore> {
    if (!this.initialization) {
      this.initialization = this.initialize().catch((error) => {
        this.initialization = undefined;
        throw error;
      });
    }
    return this.initialization;
  }

  private async initialize(): Promise<CredentialStore> {
    // If caller provided a pre-resolved type, use it directly (no probe, no file I/O)
    if (this.persistedType) {
      return this.getStoreForType(this.persistedType);
    }

    // Check for existing selection on disk
    const existingSelection = await this.readSelection();
    if (existingSelection) {
      if (this.persistSelection) {
        await this.persistSelection(existingSelection.type);
      }
      return this.getStoreForType(existingSelection.type);
    }

    try {
      await mkdir(this.configRoot, { recursive: true });
    } catch (error) {
      return this.usePublishedSelectionOrThrow(error);
    }

    let candidateType: CredentialStoreType = "keyring";
    let keyringError: unknown;
    try {
      await this.probeKeyring();
    } catch (error) {
      keyringError = error;
      try {
        await this.fileStore.ensureSupported();
        candidateType = "file";
      } catch (fileError) {
        const keyringMessage = keyringError instanceof Error ? keyringError.message : "Unknown keyring error";
        const fileMessage = fileError instanceof Error ? fileError.message : "Unknown file storage error";
        return this.usePublishedSelectionOrThrow(
          new Error(`Keyring unavailable (${keyringMessage}) and file store unavailable (${fileMessage})`),
        );
      }
    }

    return this.publishSelection(candidateType);
  }

  private async publishSelection(type: CredentialStoreType): Promise<CredentialStore> {
    // If a persistSelection callback is provided, delegate to it instead of
    // writing selection.json. ConfigStore uses this to own the credentialStore
    // field in config.json.
    if (this.persistSelection) {
      await this.persistSelection(type);
      return this.getStoreForType(type);
    }

    let candidateDirectory: string | undefined;
    let handle: FileHandle | undefined;
    let published = false;

    try {
      candidateDirectory = await mkdtemp(join(this.configRoot, ".credential-store.tmp-"));
      await this.tryRestrictPermissions(candidateDirectory, 0o700);
      const candidateSelectionPath = join(candidateDirectory, "selection.json");
      handle = await open(
        candidateSelectionPath,
        constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
        0o600,
      );
      await handle.chmod(0o600).catch(() => undefined);
      await handle.writeFile(stringifyJson({ type } satisfies CredentialStoreSelection));
      await handle.sync();
      await handle.close();
      handle = undefined;

      await this.syncDirectory(candidateDirectory);

      try {
        await rename(candidateDirectory, this.selectionDirectory);
        published = true;
      } catch (error) {
        const winner = await this.readSelection();
        if (winner) {
          return this.getStoreForType(winner.type);
        }
        throw error;
      }

      try {
        await this.syncDirectory(this.configRoot);
      } catch (error) {
        throw this.initializationError(error);
      }

      return this.getStoreForType(type);
    } catch (error) {
      if (published) {
        throw this.initializationError(error);
      }
      return this.usePublishedSelectionOrThrow(error);
    } finally {
      if (handle) {
        await handle.close().catch(() => undefined);
      }
      if (candidateDirectory) {
        await rm(candidateDirectory, { recursive: true, force: true }).catch(() => undefined);
      }
    }
  }

  private async readSelection(): Promise<CredentialStoreSelection | undefined> {
    let raw: string;
    try {
      raw = await readFile(this.selectionPath, "utf8");
    } catch (error) {
      if (!isFileNotFound(error)) {
        throw this.initializationError(error);
      }
      return undefined;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new CliError(`Credential store selection is invalid at ${this.selectionPath}.`);
    }

    if (
      !parsed ||
      typeof parsed !== "object" ||
      !isCredentialStoreType((parsed as { type?: unknown }).type)
    ) {
      throw new CliError(`Credential store selection is invalid at ${this.selectionPath}.`);
    }

    return parsed as CredentialStoreSelection;
  }

  private async usePublishedSelectionOrThrow(error: unknown): Promise<CredentialStore> {
    const selection = await this.readSelection();
    if (selection) {
      return this.getStoreForType(selection.type);
    }
    throw this.initializationError(error);
  }

  private getStoreForType(type: CredentialStoreType): CredentialStore {
    if (type === "keyring") {
      return this.keyringStore;
    }
    return this.fileStore;
  }

  private async tryRestrictPermissions(path: string, mode: number): Promise<void> {
    await chmod(path, mode).catch(() => undefined);
  }

  private async syncDirectory(path: string): Promise<void> {
    let handle: FileHandle | undefined;
    try {
      handle = await open(path, constants.O_RDONLY);
      await handle.sync();
    } catch (error) {
      if (!isDirectorySyncUnsupported(error)) {
        throw error;
      }
    } finally {
      if (handle) {
        await handle.close().catch(() => undefined);
      }
    }
  }

  private initializationError(error: unknown): CliError {
    if (error instanceof CliError) {
      return error;
    }
    const message = error instanceof Error ? error.message : "Unknown credential store error.";
    return new CliError(`Failed to initialize credential store: ${message}`);
  }
}
