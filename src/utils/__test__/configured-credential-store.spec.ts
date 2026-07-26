import { mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { expect, test, vi } from "vite-plus/test";

import type { HaloCredentials } from "../../shared/profile.js";
import { ConfiguredCredentialStore } from "../configured-credential-store.js";
import type { CredentialStore } from "../credential-store.js";

class MemoryCredentialStore implements CredentialStore {
  readonly deleteProfileCredentials = vi.fn(async () => undefined);
  readonly getProfileCredentials = vi.fn(async () => this.credentials);
  readonly setProfileCredentials = vi.fn(async (_profileName: string, value: HaloCredentials) => {
    this.credentials = value;
  });

  constructor(private credentials: HaloCredentials) {}
}

class MemoryFileCredentialStore extends MemoryCredentialStore {
  readonly ensureSupported = vi.fn(async () => undefined);
}

function createStores() {
  return {
    fileStore: new MemoryFileCredentialStore({ type: "bearer", token: "file" }),
    keyringStore: new MemoryCredentialStore({ type: "bearer", token: "keyring" }),
  };
}

async function withTempRoot(run: (root: string) => Promise<void>): Promise<void> {
  const parent = await mkdtemp(join(tmpdir(), "halo-configured-credentials-"));
  const root = join(parent, "missing-config-root");
  try {
    await run(root);
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
}

async function writeSelection(root: string, contents: unknown): Promise<void> {
  const selectionDirectory = join(root, "credential-store");
  await mkdir(selectionDirectory, { recursive: true, mode: 0o700 });
  await writeFile(join(selectionDirectory, "selection.json"), JSON.stringify(contents), {
    mode: 0o600,
  });
}

async function readSelection(root: string): Promise<{ type: string }> {
  return JSON.parse(await readFile(join(root, "credential-store", "selection.json"), "utf8")) as {
    type: string;
  };
}

test("ConfiguredCredentialStore selects and persists keyring", async () => {
  await withTempRoot(async (root) => {
    const stores = createStores();
    const probeKeyring = vi.fn(async () => undefined);
    const store = new ConfiguredCredentialStore(root, { ...stores, probeKeyring });

    await expect(store.getProfileCredentials("local")).resolves.toEqual({
      type: "bearer",
      token: "keyring",
    });
    await store.getProfileCredentials("local");

    expect(probeKeyring).toHaveBeenCalledTimes(1);
    expect(await readSelection(root)).toEqual({ type: "keyring" });
    if (process.platform !== "win32") {
      expect(
        await stat(join(root, "credential-store", "selection.json")).then(
          (value) => value.mode & 0o777,
        ),
      ).toBe(0o600);
    }
  });
});

test("ConfiguredCredentialStore selects file when initial keyring probing fails", async () => {
  await withTempRoot(async (root) => {
    const stores = createStores();
    const store = new ConfiguredCredentialStore(root, {
      ...stores,
      probeKeyring: async () => {
        throw new Error("DBus unavailable");
      },
    });

    await expect(store.getProfileCredentials("local")).resolves.toEqual({
      type: "bearer",
      token: "file",
    });
    expect(stores.fileStore.ensureSupported).toHaveBeenCalledTimes(1);
    expect(await readSelection(root)).toEqual({ type: "file" });
  });
});

test("ConfiguredCredentialStore reuses a persisted selection without probing", async () => {
  await withTempRoot(async (root) => {
    await writeSelection(root, { type: "keyring" });
    const stores = createStores();
    const probeKeyring = vi.fn(async () => undefined);
    const store = new ConfiguredCredentialStore(root, { ...stores, probeKeyring });

    await expect(store.getProfileCredentials("local")).resolves.toEqual({
      type: "bearer",
      token: "keyring",
    });

    expect(probeKeyring).not.toHaveBeenCalled();
  });
});

test("ConfiguredCredentialStore reuses a persisted file selection", async () => {
  await withTempRoot(async (root) => {
    await writeSelection(root, { type: "file" });
    const stores = createStores();
    const store = new ConfiguredCredentialStore(root, {
      ...stores,
      probeKeyring: vi.fn(async () => undefined),
    });

    await expect(store.getProfileCredentials("local")).resolves.toEqual({
      type: "bearer",
      token: "file",
    });
    expect(stores.fileStore.getProfileCredentials).toHaveBeenCalledWith("local");
  });
});

test("ConfiguredCredentialStore persists file when probing fails", async () => {
  await withTempRoot(async (root) => {
    const stores = createStores();
    const store = new ConfiguredCredentialStore(root, {
      ...stores,
      probeKeyring: async () => {
        throw new Error("keyring unavailable");
      },
    });

    await expect(store.getProfileCredentials("local")).resolves.toEqual({
      type: "bearer",
      token: "file",
    });
    expect(await readSelection(root)).toEqual({ type: "file" });
    expect(stores.fileStore.ensureSupported).toHaveBeenCalledTimes(1);
  });
});

test.each([
  ["unsupported type", JSON.stringify({ type: "future-store" })],
  ["invalid JSON", "not-json"],
])("ConfiguredCredentialStore rejects %s selection records", async (_label, contents) => {
  await withTempRoot(async (root) => {
    const selectionDirectory = join(root, "credential-store");
    await mkdir(selectionDirectory, { recursive: true, mode: 0o700 });
    await writeFile(join(selectionDirectory, "selection.json"), contents, { mode: 0o600 });
    const probeKeyring = vi.fn(async () => undefined);
    const store = new ConfiguredCredentialStore(root, { ...createStores(), probeKeyring });

    await expect(store.getProfileCredentials("local")).rejects.toThrow(
      /credential store selection is invalid/i,
    );
    expect(probeKeyring).not.toHaveBeenCalled();
  });
});

test("ConfiguredCredentialStore converges concurrent initialization on one selection", async () => {
  await withTempRoot(async (root) => {
    let arrivals = 0;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const createProbe = (shouldFail: boolean) => async () => {
      arrivals += 1;
      if (arrivals === 2) {
        release();
      }
      await gate;
      if (shouldFail) {
        throw new Error("DBus unavailable");
      }
    };
    const first = new ConfiguredCredentialStore(root, {
      ...createStores(),
      probeKeyring: createProbe(false),
    });
    const second = new ConfiguredCredentialStore(root, {
      ...createStores(),
      probeKeyring: createProbe(true),
    });

    const [firstCredentials, secondCredentials] = await Promise.all([
      first.getProfileCredentials("local"),
      second.getProfileCredentials("local"),
    ]);
    const selection = await readSelection(root);

    expect(firstCredentials).toEqual({ type: "bearer", token: selection.type });
    expect(secondCredentials).toEqual({ type: "bearer", token: selection.type });
    expect(
      (await readdir(root)).every((entry) => !entry.startsWith(".credential-store.tmp-")),
    ).toBe(true);
  });
});

test("ConfiguredCredentialStore adopts a selection published before returning an error", async () => {
  await withTempRoot(async (root) => {
    const stores = createStores();
    const store = new ConfiguredCredentialStore(root, {
      ...stores,
      probeKeyring: async () => {
        await writeSelection(root, { type: "keyring" });
        throw new Error("keyring unavailable");
      },
    });

    await expect(store.getProfileCredentials("local")).resolves.toEqual({
      type: "bearer",
      token: "keyring",
    });
  });
});

test("ConfiguredCredentialStore retries initialization after an initial failure", async () => {
  await withTempRoot(async (root) => {
    const stores = createStores();
    let attempts = 0;
    stores.fileStore.ensureSupported.mockImplementation(async () => {
      if (attempts === 1) {
        throw new Error("temporary file storage failure");
      }
    });
    const store = new ConfiguredCredentialStore(root, {
      ...stores,
      probeKeyring: async () => {
        attempts += 1;
        if (attempts === 1) {
          throw new Error("temporary keyring failure");
        }
      },
    });

    await expect(store.getProfileCredentials("local")).rejects.toThrow(
      "temporary file storage failure",
    );
    await expect(store.getProfileCredentials("local")).resolves.toEqual({
      type: "bearer",
      token: "keyring",
    });
    expect(attempts).toBe(2);
  });
});
