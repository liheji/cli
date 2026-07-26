import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { expect, test } from "vite-plus/test";

import type { HaloProfile } from "../../shared/profile.js";
import { ConfigStore, resolveConfigRoot } from "../config-store.js";
import { ConfiguredCredentialStore } from "../configured-credential-store.js";
import type { CredentialStore } from "../credential-store.js";

async function withTempStore(
  run: (context: { store: ConfigStore; credentials: Map<string, string> }) => Promise<void>,
): Promise<void> {
  const root = await mkdtemp(join(tmpdir(), "halo-cli-test-"));
  const credentials = new Map<string, string>();
  const credentialStore: CredentialStore = {
    async setProfileCredentials(profileName, auth) {
      credentials.set(profileName, JSON.stringify(auth));
    },
    async getProfileCredentials(profileName) {
      const raw = credentials.get(profileName);
      return raw ? (JSON.parse(raw) as HaloProfile["auth"]) : undefined;
    },
    async deleteProfileCredentials(profileName) {
      credentials.delete(profileName);
    },
  };
  const store = new ConfigStore(join(root, "config.json"), credentialStore);

  try {
    await run({ store, credentials });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

function createProfile(name: string): HaloProfile {
  return {
    name,
    baseUrl: "https://demo.halo.run",
    auth: {
      type: "bearer",
      token: "token-value",
    },
    createdAt: "2026-03-18T00:00:00.000Z",
    updatedAt: "2026-03-18T00:00:00.000Z",
  };
}

test("resolveConfigRoot follows CLI, XDG, and home precedence", () => {
  expect(
    resolveConfigRoot(
      {
        HALO_CLI_CONFIG_DIR: "/custom/halo-config",
        XDG_CONFIG_HOME: "/xdg",
      },
      "/home/test",
    ),
  ).toBe("/custom/halo-config");
  expect(resolveConfigRoot({ XDG_CONFIG_HOME: "/xdg" }, "/home/test")).toBe("/xdg/halo");
  expect(resolveConfigRoot({}, "/home/test")).toBe("/home/test/.config/halo");
});

test("ConfigStore colocates default credential storage with a custom config path", async () => {
  const root = await mkdtemp(join(tmpdir(), "halo-cli-default-credentials-"));
  const configPath = join(root, "nested", "config.json");

  try {
    const store = new ConfigStore(configPath);

    expect(store.credentialStore).toBeInstanceOf(ConfiguredCredentialStore);
    expect((store.credentialStore as ConfiguredCredentialStore).selectionPath).toBe(
      join(root, "nested", "credential-store", "selection.json"),
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("ConfigStore persists profiles and active profile", async () => {
  await withTempStore(async ({ store }) => {
    await store.upsertProfile(createProfile("default"), true);

    const loaded = await store.load();
    expect(loaded.activeProfile).toBe("default");
    expect(loaded.profiles.default?.baseUrl).toBe("https://demo.halo.run");
    expect(loaded.profiles.default?.auth).toEqual({ type: "bearer" });

    const active = await store.getActiveResolvedProfile();
    expect(active.name).toBe("default");
    expect(active.auth).toEqual({
      type: "bearer",
      token: "token-value",
    });
  });
});

test("ConfigStore keeps secrets out of config.json", async () => {
  await withTempStore(async ({ store }) => {
    await store.upsertProfile(createProfile("default"), true);

    const configJson = await readFile(store.configPath, "utf8");
    expect(configJson).not.toContain("token-value");
  });
});

test("ConfigStore rejects legacy inline credentials in config.json", async () => {
  await withTempStore(async ({ store }) => {
    await writeFile(
      store.configPath,
      `${JSON.stringify(
        {
          activeProfile: "legacy",
          profiles: {
            legacy: {
              name: "legacy",
              baseUrl: "https://demo.halo.run",
              auth: {
                type: "bearer",
                token: "token-value",
              },
              createdAt: "2026-03-18T00:00:00.000Z",
              updatedAt: "2026-03-18T00:00:00.000Z",
            },
          },
        },
        null,
        2,
      )}\n`,
      "utf8",
    );

    await expect(store.load()).rejects.toThrow(/unsupported legacy credential format/i);
  });
});

test("ConfigStore resolves explicit profiles without using active profile", async () => {
  await withTempStore(async ({ store }) => {
    await store.upsertProfile(createProfile("default"), true);
    await store.upsertProfile(createProfile("staging"), false);

    const active = await store.getActiveResolvedProfile("staging");
    expect(active.name).toBe("staging");
  });
});

test("ConfigStore lists profiles and marks the active profile", async () => {
  await withTempStore(async ({ store }) => {
    await store.upsertProfile(createProfile("prod"), true);
    await store.upsertProfile(createProfile("staging"), false);

    const result = await store.listProfiles();
    expect(result.activeProfile).toBe("prod");
    const names = result.profiles.map((profile) => profile.name);
    expect(names).toContain("prod");
    expect(names).toContain("staging");
  });
});

test("ConfigStore switches the active profile", async () => {
  await withTempStore(async ({ store }) => {
    await store.upsertProfile(createProfile("prod"), true);
    await store.upsertProfile(createProfile("staging"), false);

    const profile = await store.setActiveProfile("staging");
    expect(profile.name).toBe("staging");

    const result = await store.listProfiles();
    expect(result.activeProfile).toBe("staging");
  });
});

test("ConfigStore rejects missing active profiles", async () => {
  await withTempStore(async ({ store }) => {
    await expect(store.getActiveResolvedProfile()).rejects.toThrow(/No active Halo profile found/);
  });
});

test("ConfigStore reports missing credentials without assuming keyring storage", async () => {
  await withTempStore(async ({ store, credentials }) => {
    await store.upsertProfile(createProfile("default"), true);
    credentials.delete("default");

    await expect(store.getActiveResolvedProfile()).rejects.toThrow(/credential store/i);
    await expect(store.getActiveResolvedProfile()).rejects.not.toThrow(/system keyring/i);
  });
});

test("ConfigStore deletes profiles and clears their stored credentials", async () => {
  await withTempStore(async ({ store, credentials }) => {
    await store.upsertProfile(createProfile("prod"), true);

    const result = await store.deleteProfile("prod");

    expect(result.profile.name).toBe("prod");
    expect(result.activeProfile).toBeUndefined();
    expect(await store.getStoredProfile("prod")).toBeUndefined();
    expect(credentials.has("prod")).toBe(false);
  });
});

test("ConfigStore removes profile even when credential deletion fails", async () => {
  await withTempStore(async ({ store, credentials }) => {
    await store.upsertProfile(createProfile("prod"), true);
    store.credentialStore.deleteProfileCredentials = async () => {
      throw new Error("credential delete failed");
    };

    await expect(store.deleteProfile("prod")).rejects.toThrow("credential delete failed");
    // Profile is removed from config before credential deletion — save succeeded
    expect(await store.getStoredProfile("prod")).toBeUndefined();
    // Credentials are orphaned but harmless; the error propagated correctly
    expect(credentials.has("prod")).toBe(true);
  });
});

test("ConfigStore inspects profile credential health", async () => {
  await withTempStore(async ({ store, credentials }) => {
    await store.upsertProfile(createProfile("prod"), true);
    await store.upsertProfile(createProfile("staging"), false);
    credentials.delete("staging");

    const report = await store.inspectProfileCredentials();

    expect(report.ok).toBe(false);
    expect(report.activeProfile).toBe("prod");
    expect(report.profiles).toEqual([
      {
        name: "prod",
        baseUrl: "https://demo.halo.run",
        authType: "bearer",
        status: "ok",
      },
      {
        name: "staging",
        baseUrl: "https://demo.halo.run",
        authType: "bearer",
        status: "missing-credentials",
      },
    ]);
  });
});

test("ConfigStore.load returns credentialStore from config.json", async () => {
  await withTempStore(async ({ store }) => {
    await writeFile(
      store.configPath,
      JSON.stringify({
        credentialStore: "file",
        profiles: {},
      }),
      "utf8",
    );
    const config = await store.load();
    expect(config.credentialStore).toBe("file");
  });
});

test("ConfigStore.save injects resolvedCredentialStore after persisting", async () => {
  const root = await mkdtemp(join(tmpdir(), "halo-cli-credstore-"));
  const configPath = join(root, "config.json");
  try {
    const store = new ConfigStore(configPath);
    // Manually set credentialStore as if persistSelection callback fired
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (store as any).resolvedCredentialStore = "file";
    await store.save({ profiles: {} });
    const configJson = await readFile(configPath, "utf8");
    const parsed = JSON.parse(configJson);
    expect(parsed.credentialStore).toBe("file");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("ConfigStore migrates legacy selection.json on load", async () => {
  const root = await mkdtemp(join(tmpdir(), "halo-cli-migration-"));
  const configPath = join(root, "config.json");
  try {
    // Write empty config.json so load doesn't fail with ENOENT
    await mkdir(dirname(configPath), { recursive: true });
    await writeFile(configPath, JSON.stringify({ profiles: {} }), "utf8");
    // Create old-style selection.json
    const selectionDir = join(root, "credential-store");
    await mkdir(selectionDir, { recursive: true });
    await writeFile(
      join(selectionDir, "selection.json"),
      JSON.stringify({ type: "file" }),
      "utf8",
    );

    const store = new ConfigStore(configPath);
    const config = await store.load();
    expect(config.credentialStore).toBe("file");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("ConfigStore silently skips corrupt selection.json during migration", async () => {
  const root = await mkdtemp(join(tmpdir(), "halo-cli-corrupt-"));
  const configPath = join(root, "config.json");
  try {
    await mkdir(dirname(configPath), { recursive: true });
    await writeFile(configPath, JSON.stringify({ profiles: {} }), "utf8");
    const selectionDir = join(root, "credential-store");
    await mkdir(selectionDir, { recursive: true });
    await writeFile(
      join(selectionDir, "selection.json"),
      "not valid json",
      "utf8",
    );

    const store = new ConfigStore(configPath);
    const config = await store.load();
    expect(config.credentialStore).toBeUndefined();
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("ConfigStore config.json credentialStore takes precedence over selection.json", async () => {
  await withTempStore(async ({ store }) => {
    // Write config.json with credentialStore: "keyring"
    await writeFile(
      store.configPath,
      JSON.stringify({
        credentialStore: "keyring",
        profiles: {},
      }),
      "utf8",
    );
    // Write conflicting selection.json
    const selectionDir = join(dirname(store.configPath), "credential-store");
    await mkdir(selectionDir, { recursive: true });
    await writeFile(
      join(selectionDir, "selection.json"),
      JSON.stringify({ type: "file" }),
      "utf8",
    );

    const config = await store.load();
    expect(config.credentialStore).toBe("keyring");
  });
});

test("ConfigStore deleteProfile does not call deleteProfileCredentials when save fails", async () => {
  await withTempStore(async ({ store }) => {
    await store.upsertProfile(createProfile("prod"), true);
    const origSave = store.save.bind(store);
    let deleteCalled = false;
    store.save = async (_config) => {
      throw new Error("save failed");
    };
    store.credentialStore.deleteProfileCredentials = async () => {
      deleteCalled = true;
    };

    await expect(store.deleteProfile("prod")).rejects.toThrow("save failed");
    expect(deleteCalled).toBe(false);
    store.save = origSave; // restore for cleanup
  });
});
