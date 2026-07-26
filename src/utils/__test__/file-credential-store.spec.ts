import { createHash } from "node:crypto";
import {
  chmod,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { expect, test } from "vite-plus/test";

import type { HaloCredentials } from "../../shared/profile.js";
import { FileCredentialStore } from "../file-credential-store.js";

const posixTest = process.platform === "win32" ? test.skip : test;

function getCredentialPath(root: string, profileName: string): string {
  const hash = createHash("sha256").update(profileName).digest("hex");
  return join(root, "credentials", `${hash}.json`);
}

async function withTempRoot(run: (root: string) => Promise<void>): Promise<void> {
  const root = await mkdtemp(join(tmpdir(), "halo-file-credentials-"));
  try {
    await run(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test.each([
  {
    type: "bearer",
    token: "token-value",
  } satisfies HaloCredentials,
  {
    type: "basic",
    username: "admin",
    password: "password-value",
  } satisfies HaloCredentials,
])("FileCredentialStore round-trips $type credentials", async (credentials) => {
  await withTempRoot(async (root) => {
    const store = new FileCredentialStore(root);

    await store.setProfileCredentials("local", credentials);

    await expect(store.getProfileCredentials("local")).resolves.toEqual(credentials);
  });
});

posixTest("FileCredentialStore hashes profile names and restricts file permissions", async () => {
  await withTempRoot(async (root) => {
    const store = new FileCredentialStore(root);
    const credentialPath = getCredentialPath(root, "../../local");

    await store.setProfileCredentials("../../local", {
      type: "bearer",
      token: "token-value",
    });

    expect(await stat(credentialPath).then((value) => value.mode & 0o777)).toBe(0o600);
    expect(await stat(join(root, "credentials")).then((value) => value.mode & 0o777)).toBe(0o700);
  });
});

test("FileCredentialStore deletes only the selected profile", async () => {
  await withTempRoot(async (root) => {
    const store = new FileCredentialStore(root);
    await store.setProfileCredentials("prod", { type: "bearer", token: "prod-token" });
    await store.setProfileCredentials("staging", { type: "bearer", token: "staging-token" });

    await store.deleteProfileCredentials("prod");

    await expect(store.getProfileCredentials("prod")).resolves.toBeUndefined();
    await expect(store.getProfileCredentials("staging")).resolves.toEqual({
      type: "bearer",
      token: "staging-token",
    });
  });
});

test("FileCredentialStore rejects invalid JSON", async () => {
  await withTempRoot(async (root) => {
    const credentialPath = getCredentialPath(root, "local");
    await mkdir(join(root, "credentials"), { recursive: true, mode: 0o700 });
    await writeFile(credentialPath, "not-json", { mode: 0o600 });

    await expect(new FileCredentialStore(root).getProfileCredentials("local")).rejects.toThrow(
      /stored credentials for profile "local" are invalid/i,
    );
  });
});

test("FileCredentialStore rejects credentials with a mismatched profile name", async () => {
  await withTempRoot(async (root) => {
    const credentialPath = getCredentialPath(root, "local");
    await mkdir(join(root, "credentials"), { recursive: true, mode: 0o700 });
    await writeFile(
      credentialPath,
      JSON.stringify({
        profileName: "other",
        credentials: { type: "bearer", token: "token-value" },
      }),
      { mode: 0o600 },
    );

    await expect(new FileCredentialStore(root).getProfileCredentials("local")).rejects.toThrow(
      /stored credentials for profile "local" are invalid/i,
    );
  });
});

test("FileCredentialStore rejects invalid credential structures", async () => {
  await withTempRoot(async (root) => {
    const credentialPath = getCredentialPath(root, "local");
    await mkdir(join(root, "credentials"), { recursive: true, mode: 0o700 });
    await writeFile(
      credentialPath,
      JSON.stringify({
        profileName: "local",
        credentials: { type: "bearer", username: "admin" },
      }),
      { mode: 0o600 },
    );

    await expect(new FileCredentialStore(root).getProfileCredentials("local")).rejects.toThrow(
      /stored credentials for profile "local" are invalid/i,
    );
  });
});

posixTest("FileCredentialStore restricts existing file permissions before reading", async () => {
  await withTempRoot(async (root) => {
    const credentialPath = getCredentialPath(root, "local");
    await mkdir(join(root, "credentials"), { recursive: true, mode: 0o700 });
    await writeFile(
      credentialPath,
      JSON.stringify({
        profileName: "local",
        credentials: { type: "bearer", token: "token-value" },
      }),
      { mode: 0o644 },
    );
    await chmod(credentialPath, 0o644);

    await new FileCredentialStore(root).getProfileCredentials("local");

    expect(await stat(credentialPath).then((value) => value.mode & 0o777)).toBe(0o600);
  });
});

test("FileCredentialStore preserves concurrent writes for different profiles", async () => {
  await withTempRoot(async (root) => {
    const store = new FileCredentialStore(root);

    await Promise.all([
      store.setProfileCredentials("prod", { type: "bearer", token: "prod-token" }),
      store.setProfileCredentials("staging", { type: "bearer", token: "staging-token" }),
    ]);

    await expect(store.getProfileCredentials("prod")).resolves.toEqual({
      type: "bearer",
      token: "prod-token",
    });
    await expect(store.getProfileCredentials("staging")).resolves.toEqual({
      type: "bearer",
      token: "staging-token",
    });
  });
});

posixTest("FileCredentialStore validates directory permissions once on first write", async () => {
  await withTempRoot(async (root) => {
    const store = new FileCredentialStore(root);
    await store.setProfileCredentials("prod", { type: "bearer", token: "prod-token" });

    expect(await stat(join(root, "credentials")).then((value) => value.mode & 0o777)).toBe(0o700);

    // Changing permissions after the first write has no effect on the
    // same instance — ensureSupported() is cached. A new instance
    // re-runs checkSupport() and restores permissions.
    await chmod(join(root, "credentials"), 0o777);
    const freshStore = new FileCredentialStore(root);
    await freshStore.setProfileCredentials("staging", {
      type: "bearer",
      token: "staging-token",
    });

    expect(await stat(join(root, "credentials")).then((value) => value.mode & 0o777)).toBe(0o700);
  });
});

test("FileCredentialStore preserves old credentials when atomic rename fails", async () => {
  await withTempRoot(async (root) => {
    const originalStore = new FileCredentialStore(root);
    await originalStore.setProfileCredentials("local", {
      type: "bearer",
      token: "old-token",
    });
    const store = new FileCredentialStore(root, {
      fileSystem: {
        async rename() {
          throw new Error("rename failed");
        },
      },
    });

    await expect(
      store.setProfileCredentials("local", { type: "bearer", token: "new-token" }),
    ).rejects.toThrow("rename failed");
    await expect(originalStore.getProfileCredentials("local")).resolves.toEqual({
      type: "bearer",
      token: "old-token",
    });

    const entries = await readdir(join(root, "credentials"));
    expect(entries.every((entry) => !entry.includes(".tmp-"))).toBe(true);
    expect(JSON.parse(await readFile(getCredentialPath(root, "local"), "utf8"))).toMatchObject({
      credentials: { token: "old-token" },
    });
  });
});

test("FileCredentialStore cleans up leftover temporary files on next process startup", async () => {
  await withTempRoot(async (root) => {
    let failCleanup = true;
    const store = new FileCredentialStore(root, {
      fileSystem: {
        async rename() {
          throw new Error("rename failed");
        },
        async rm(path, options) {
          if (failCleanup && String(path).includes(".tmp-")) {
            throw new Error("cleanup failed");
          }
          return rm(path, options);
        },
      },
    });

    await expect(
      store.setProfileCredentials("local", { type: "bearer", token: "new-token" }),
    ).rejects.toThrow(/rename failed.*cleanup failed/i);
    expect(
      (await readdir(join(root, "credentials"))).some((entry) => entry.includes(".tmp-")),
    ).toBe(true);

    // A new store instance runs checkSupport() on first use, which glob-scans and cleans up temp files
    failCleanup = false;
    const freshStore = new FileCredentialStore(root);
    await freshStore.setProfileCredentials("local", { type: "bearer", token: "fresh-token" });

    // The leftover temp file from the previous instance should now be cleaned up
    expect(
      (await readdir(join(root, "credentials"))).every((entry) => !entry.includes(".tmp-")),
    ).toBe(true);
  });
});

test("FileCredentialStore cleans up only temporary files it created", async () => {
  await withTempRoot(async (root) => {
    let attemptedCredentialCleanup = false;
    const store = new FileCredentialStore(root, {
      fileSystem: {
        async open(path, flags, mode) {
          if (String(path).includes(".tmp-")) {
            throw Object.assign(new Error("temporary path already exists"), { code: "EEXIST" });
          }
          return open(path, flags, mode);
        },
        async rm(path, options) {
          if (String(path).includes(".tmp-")) {
            attemptedCredentialCleanup = true;
          }
          return rm(path, options);
        },
      },
    });

    await expect(
      store.setProfileCredentials("local", { type: "bearer", token: "token-value" }),
    ).rejects.toThrow("temporary path already exists");
    expect(attemptedCredentialCleanup).toBe(false);
  });
});

test("FileCredentialStore continues when chmod is unavailable", async () => {
  await withTempRoot(async (root) => {
    const store = new FileCredentialStore(root, {
      fileSystem: {
        async chmod() {
          throw Object.assign(new Error("chmod is unavailable"), { code: "ENOTSUP" });
        },
      },
    });

    await expect(
      store.setProfileCredentials("local", { type: "bearer", token: "token-value" }),
    ).resolves.toBeUndefined();
    await expect(store.getProfileCredentials("local")).resolves.toEqual({
      type: "bearer",
      token: "token-value",
    });
  });
});

test("FileCredentialStore gracefully handles chmod failures on permission-restricted filesystems", async () => {
  await withTempRoot(async (root) => {
    const store = new FileCredentialStore(root, {
      fileSystem: {
        chmod: (async () => {
          throw new Error("EPERM: operation not permitted");
        }) as unknown as typeof chmod,
      },
    });

    await expect(
      store.setProfileCredentials("local", { type: "bearer", token: "token-value" }),
    ).resolves.toBeUndefined();
    await expect(store.getProfileCredentials("local")).resolves.toEqual({
      type: "bearer",
      token: "token-value",
    });
  });
});
