import { beforeEach, expect, test, vi } from "vite-plus/test";

const { deleteState, entryState, findCredentialsMock } = vi.hoisted(() => {
  const entryState = new Map<string, string | null>();
  return {
    deleteState: { succeeds: true },
    entryState,
    findCredentialsMock: vi.fn((service: string) => {
      const prefix = `${service}:`;
      return [...entryState.entries()]
        .filter(([key, password]) => key.startsWith(prefix) && password !== null)
        .map(([key, password]) => ({
          account: key.slice(prefix.length),
          password: password as string,
        }));
    }),
  };
});

vi.mock("@napi-rs/keyring", () => ({
  findCredentials: findCredentialsMock,
  Entry: class MockEntry {
    private readonly key: string;

    constructor(service: string, account: string) {
      this.key = `${service}:${account}`;
    }

    setPassword(value: string) {
      entryState.set(this.key, value);
    }

    getPassword() {
      return entryState.get(this.key) ?? null;
    }

    deletePassword() {
      if (!deleteState.succeeds) {
        return false;
      }
      entryState.delete(this.key);
      return true;
    }
  },
}));

import { KeyringCredentialStore } from "../credential-store.js";
import { CliError } from "../errors.js";

beforeEach(() => {
  entryState.clear();
  findCredentialsMock.mockClear();
  deleteState.succeeds = true;
});

test("KeyringCredentialStore round-trips bearer credentials", async () => {
  const store = new KeyringCredentialStore();

  await store.setProfileCredentials("local", {
    type: "bearer",
    token: "token-value",
  });

  await expect(store.getProfileCredentials("local")).resolves.toEqual({
    type: "bearer",
    token: "token-value",
  });
});

test("KeyringCredentialStore rejects invalid JSON returned from keyring", async () => {
  entryState.set("@halo-dev/cli:profile:broken-json", "not-json");
  const store = new KeyringCredentialStore();

  await expect(store.getProfileCredentials("broken-json")).rejects.toEqual(
    new CliError('Stored credentials for profile "broken-json" are invalid.'),
  );
});

test("KeyringCredentialStore rejects invalid credential structures from keyring", async () => {
  entryState.set(
    "@halo-dev/cli:profile:broken-shape",
    JSON.stringify({
      type: "bearer",
      username: "admin",
    }),
  );
  const store = new KeyringCredentialStore();

  await expect(store.getProfileCredentials("broken-shape")).rejects.toEqual(
    new CliError('Stored credentials for profile "broken-shape" are invalid.'),
  );
});

test("KeyringCredentialStore preserves errors while reading credentials", async () => {
  findCredentialsMock.mockImplementationOnce(() => {
    throw new Error("DBus unavailable");
  });
  const store = new KeyringCredentialStore();

  await expect(store.getProfileCredentials("local")).rejects.toEqual(
    new CliError('Failed to read credentials for profile "local": DBus unavailable'),
  );
});

test("KeyringCredentialStore reports credentials left after a failed delete", async () => {
  entryState.set(
    "@halo-dev/cli:profile:local",
    JSON.stringify({
      type: "bearer",
      token: "token-value",
    }),
  );
  deleteState.succeeds = false;
  const store = new KeyringCredentialStore();

  await expect(store.deleteProfileCredentials("local")).rejects.toThrow(
    /credentials for profile "local" remain in the system keyring/i,
  );
});
