import type {Binding, Identity, IdentityAdapter, Scope, Checkpoint} from 'sea-device-link';
import type {ResolutionContext} from 'sociacl-ids';
import type {KeyringState} from 'sociacl-ids/keyring';
export type AuthorityResponse = {
  identity: Identity;
  scope: Scope;
  binding: Binding | null;
  at: number;
  checkpoint: Checkpoint;
  trust: Pick<ResolutionContext, 'jwks' | 'policy'> & {pinnedIss: string[]};
  history: {
    completeThrough: number;
    links: unknown[];
    accounts: {principal: string; rotations: unknown[]; revocations: unknown[]; genesisEpubBindings: unknown[]}[];
  };
};
export type StateRequest = {scope: Scope; identity: Identity};
export type CurrentRequest = {binding: Binding; expectedRevision?: string};
/** Must authenticate ACL over HTTPS, bound response bytes and refuse non-2xx.
 * Scope and credentials come from trusted application configuration, never QR. */
export type AuthorityRequest = (operation: 'state' | 'current', body: StateRequest | CurrentRequest) => Promise<unknown>;
export type AuthorityOptions = {scope: Scope; request: AuthorityRequest; now?: () => number};
export type Authority = IdentityAdapter & {
  /** Fresh authenticated state for local import/export. Never sourced from a transfer. */
  keyringState(identity: Identity): Promise<KeyringState>;
  close(): void;
};
export function createAuthority(options: AuthorityOptions): Authority;
