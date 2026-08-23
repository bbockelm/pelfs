import { RestDataProvider } from "@svar-ui/filemanager-data-provider";

/**
 * The data provider pelfs uses, and the reason it exists rather than the
 * shipped one being used directly.
 *
 * The U0 probe (webui/frontend/probe, recording in
 * internal/webui/testdata/svar-contract) found two things on the wire that
 * matter to this design:
 *
 *  1. `RestDataProvider.send()` overrides the base `Rest.send()` and spreads
 *     ONLY its `customHeaders` argument -- it never reads `this._customHeaders`.
 *     So `provider.setHeaders({...})`, the documented way to add a
 *     credential, is silently dropped: the probe called it and watched the
 *     header never reach the wire. The session token is header-borne by
 *     design (docs/design-webui.md: no session cookie), so this is not a
 *     nicety, it is the credential.
 *
 *  2. Every mutating request goes out as `Content-Type: text/plain;charset=UTF-8`
 *     -- fetch's default for a string body, because the provider sets no
 *     content type at all. `text/plain` is one of the three types an HTML
 *     form can send, so a server that accepts it has given up the
 *     content-type half of its CSRF defence, and the threat model's
 *     "mutating route with text/plain => 415" row would reject every write
 *     the file manager makes.
 *
 * Overriding `send` fixes both in three lines, which is why the probe ran
 * before the app was written.
 */
export class PelfsDataProvider extends RestDataProvider {
  #session: string;

  constructor(url: string, session: string) {
    super(url);
    this.#session = session;
  }

  setSession(token: string) {
    this.#session = token;
  }

  send<T>(url: string, method: string, data?: unknown, customHeaders?: Record<string, string>) {
    const headers: Record<string, string> = { ...(customHeaders || {}) };
    if (this.#session) headers["X-Pelfs-Session"] = this.#session;
    // A string body is the provider's JSON; a FormData body is the upload,
    // whose boundary only fetch can write, so it must keep its own type.
    if (typeof data === "string") headers["Content-Type"] = "application/json";
    return super.send<T>(url, method, data, headers);
  }
}

/**
 * The wiring the store needs for lazy directory loading, which is NOT
 * automatic: the store emits `request-data` when a folder marked
 * `lazy: true` is navigated into, and expects the answer back as
 * `provide-data`. The shipped RestDataProvider registers no handler for
 * `request-data` at all, so without this the tree simply never loads.
 *
 * The probe also caught the store emitting `request-data` TWICE for one
 * navigation, which on a 100k-entry directory is two full listings. Hence
 * the in-flight guard.
 */
export function wireLazyLoading(api: {
  on: (action: string, cb: (ev: { id: string }) => void) => void;
  exec: (action: string, ev: unknown) => void;
}, provider: PelfsDataProvider) {
  const inFlight = new Set<string>();
  api.on("request-data", (ev) => {
    if (inFlight.has(ev.id)) return;
    inFlight.add(ev.id);
    provider
      .loadFiles(ev.id)
      .then((data) => api.exec("provide-data", { id: ev.id, data }))
      .finally(() => inFlight.delete(ev.id));
  });
}
