import { RestDataProvider } from "@svar-ui/filemanager-data-provider";
import type { Entry, ListingMeta } from "./types";

/**
 * The data provider pelfs uses, and the reason it exists rather than the
 * shipped one being used directly.
 *
 * THERE ARE THREE DEFECTS in the shipped `RestDataProvider.send`, not two.
 * The U0 probe (webui/frontend/probe, recording in
 * internal/webui/testdata/svar-contract) found the first two on the wire;
 * reading the method afterwards found the third, which no wire trace could
 * show. The count is worth stating because it was recorded as two in three
 * places (this comment, probe/README.md, docs/design-webui.md) and the third
 * is the only one of them that can cost a user their belief about the volume:
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
 *     the file manager makes (internal/httpguard, SurfaceAPI).
 *
 *  3. IT SWALLOWS EVERY FAILURE. The shipped `send` is
 *
 *         return fetch(...).then(res => res.json()
 *             .then(response => { if (!res.ok) throw new Error(...); return response; })
 *             .catch(error => { console.error(error); }));
 *
 *     -- and that `.catch` is attached AFTER the throw, so the throw it just
 *     made is caught by it. A 401, a 415, a 500 or a torn connection all
 *     resolve to `undefined`, the promise never rejects, and the store keeps
 *     the optimistic change it already applied. The user sees the rename they
 *     asked for; the volume does not have it. For this audience that is the
 *     same class of lie as a green checkmark on unpublished data, so this
 *     class does its own fetch: the happy path is identical, and a failure is
 *     a rejected promise that reaches `onError` and the screen.
 *
 * All three are fixed here rather than patched around at every call site,
 * which is why the probe ran before the app was written.
 *
 * # The half of defect 3 that `send` cannot fix, and where it is fixed
 *
 * A rejected promise is necessary and not sufficient. The STORE applies every
 * mutation optimistically -- @svar-ui/filemanager-store's `rename-file`
 * handler renames the node and re-parents its children before the provider is
 * reached at all -- and nothing in the store or the component rolls that back
 * when the request fails. So with `send` fixed and nothing else, a refused
 * rename produced an error banner AND a row that kept the new name: the
 * banner said "that did not happen" while the screen showed that it had, and
 * of the two the screen is what a user believes.
 *
 * `getHandlers` below closes it, and the repair is deliberately not an
 * inverse operation. Undoing a rename in the store means computing what the
 * store did and doing the opposite, which is a second model of the volume
 * maintained by us -- and the first thing that model gets wrong is the case
 * that matters (a batch move whose fourth id failed). So the repair asks the
 * SERVER what the affected directories hold now and hands the answer back
 * through `provide-data`, which the store treats as authoritative. The volume
 * is the model; there is only ever one.
 */
export class PelfsDataProvider extends RestDataProvider {
  #session: string;
  #base: string;
  /**
   * Per-directory listing metadata, keyed by the id that was listed. The
   * cap lives in response HEADERS (see ListingMeta), and `loadFiles` returns
   * only the parsed body, so this is where the headers are kept for the UI
   * to read afterwards.
   */
  #listings = new Map<string, ListingMeta>();
  /**
   * The store's event bus, once the component has handed it over (`attach`).
   * It is how a refused mutation is undone -- by re-listing, not by inventing
   * an inverse. Null until `init(api)` runs.
   */
  #api: StoreBus | null = null;
  /** Told about every failure, so a refused operation reaches the screen. */
  onError: (err: Error, ctx: { url: string; method: string }) => void = () => {};
  /**
   * Told about every request that SUCCEEDED. The upload is why this exists:
   * the component's uploader hands the file to the store and nothing in the
   * store or the component knows when the POST finished, and "your bytes are
   * on this machine now, and only there" is exactly the sentence that must
   * appear at that moment rather than a minute later.
   */
  onSettled: (ctx: { url: string; method: string }) => void = () => {};

  constructor(url: string, session: string) {
    super(url);
    this.#base = url.replace(/\/$/, "");
    this.#session = session;
  }

  setSession(token: string) {
    this.#session = token;
  }

  /** What the last listing of `id` did not return; undefined if never listed. */
  listing(id: string): ListingMeta | undefined {
    return this.#listings.get(id || "/");
  }

  /**
   * Hands over the store's event bus, so a refused mutation can put the screen
   * back (see `getHandlers`).
   *
   * A method rather than a constructor argument because the bus does not exist
   * until the component initialises: the provider is built at session time and
   * `init(api)` is called by the component afterwards. Until this is called
   * the repair is a no-op and the banner is all there is, which is the same
   * behaviour as before it existed -- not a silent regression.
   */
  attach(api: StoreBus) {
    this.#api = api;
  }

  /**
   * EVERY MUTATING ACTION, WRAPPED SO A REFUSAL PUTS THE SCREEN BACK.
   *
   * `Rest`'s constructor calls `getHandlers()` and registers what it returns,
   * one handler per action, so this is the one place where an action's name,
   * its event and the outcome of its request are all in scope. That is why the
   * fix is here and not in `send`, which sees a URL and a method and cannot
   * know which directory a failed `PUT /files` was about.
   *
   * The upstream handler is CALLED, not copied: this adds a `.catch` to
   * whatever it returns and rethrows, so an upgrade that changes what
   * `rename-file` sends changes it here too. A copy of upstream's promise
   * chain -- the other option this could have been -- would have had to be
   * re-read against every component upgrade, and the failure mode of getting
   * it wrong is silence.
   *
   * NOTE ON ORDER: this runs during `super()`, before this class's own field
   * initialisers, so nothing in this method's BODY may touch a private field
   * (`this.#api` here would throw). The closures it returns run long
   * afterwards, which is where the field access lives.
   */
  getHandlers() {
    const base = super.getHandlers() as Record<string, HandlerSpec | undefined>;
    const out: Record<string, HandlerSpec> = {};
    for (const action of Object.keys(base)) {
      const spec = base[action];
      if (!spec) continue;
      out[action] = {
        ...spec,
        handler: (data: Record<string, unknown>, name: string, ev: Record<string, unknown>) =>
          Promise.resolve(spec.handler(data, name, ev)).catch((err: unknown) => {
            // The event, not the corrected copy: the queue rewrites temporary
            // ids in `data`, and what the store knows the node by is `ev`.
            void this.#repair(action, ev ?? data);
            throw err;
          }),
      };
    }
    return out as ReturnType<RestDataProvider["getHandlers"]>;
  }

  /**
   * Re-lists the directories a failed mutation touched, and hands the answers
   * to the store as `provide-data` -- which replaces that directory's contents
   * outright (measured: the store's handler clears `data` for a node that is
   * not lazy and re-parses).
   *
   * Failures here are swallowed on purpose. The user has already been told
   * that the operation was refused; a second banner saying the repair also
   * failed would replace the actionable message with a less actionable one,
   * and the `Reload the listing` control in ui/Notices.tsx is the honest
   * fallback for a page that cannot reach the server at all.
   */
  async #repair(action: string, ev: Record<string, unknown>) {
    const api = this.#api;
    if (!api) return;
    for (const dir of affectedDirs(action, ev)) {
      try {
        // The ROOT is listed through the un-pathed form, the same way boot
        // does it: `loadFiles("/")` would send `files/%2F`, which is a route
        // that exists (webapi's {id...} sibling) but is not the one every
        // other listing of the root uses, and a repair should not be the only
        // caller of a second spelling.
        const { data, meta } = await this.loadFilesWithMeta(dir === "/" ? "" : dir);
        // ...but the STORE's id for the root is "/", not "": its own root
        // node is `{id: "/", name: "My files"}`.
        api.exec("provide-data", { id: dir, data });
        this.#listings.set(dir, meta);
      } catch {
        /* see the doc comment */
      }
    }
  }

  async send<T>(
    url: string,
    method: string,
    data?: unknown,
    customHeaders?: Record<string, string>,
  ): Promise<T> {
    const headers: Record<string, string> = { ...(customHeaders || {}) };
    if (this.#session) headers["X-Pelfs-Session"] = this.#session;
    // A string body is the provider's JSON; a FormData body is the upload,
    // whose boundary only fetch can write, so it must keep its own type.
    if (typeof data === "string") headers["Content-Type"] = "application/json";

    const target = `${this.#base}/${url}`;
    let res: Response;
    try {
      res = await fetch(target, {
        method,
        headers,
        body: data === undefined || data === null ? undefined : (data as BodyInit),
        // No credentials of any kind: this design has no cookie, and asking
        // for one would send whatever another service on 127.0.0.1 set (RFC
        // 6265bis 8.5 -- cookies have no port isolation).
        credentials: "omit",
        cache: "no-store",
        referrerPolicy: "no-referrer",
      });
    } catch (e) {
      const err = new Error(`${method} ${url}: the server did not answer (${String(e)})`);
      this.onError(err, { url, method });
      throw err;
    }

    if (!res.ok) {
      const err = new Error(await explain(res, method, url));
      this.onError(err, { url, method });
      throw err;
    }

    if (method === "GET" && (url === "files" || url.startsWith("files/"))) {
      this.#recordListing(url, res);
    }

    this.onSettled({ url, method });

    // 204 and an empty 200 are both legal answers to a delete.
    const text = await res.text();
    if (!text) return undefined as T;
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      const err = new Error(`${method} ${url}: the answer was not JSON`);
      this.onError(err, { url, method });
      throw err;
    }
    // Per-id results (docs/design-webui.md, "semantic restraint"): a batch
    // move is N sequential renames and the server reports each one. A partial
    // failure inside a 200 is still a failure and must not be silent.
    const partial = partialFailure(parsed);
    if (partial) {
      const err = new Error(`${method} ${url}: ${partial}`);
      this.onError(err, { url, method });
      // NOT thrown: the ids that did move, moved, and the store's view of
      // them is right. The banner is the honest part.
    }
    return parsed as T;
  }

  #recordListing(url: string, res: Response) {
    const id = url === "files" ? "/" : decodeURIComponent(url.slice("files/".length));
    const num = (h: string) => {
      const v = res.headers.get(h);
      if (v === null) return undefined;
      const n = Number(v);
      return Number.isFinite(n) ? n : undefined;
    };
    // `returned` is filled in by loadFilesWithMeta, which is the only caller
    // that sees the parsed array. Recording the headers here keeps the two
    // facts in one place.
    const meta: ListingMeta = {
      returned: this.#listings.get(id)?.returned ?? 0,
      total: num("X-Pelfs-Listing-Total"),
      cap: num("X-Pelfs-Listing-Cap"),
    };
    this.#listings.set(id, meta);
  }

  /** `loadFiles`, plus what the response headers said about the cap. */
  async loadFilesWithMeta(id: string): Promise<{ data: Entry[]; meta: ListingMeta }> {
    const data = (await this.loadFiles(id)) as unknown as Entry[];
    const key = id || "/";
    const meta: ListingMeta = { ...(this.#listings.get(key) ?? {}), returned: data.length };
    this.#listings.set(key, meta);
    return { data, meta };
  }
}

/**
 * The two calls this module makes on the store's event bus. A local shape
 * rather than the component's `IApi`, so that api/provider.ts does not depend
 * on @svar-ui/react-filemanager -- the provider is the layer that has to stay
 * testable without React.
 */
export type StoreBus = {
  on: (action: string, cb: (ev: { id: string }) => void) => void;
  exec: (action: string, ev: unknown) => void;
};

/** One entry of what `Rest`'s constructor registers, per action. */
type HandlerSpec = {
  handler: (data: Record<string, unknown>, action: string, ev: Record<string, unknown>) => unknown;
  ignoreID?: boolean;
  debounce?: number;
};

/**
 * The directories a failed mutation may have changed the LOOK of, which is
 * the set that has to be re-listed to put the screen back.
 *
 * Derived from the store's own event shapes (@svar-ui/filemanager-store's
 * handlers, and the recording in internal/webui/testdata/svar-contract):
 * `create-file` carries a `parent`, `rename-file` an `id`, and the three batch
 * actions carry `ids` plus, for move and copy, a `target`. A move is listed on
 * BOTH sides because a half-applied one is exactly the case an inverse
 * operation would get wrong.
 *
 * An unknown action returns nothing rather than guessing: a future action this
 * function has not been taught about must produce no repair, not a repair of
 * the wrong directory.
 */
function affectedDirs(action: string, ev: Record<string, unknown>): string[] {
  const dirs = new Set<string>();
  const ids = Array.isArray(ev.ids) ? (ev.ids as unknown[]).filter(isId) : [];
  switch (action) {
    case "create-file":
      dirs.add(dirOf(ev.parent));
      break;
    case "rename-file":
      dirs.add(parentOf(ev.id));
      break;
    case "move-files":
    case "copy-files":
      dirs.add(dirOf(ev.target));
      for (const id of ids) dirs.add(parentOf(id));
      break;
    case "delete-files":
      for (const id of ids) dirs.add(parentOf(id));
      break;
  }
  return [...dirs];
}

function isId(v: unknown): v is string {
  return typeof v === "string" && v !== "";
}

/** A directory id as the store spells it: "/" for the root, else "/a/b". */
function dirOf(v: unknown): string {
  return isId(v) ? v : "/";
}

/** The directory an entry lives in. "/README.txt" -> "/"; "/a/b" -> "/a". */
function parentOf(v: unknown): string {
  if (!isId(v)) return "/";
  const cut = v.lastIndexOf("/");
  return cut <= 0 ? "/" : v.slice(0, cut);
}

/**
 * Turns a refusal into a sentence a physicist can act on. The server's own
 * body is preferred when it has one; the status-only cases are the guard's
 * (internal/httpguard) and each of them has exactly one cause worth naming.
 */
async function explain(res: Response, method: string, url: string): Promise<string> {
  let detail = "";
  try {
    const text = (await res.text()).trim();
    if (text) {
      try {
        const doc = JSON.parse(text) as { error?: string };
        detail = doc.error ?? text;
      } catch {
        detail = text;
      }
    }
  } catch {
    /* a body we cannot read is not worth a second error */
  }
  const known: Record<number, string> = {
    401: "this tab's session is not valid any more -- reload from a fresh `pelfs browse` link",
    403: "the server refused the request's origin (this is the CSRF guard, not a permission error)",
    404: "that path is not there any more",
    409: "another operation holds the volume; try again when it finishes",
    415: "the server rejected the request's content type",
    421: "the server does not answer to that hostname",
    503: "the volume is still opening",
  };
  const head = `${method} ${url} failed (${res.status})`;
  const why = detail || known[res.status] || "";
  return why ? `${head}: ${why}` : head;
}

/** Finds `{result: [{id, error}, ...]}` entries that carry an error. */
function partialFailure(parsed: unknown): string | null {
  if (typeof parsed !== "object" || parsed === null) return null;
  const result = (parsed as { result?: unknown }).result;
  if (!Array.isArray(result)) return null;
  const bad = result
    .filter((r): r is { id?: string; error: string } => !!r && typeof r === "object" && "error" in r)
    .map((r) => `${r.id ?? "?"}: ${r.error}`);
  return bad.length ? `${bad.length} of ${result.length} did not happen -- ${bad.join("; ")}` : null;
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
 *
 * `onListing` is how the cap reaches the UI: the listing that was just
 * loaded is the one the user is looking at.
 */
export function wireLazyLoading(
  api: StoreBus,
  provider: PelfsDataProvider,
  onListing?: (id: string, meta: ListingMeta) => void,
) {
  // The same bus, for the other direction: a refused mutation is repaired by
  // re-listing and pushing `provide-data` back through it. One call rather
  // than a second wiring function, because there is exactly one bus and both
  // uses want it at the same moment.
  provider.attach(api);
  const inFlight = new Set<string>();
  api.on("request-data", (ev) => {
    if (inFlight.has(ev.id)) return;
    inFlight.add(ev.id);
    provider
      .loadFilesWithMeta(ev.id)
      .then(({ data, meta }) => {
        api.exec("provide-data", { id: ev.id, data });
        onListing?.(ev.id, meta);
      })
      .catch(() => {
        // The provider has already reported it; nothing to add, and an
        // unhandled rejection here would be noise in the console for a
        // failure that is already on the screen.
      })
      .finally(() => inFlight.delete(ev.id));
  });
}
