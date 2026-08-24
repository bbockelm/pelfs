/**
 * The JSON API's shapes, in one file, so that the wiring pass against the
 * real Go handlers (work item U11) has a single place to reconcile.
 *
 * Two of these are not guesses. `BrowseState` is `browseState` in
 * cmd/pelfs/browse.go, field for field -- M1 already serves it on
 * `GET /api/v1/info` and pushes it, complete, on every `/events` frame, and
 * this app is a second CLIENT of that contract rather than a second
 * implementation of it. `Entry` is what @svar-ui/filemanager-store's
 * `IEntity` requires, which the U0 recording pins.
 *
 * Everything marked ASSUMED is a request to U11, listed in the same words in
 * the work item's report.
 */

/** One directory entry, as the SVAR store requires it. */
export type Entry = {
  /** The FULL PATH, which is also the store's id: `/dir/file.txt`. */
  id: string;
  type?: "file" | "folder";
  size?: number;
  /**
   * MANDATORY ON EVERY FOLDER, or the store never asks for its contents:
   * `set-path` fires `request-data` only when the node it navigated into is
   * marked lazy (measured -- @svar-ui/filemanager-store's DataStore, the
   * `set-path` handler). A folder without it is an empty folder forever.
   */
  lazy?: boolean;
  /** ISO 8601. The provider parses it into a Date. */
  date?: string;
};

/** cmd/pelfs/browse.go's browseState. Not assumed: it is served today. */
export type BrowseState = {
  phase: "connecting" | "ready" | "failed";
  error?: string;
  volume: string;
  mode: "read-only" | "read-write";
  branch: string;
  generation: number;
  /**
   * held | stale | interrupted | lost -- the control socket's own
   * vocabulary -- or "none" for a read-only or --no-lease session, which is
   * NOT a fifth state of the same kind.
   */
  lease: string;
  lease_age_s?: number;
  staged_files: number;
  staged_bytes: number;
  dirty_nodes: number;
  upload_backlog: number;
  /** A floor, not a promise: write pressure can fire a checkpoint sooner. */
  next_publish_s: number;
  /**
   * The idle-seal window, in seconds, or absent when idle sealing is off for
   * this session (a read-only browse, or --no-idle-seal). It is the second
   * half of the durability sentence -- "or 30s after this tab closes" -- and
   * saying it is the promise that closing the tab publishes rather than
   * abandons.
   */
  idle_seal_s?: number;
  publish?: PublishJob;
  /**
   * Federation logins waiting on the user (U13). The CARDS live on the
   * connection page at /connect, which owns the dismiss control; the file
   * manager needs the count so it can say a login is waiting rather than
   * leaving a user on `/` wondering why nothing loads.
   */
  prompts?: SsoPrompt[];
  test_hooks: boolean;
  streams: number;
};

/** cmd/pelfs/ssoprompt.go's ssoPrompt. One device flow awaiting the user. */
export type SsoPrompt = {
  id: string;
  url: string;
  code?: string;
  age_s: number;
  expired?: boolean;
};

export type PublishJob = {
  id: string;
  state: "running" | "done" | "failed" | "idle";
  started: string;
  ended?: string;
  summary?: string;
  error?: string;
};

/**
 * `GET /api/v1/info`: M1's browseState, plus the two numbers the component's
 * own drive panel reads.
 *
 * ASSUMED: that U11 keeps serving browseState here rather than inventing a
 * second shape, and adds `used`/`total`. The design names this route as "the
 * natural home for the durability counters", and M1 already answers it with
 * exactly this document.
 */
export type DriveInfo = BrowseState & {
  /** bytes in use, for the component's drive bar. ASSUMED addition. */
  used?: number;
  /** bytes total. ASSUMED addition. */
  total?: number;
};

/**
 * What a listing did NOT return, which is the whole reason this type exists.
 *
 * The U0 measurement: the component does not virtualize -- 100,000 entries
 * produced 100,000 card elements, 1,000,067 DOM nodes and 703 MB of heap --
 * so the API caps a listing. A cap the UI does not surface is a UI that lies
 * about a directory's contents, and the component's search is client-side
 * over loaded data only, so the same cap silently truncates search results
 * too.
 *
 * ASSUMED: U11 reports the cap in RESPONSE HEADERS, because the response
 * BODY has to stay a bare JSON array (RestDataProvider.loadFiles hands it
 * straight to parseDates, which calls Array.prototype.forEach on it -- an
 * envelope object throws). Headers cost the body nothing, and this app reads
 * them inside the `send` override it already has to have:
 *
 *   X-Pelfs-Listing-Total: <the directory's TRUE entry count>
 *   X-Pelfs-Listing-Cap:   <the cap that was applied>
 *
 * Absent headers mean "not truncated", so a U11 that never caps needs no
 * change and this app then says nothing.
 */
export type ListingMeta = {
  /** How many entries the response actually carried. */
  returned: number;
  /** The directory's true entry count, if the server said. */
  total?: number;
  /** The cap the server applied, if it said. */
  cap?: number;
};

/**
 * One branch, as `GET /api/v1/branches` reports it.
 *
 * ASSUMED, and this is the whole of what the branch picker needs from the
 * sibling building the route (api/branches.ts states the contract in full):
 * a name, the generation it is on, its head, and whether it has staged work.
 * `head` is carried because the list is also the answer to "which of these is
 * the one I published from", and dropping it from the type would make that a
 * second request later.
 */
export type Branch = {
  name: string;
  /**
   * Optional, and not because the contract makes it so: the picker also has to
   * render the branch the /events snapshot names when the list has not caught
   * up with it yet, and that stand-in has a name and nothing else.
   */
  generation?: number;
  head?: string;
  /** This branch has work staged against it that a switch would strand. */
  staged?: boolean;
};

/** `GET /api/v1/branches` -> this. ASSUMED; see api/branches.ts. */
export type BranchList = {
  /** The branch this session is on. Must be one of `branches`. */
  current: string;
  branches: Branch[];
};

/** `POST /api/v1/download` -> this. Not assumed: M1 serves it. */
export type TicketResponse = { url: string; ttl?: string };

/** `POST /api/v1/session`. Not assumed: internal/browsesession serves it. */
export type SessionResponse = { session: string; header: string; scope?: string };
