import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import { Filemanager, Willow, WillowDark } from "@svar-ui/react-filemanager";
import type { IApi } from "@svar-ui/react-filemanager";
import { Brand } from "./brand/Brand";
import { PelfsDataProvider, wireLazyLoading, type StoreBus } from "./api/provider";
import { establishSession } from "./api/session";
import { subscribeState, type StreamStatus } from "./api/events";
import { downloadFile } from "./api/control";
import type { BrowseState, DriveInfo, Entry, ListingMeta } from "./api/types";
import { Durability } from "./ui/Durability";
import { CapCaveat, ErrorBanner, SearchCaveat, UploadNotice } from "./ui/Notices";
import { publishState } from "./durability";
import { CONNECT } from "./routes";

/**
 * The pelfs file manager.
 *
 * WHAT THIS PAGE IS FOR, in the order the design puts it: first, an honest
 * answer to "is my data in the federation yet"; second, files. The order
 * matters, because a file manager that implies "uploaded" means "in the
 * federation" is the single worst outcome for this audience -- the user's next
 * action after a finished upload is to close the laptop and tell a
 * collaborator the data is there. So the durability panel is above the grid,
 * not behind a tab, and it speaks the same words as M1's connection page (see
 * ui/durability.ts).
 *
 * WHAT IT DOES NOT DO, and why each is a decision rather than an omission:
 *
 *   - It does not preview files. Rendering a file from the volume in this
 *     origin is the stored-XSS problem (docs/design-webui.md A5), and the
 *     download route answers with `attachment` and `application/octet-stream`
 *     unconditionally for the same reason. `previews` is therefore left off
 *     and `icons="simple"` replaces the component's default icon callback,
 *     which builds cdn.svar.dev URLs per file extension.
 *
 *   - It does not resume an upload. The component posts one whole multipart
 *     request through fetch [U0 recording, step "upload"], so a dropped
 *     connection at 90% of a 68 MB SIF starts over and there is no progress
 *     bar to watch on the way. Resumable upload is `tus` + `uppy` at
 *     `api.intercept("upload-file")`, deferred by decision (U15). The page
 *     says so rather than letting somebody find out at 80%.
 *
 *   - It does not search the volume. See ui/Notices.tsx.
 */

const API_BASE = "/api/v1";

/**
 * WHICH OF THE COMPONENT'S TWO THEMES TO RENDER, and why this is a hook rather
 * than a stylesheet.
 *
 * The app's own chrome has followed `prefers-color-scheme` since it was
 * written; the component has a light theme and a dark theme and no automatic
 * relationship to either. That combination shipped, and in dark mode it was
 * unusable rather than merely inconsistent: the chrome went dark, the file
 * manager stayed on Willow's white cards, and the file names inherited the
 * app's near-white body colour -- white text on white cards.
 *
 * So the media query is READ here and the matching theme is rendered. Both
 * theme components appear below as literal JSX tags, each with fonts={false}:
 * vite.config.ts's offlineAssets plugin scans the SOURCE for a theme element
 * that leaves fonts on (which injects a stylesheet link to cdn.svar.dev), and
 * it can only see a literal tag -- an aliased component, `const Theme = dark ?
 * WillowDark : Willow`, would have silently taken the page out from under that
 * guard. (The plugin reads comments too, so this one names no tags.)
 */
function usePrefersDark(): boolean {
  const query = "(prefers-color-scheme: dark)";
  const [dark, setDark] = useState(
    () => typeof matchMedia === "function" && matchMedia(query).matches,
  );
  useEffect(() => {
    if (typeof matchMedia !== "function") return;
    const mq = matchMedia(query);
    const onChange = () => setDark(mq.matches);
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, []);
  return dark;
}

/**
 * THE VOLUME OPENS AFTER THE LISTENER, which is why `connecting` is a state of
 * this app and not merely a spinner.
 *
 * cmd/pelfs/browse.go binds, serves and prints the URL FIRST, and opens the
 * volume afterwards — deliberately, because the first federation device-flow
 * prompt has to have a page to appear on. So the tab is loaded, and often
 * loaded for several seconds, before `GET /api/v1/files` can answer anything
 * but 503.
 *
 * The first version of this app did the boot listing once and treated a
 * failure as terminal, which was survivable while the app was only ever served
 * against a mock whose volume was already open. Mounted on the real route
 * table it meant that opening the printed URL promptly — the normal case, since
 * `--open` does it for you — showed "the JSON data plane did not answer" and
 * stayed there until a manual reload. That is the second thing that only broke
 * once the app was reachable, and it is the worse of the two.
 *
 * So readiness is not guessed and not polled: the `/events` stream is
 * subscribed as soon as there is a session, and the data plane is asked for
 * exactly once, when a frame says `phase: "ready"`. The same stream is what the
 * durability panel reads, so there is one source of truth about whether the
 * volume is open and no timer anywhere.
 */
type Boot =
  | { kind: "loading" }
  | { kind: "no-session"; why: string }
  | { kind: "connecting"; token: string }
  | { kind: "no-api"; token: string; why: string }
  | { kind: "ready"; token: string; info: DriveInfo; root: Entry[]; meta: ListingMeta };

export function App() {
  const [boot, setBoot] = useState<Boot>({ kind: "loading" });
  const [live, setLive] = useState<BrowseState | null>(null);
  const [stream, setStream] = useState<StreamStatus>("connecting");
  const [error, setError] = useState("");
  const [upload, setUpload] = useState("");
  const [search, setSearch] = useState("");
  const [path, setPath] = useState("/");
  const [listings, setListings] = useState<Record<string, ListingMeta>>({});
  const dark = usePrefersDark();

  const providerRef = useRef<PelfsDataProvider | null>(null);
  // The session token, for the two routes that are not the provider's
  // (publish and the download ticket). A ref rather than a closure over
  // state, because `init` runs once and must not be re-created: the component
  // re-initialises its store when its props change identity.
  const tokenRef = useRef("");

  // Step one, and the only step that can fail for a reason the user caused:
  // the session. Everything after it needs a credential.
  useEffect(() => {
    let alive = true;
    (async () => {
      const session = await establishSession(API_BASE);
      if (!alive) return;
      if (!session.ok) {
        setBoot({ kind: "no-session", why: session.reason });
        return;
      }
      const provider = new PelfsDataProvider(API_BASE, session.token);
      providerRef.current = provider;
      tokenRef.current = session.token;
      provider.onError = (err) => setError(err.message);
      provider.onSettled = ({ url, method }) => {
        if (method === "POST" && url.startsWith("upload?")) {
          setUpload(
            "Upload finished. The bytes are on THIS MACHINE, in the local overlay — durable " +
              "against a crash, invisible to the federation until a publish. The line above says " +
              "when that happens; “Publish now” makes it happen immediately.",
          );
        }
      };
      setBoot({ kind: "connecting", token: session.token });
    })();
    return () => {
      alive = false;
    };
  }, []);

  // The session token, once there is one. A string rather than the Boot value
  // so the two effects below do not re-run when boot goes connecting -> ready:
  // re-subscribing the stream on that transition would drop and reopen it for
  // no reason, and `streams` is what the idle seal counts.
  const token = boot.kind === "loading" || boot.kind === "no-session" ? "" : boot.token;

  // The durability stream, from the moment there is a credential — not from
  // the moment the volume is open. It is both the panel's source and the
  // readiness signal the effect below waits on; see Boot.
  //
  // Snapshots, so this replaces state rather than patching it; see
  // api/events.ts.
  useEffect(() => {
    if (!token) return;
    return subscribeState(token, setLive, setStream);
  }, [token]);

  // Step two: the data plane, asked once, when the volume is open.
  //
  // `bootedRef` and not a dependency on `boot.kind`, because a frame arrives
  // roughly twice a second and this must not fire twice: two boot listings
  // would be two full root listings on a large volume, and the second one's
  // `data` would replace the store the user had already started using.
  const bootedRef = useRef(false);
  useEffect(() => {
    if (boot.kind !== "connecting" || !live || bootedRef.current) return;
    if (live.phase === "connecting") return;
    if (live.phase === "failed") {
      // The volume did not open. The server already knows why and says so on
      // the stream, and asking the data plane would only turn a real reason
      // into "503, the volume is still opening" — which is false and sends the
      // user off to wait for something that is not coming.
      bootedRef.current = true;
      setBoot({
        kind: "no-api",
        token: boot.token,
        why: live.error || "the volume could not be opened",
      });
      return;
    }
    const provider = providerRef.current;
    if (!provider) return;
    bootedRef.current = true;
    const tok = boot.token;
    let alive = true;
    (async () => {
      try {
        const info = (await provider.loadInfo("")) as unknown as DriveInfo;
        const { data, meta } = await provider.loadFilesWithMeta("");
        if (!alive) return;
        if (!info || !Array.isArray(data)) throw new Error("the JSON API answered nothing usable");
        setBoot({ kind: "ready", token: tok, info, root: data, meta });
        setListings({ "/": meta });
      } catch (e) {
        // A failure HERE is terminal and worth saying so: the volume reported
        // itself open and the data plane still would not answer, which is not
        // something waiting fixes.
        if (alive) setBoot({ kind: "no-api", token: tok, why: String(e) });
      }
    })();
    return () => {
      alive = false;
    };
  }, [boot, live]);

  // THE IDLE-SEAL HINT (U10), which this app owed the session the moment it
  // became the page at `/`.
  //
  // The TRIGGER is not this: it is the SSE stream above closing, which the
  // server sees whether or not a beacon arrives (cmd/pelfs/idleseal.go is
  // explicit that a best-effort beacon must never be a durability mechanism).
  // What the beacon buys is the difference between sealing five seconds after
  // the tab closes and thirty, and before the wiring pass it was sent only by
  // the page that is now at /connect -- so a user of the file manager, the
  // one surface that can actually stage files, was the one user who did not
  // get the shorter window. Measured as the whole regression: the seal still
  // happened, 25 seconds later than it needed to.
  //
  // sendBeacon can set no request header, so the session token travels in the
  // body as a JSON Blob -- which is also what makes the request's
  // Content-Type application/json, and so acceptable to SurfaceExchange.
  useEffect(() => {
    if (!token) return;
    const beacon = () => {
      if (!navigator.sendBeacon) return;
      try {
        navigator.sendBeacon(
          `${API_BASE}/beacon`,
          new Blob([JSON.stringify({ session: token })], { type: "application/json" }),
        );
      } catch {
        /* best-effort, by definition */
      }
    };
    // pagehide rather than unload: unload is not fired at all on mobile and
    // is deprecated for exactly this use.
    const onHidden = () => {
      if (document.visibilityState === "hidden") beacon();
    };
    window.addEventListener("pagehide", beacon);
    document.addEventListener("visibilitychange", onHidden);
    return () => {
      window.removeEventListener("pagehide", beacon);
      document.removeEventListener("visibilitychange", onHidden);
    };
  }, [token]);

  const state = live;

  // The browser's own "leave site?" prompt, when this tab has staged work.
  //
  // It is a HINT and never the mechanism -- the session seals at exit either
  // way, and browsers suppress this dialog entirely without a prior
  // interaction -- but it is the last chance to catch the exact gesture this
  // whole design is about: a finished upload and a closed laptop. The wording
  // is not ours to choose; the trigger is.
  const staged = state?.staged_files ?? 0;
  useEffect(() => {
    if (staged <= 0) return;
    const warn = (e: BeforeUnloadEvent) => e.preventDefault();
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [staged]);

  const publishing = publishState(state) === "running";
  const publishingRef = useRef(publishing);
  publishingRef.current = publishing;

  // `drive` MUST be referentially stable: the component re-initialises its
  // WHOLE STORE whenever this prop's identity changes (Filemanager.jsx's
  // useEffect deps include `drive`), so a fresh object on every SSE frame
  // would throw away the directory the user had opened, twice a second.
  //
  // The capacity numbers therefore come from the boot-time `GET /api/v1/info`
  // and not from the stream: browseState carries no `used`/`total` (the
  // stream's frames are cmd/pelfs/browse.go's browseState verbatim), and a
  // volume's capacity is not a number that moves while somebody watches.
  const boots = boot.kind === "ready" ? boot.info : null;
  const drive = useMemo(
    () => ({ used: boots?.used ?? 0, total: boots?.total ?? 0 }),
    [boots?.used, boots?.total],
  );

  const init = useCallback(
    (api: IApi) => {
      const provider = providerRef.current;
      if (!provider) return;
      // Both directions of the store's bus: lazy directory loading out, and
      // the re-listing that repairs a refused mutation back in.
      wireLazyLoading(api as unknown as StoreBus, provider, (id, meta) =>
        setListings((prev) => ({ ...prev, [id || "/"]: meta })),
      );
      api.setNext(provider as unknown as Parameters<IApi["setNext"]>[0]);

      // Which directory the user is looking at, so the cap notice is about
      // THIS folder and not the one they opened first.
      api.on("set-path", (ev: { id: string }) => setPath(ev.id));
      api.on("filter-files", (ev: { text: string }) => setSearch(ev.text || ""));

      // The download. `download-file` has no handler in the store at all, so
      // nothing happens unless this is here -- and what happens has to be the
      // ticket flow, because an <a href> cannot carry the session header (see
      // api/control.ts).
      api.on("download-file", (ev: { id: string }) => {
        setError("");
        downloadFile(tokenRef.current, ev.id).catch((e: unknown) =>
          setError(`download refused: ${String(e)}`),
        );
      });

      // A seal freezes the overlay, so a write during a publish blocks. The
      // design's instruction is to disable the write and say so rather than
      // let a drop fail with an opaque error; `intercept` returning false is
      // how the store's own action is cancelled before it is applied.
      for (const action of ["create-file", "rename-file", "move-files", "copy-files", "delete-files"]) {
        api.intercept(action, () => {
          if (!publishingRef.current) return;
          setError(
            "publishing — the seal holds the overlay, so writes wait. Nothing was changed; " +
              "try again when the publish finishes (a moment, or minutes for a large one).",
          );
          return false;
        });
      }
    },
    [],
  );

  // ---- what renders, and why the chrome is not gated on the file manager --
  //
  // The two states before `ready` used to replace the WHOLE page with a
  // sentence. That was wrong the moment this became the page at `/`: the
  // durability panel is this design's reason for existing, the `/events`
  // stream that feeds it is live as soon as there is a session, and a user
  // whose volume is still opening — or whose data plane just failed — is
  // exactly the user who needs to be told what is and is not published. M1's
  // connection page always showed the panel; so does this.
  //
  // So only two states have no chrome at all, and neither of them has a
  // credential to read anything with.
  if (boot.kind === "loading") {
    return (
      <Shell>
        <p data-testid="pelfs-status">connecting to pelfs…</p>
      </Shell>
    );
  }
  if (boot.kind === "no-session") {
    return (
      <Shell>
        <p className="pelfs-note pelfs-note--bad" data-testid="session-error">
          {boot.why}
        </p>
      </Shell>
    );
  }

  const meta = listings[path] ?? null;
  const ready = boot.kind === "ready" ? boot : null;
  const mode = state?.mode ?? ready?.info.mode ?? "";

  // The grid, built once and rendered inside whichever of the component's two
  // themes matches the platform. See usePrefersDark for why both theme tags
  // are literal.
  const grid = ready ? (
    <Filemanager
      icons="simple"
      // The cast is the provider's parseDates: the wire carries `date` as an
      // ISO string and RestDataProvider.loadFiles rewrites each one into a
      // Date in place before this array is ever rendered, so the runtime value
      // matches IEntity even though the wire type does not.
      data={ready.root as unknown as Parameters<typeof Filemanager>[0]["data"]}
      drive={drive}
      // A read-only session cannot lose anything, which is `pelfs browse`'s
      // default. Telling the component makes the menus match the truth
      // instead of offering a rename that will 403.
      readonly={mode === "read-only"}
      init={init}
    />
  ) : null;

  return (
    <div className="pelfs-app" data-testid="pelfs-shell" data-phase={state?.phase ?? "unknown"}>
      {/* THE APP BAR: who this is, what volume it is serving, the session's
          facts, and the one link off this page. The link is here and not in
          the status panel because it is navigation and not a durability
          action -- it used to sit on the same line as "Publish now", which
          made an unrelated page look like a step in publishing. */}
      <header className="pelfs-appbar">
        <div className="pelfs-appbar__id">
          <Brand subtitle={state?.volume ?? ""} />
        </div>
        <div className="pelfs-appbar__facts">
          <span className="pelfs-fact" data-testid="branch-generation">
            branch <b>{state?.branch ?? "—"}</b>, generation{" "}
            <b>{state && state.phase === "ready" ? state.generation : "—"}</b>
          </span>
          <span className="pelfs-fact" data-testid="lease" data-lease-state={state?.lease ?? "—"}>
            lease <b>{state?.lease ?? "—"}</b>
          </span>
          <span className="pelfs-chip" data-testid="mode" data-mode={mode}>
            {mode || "—"}
          </span>
          <a className="pelfs-navlink" href={CONNECT} data-testid="connect-link">
            Connect a program →
          </a>
        </div>
      </header>

      <div className="pelfs-workspace">
        <Durability state={state} token={token} onNotice={setUpload} />

        {state?.test_hooks ? (
          <p className="pelfs-note pelfs-note--warn" data-testid="test-hooks-banner">
            <strong>--test-hooks is on.</strong> This session accepts a route that overrides what
            this page reports, so what you see may not be what the volume holds. It exists for the
            browser-driver test suite. Never use it on real data.
          </p>
        ) : null}

        {/* A FEDERATION LOGIN WAITING ON THE USER (U13), which is the one
            state where this page cannot do its job and the reason is not on
            it. Without this line a user whose institution is asking for a
            device login sits at `/` watching a listing that never arrives.

            It is a POINTER, not a second copy of the card. The card owns a
            URL, a code the user must type, an expiry and a dismiss control; a
            second implementation of it here would be a second place for the
            code to be rendered wrongly, and the dismiss is one-way (nothing
            tells us the flow finished), so two dismiss buttons for one prompt
            is worse than one. /connect renders the cards; this says they are
            there. */}
        {state?.prompts?.length ? (
          <p className="pelfs-note pelfs-note--warn" data-testid="sso-waiting">
            <strong>
              {state.prompts.length === 1
                ? "Your institution is asking you to log in."
                : `${state.prompts.length} federation logins are waiting for you.`}
            </strong>{" "}
            Until that is done this page cannot read the volume.{" "}
            <a className="pelfs-link" href={CONNECT} data-testid="sso-waiting-link">
              Open the login prompt
            </a>{" "}
            — it carries the address and the code. The same prompt is in the terminal running{" "}
            <code>pelfs browse</code>.
          </p>
        ) : null}

        <ErrorBanner text={error} onReload={() => location.reload()} />
        <UploadNotice text={upload} />

        {boot.kind === "connecting" ? (
          // The same sentence M1's page carries, for the same reason: this is
          // where an institution may ask for a device login, and a user
          // watching an empty page needs to know that the wait is expected
          // and where the prompt will appear.
          <p className="pelfs-note" data-testid="phase-banner">
            connecting to the federation — this is where your institution may ask you to approve
            access. The terminal shows the same prompt, and the panel above is live already.
          </p>
        ) : null}

        {boot.kind === "no-api" ? (
          <p className="pelfs-note pelfs-note--bad" data-testid="pelfs-status">
            The volume is open but the JSON data plane did not answer: <code>{boot.why}</code>
            <span className="pelfs-note__more">
              The durability panel above is still live, so what it says about publishing is true.{" "}
              <code>pelfs browse</code> is still running in your terminal, and Ctrl-C there stops it
              (sealing, if you started it with <code>--rw</code>). To move files meanwhile, use{" "}
              <a className="pelfs-link" href={CONNECT}>
                a WebDAV client
              </a>{" "}
              or <code>pelfs mount</code>.
            </span>
          </p>
        ) : null}

        {ready ? (
          <section className="pelfs-panel pelfs-panel--files" data-testid="pelfs-files-panel">
            {/* The pane's own accessory row, directly above the component's
                toolbar -- whose search box is at its left, which is the
                reason the search caveat is here and not in a footer. */}
            <div className="pelfs-panel__bar">
              {/* The folder this pane is showing, as a PATH. The component's
                  breadcrumb above shows the same place in names; a path is
                  what a person retypes into `pelfs mount` or a WebDAV
                  client, which is the thing this page keeps recommending. */}
              <span className="pelfs-path" data-testid="pelfs-path">
                {path || "/"}
              </span>
              <span className="pelfs-panel__bar-spacer" />
              <SearchCaveat meta={meta} search={search} />
              <CapCaveat meta={meta} />
            </div>
            <div className="pelfs-panel__body pelfs-fm">
              {/* fonts={false}: the theme otherwise injects
                  <link rel=stylesheet href=https://cdn.svar.dev/fonts/wxi/wx-icons.css>
                  and a preconnect to the same host. icons="simple": the
                  default icon callback builds https://cdn.svar.dev/icons/...
                  URLs per file extension. Both were caught on the wire by the
                  U0 probe; with both off the page makes ZERO requests off
                  loopback, which vite.config.ts's no-remote-assets plugin and
                  a Playwright assertion then keep true. */}
              {dark ? (
                <WillowDark fonts={false}>{grid}</WillowDark>
              ) : (
                <Willow fonts={false}>{grid}</Willow>
              )}
            </div>
          </section>
        ) : null}
      </div>

      <div className="pelfs-statusline">
        <span className="pelfs-stream" data-testid="stream-status" data-stream={stream}>
          {stream === "open"
            ? "live"
            : stream === "reconnecting"
              ? "reconnecting…"
              : stream === "closed"
                ? "pelfs browse has exited — this page is now a snapshot"
                : "connecting…"}
        </span>
        <span>
          whole-file upload only: a dropped connection restarts it, and there is no progress bar.
          For a large set of files use <code>pelfs mount</code> or a WebDAV client.
        </span>
        <span className="pelfs-statusline__spacer" />
        {/* The MIT notices for the bundled packages. The distribution is a Go
            binary with the bundle inside it, so a person who has nothing but
            the binary has to be able to reach them from what it serves. This
            anchor is the whole of what the deleted footer was carrying that
            was an obligation rather than a statement. */}
        <a className="pelfs-link" href="./third_party.txt" data-testid="pelfs-notices-link">
          third-party notices
        </a>
      </div>
    </div>
  );
}

/**
 * The app bar alone, for the two states with no credential and so nothing to
 * render: the first paint, and a session that could not be established.
 */
function Shell({ children }: { children: ReactNode }) {
  return (
    <div className="pelfs-app" data-testid="pelfs-shell">
      <header className="pelfs-appbar">
        <div className="pelfs-appbar__id">
          <Brand />
        </div>
      </header>
      <div className="pelfs-workspace pelfs-workspace--prose">{children}</div>
      {/* The notices link is here as well as in the full status line, because
          the MIT obligation does not depend on the app being able to start:
          a page that failed to get a session still ships the bundle whose
          licences these are. */}
      <div className="pelfs-statusline">
        <span className="pelfs-statusline__spacer" />
        <a className="pelfs-link" href="./third_party.txt" data-testid="pelfs-notices-link">
          third-party notices
        </a>
      </div>
    </div>
  );
}
