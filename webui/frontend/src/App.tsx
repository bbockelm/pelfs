import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import { Filemanager, Willow } from "@svar-ui/react-filemanager";
import type { IApi } from "@svar-ui/react-filemanager";
import { Brand, BrandFooter } from "./brand/Brand";
import { PelfsDataProvider, wireLazyLoading } from "./api/provider";
import { establishSession } from "./api/session";
import { subscribeState, type StreamStatus } from "./api/events";
import { downloadFile } from "./api/control";
import type { BrowseState, DriveInfo, Entry, ListingMeta } from "./api/types";
import { Durability } from "./ui/Durability";
import { ErrorBanner, ListingNotices, UploadNotice } from "./ui/Notices";
import { publishState } from "./durability";

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

type Boot =
  | { kind: "loading" }
  | { kind: "no-session"; why: string }
  | { kind: "no-api"; why: string }
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

  const providerRef = useRef<PelfsDataProvider | null>(null);
  // The session token, for the two routes that are not the provider's
  // (publish and the download ticket). A ref rather than a closure over
  // state, because `init` runs once and must not be re-created: the component
  // re-initialises its store when its props change identity.
  const tokenRef = useRef("");

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
      try {
        const info = (await provider.loadInfo("")) as unknown as DriveInfo;
        const { data, meta } = await provider.loadFilesWithMeta("");
        if (!alive) return;
        if (!info || !Array.isArray(data)) throw new Error("the JSON API answered nothing usable");
        setBoot({ kind: "ready", token: session.token, info, root: data, meta });
        setListings({ "/": meta });
        setLive(info);
      } catch (e) {
        if (alive) setBoot({ kind: "no-api", why: String(e) });
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  // The durability stream. Snapshots, so this replaces state rather than
  // patching it; see api/events.ts.
  useEffect(() => {
    if (boot.kind !== "ready") return;
    return subscribeState(boot.token, setLive, setStream);
  }, [boot]);

  const state = live;
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
      wireLazyLoading(
        api as unknown as Parameters<typeof wireLazyLoading>[0],
        provider,
        (id, meta) => setListings((prev) => ({ ...prev, [id || "/"]: meta })),
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
        <div className="pelfs-banner pelfs-banner--bad" data-testid="session-error">
          {boot.why}
        </div>
      </Shell>
    );
  }
  if (boot.kind === "no-api") {
    return (
      <Shell>
        <div className="pelfs-banner pelfs-banner--bad" data-testid="pelfs-status">
          The UI shell is served from the binary, but the JSON data plane did not answer:{" "}
          <code>{boot.why}</code>
          <div className="pelfs-muted">
            The file manager needs <code>/api/v1</code> (work item U11). <code>pelfs browse</code>{" "}
            is still running in your terminal, and Ctrl-C there stops it.
          </div>
        </div>
      </Shell>
    );
  }

  const meta = listings[path] ?? null;

  return (
    <div className="pelfs-app" data-testid="pelfs-shell" data-phase={state?.phase ?? "unknown"}>
      <header className="pelfs-header">
        <Brand subtitle={state?.volume ?? boot.info.volume} />
        <div className="pelfs-header__right">
          <span className="pelfs-sub" data-testid="branch-generation">
            branch {state?.branch ?? "—"}, generation{" "}
            {state && state.phase === "ready" ? state.generation : "—"}
          </span>
          <span className="pelfs-sub" data-testid="lease" data-lease-state={state?.lease ?? "—"}>
            lease: {state?.lease ?? "—"}
          </span>
          <span className="pelfs-badge" data-testid="mode">
            {state?.mode ?? boot.info.mode}
          </span>
        </div>
      </header>

      {state?.test_hooks ? (
        <div className="pelfs-banner pelfs-banner--warn" data-testid="test-hooks-banner">
          <strong>--test-hooks is on.</strong> This session accepts a route that overrides what this
          page reports, so what you see may not be what the volume holds. It exists for the
          browser-driver test suite. Never use it on real data.
        </div>
      ) : null}

      <Durability state={state} token={boot.token} onNotice={setUpload} />

      <ErrorBanner text={error} onReload={() => location.reload()} />
      <UploadNotice text={upload} />
      <ListingNotices meta={meta} search={search} />

      <main className="pelfs-main">
        {/* fonts={false}: the theme otherwise injects
            <link rel=stylesheet href=https://cdn.svar.dev/fonts/wxi/wx-icons.css>
            and a preconnect to the same host. icons="simple": the default icon
            callback builds https://cdn.svar.dev/icons/... URLs per file
            extension. Both were caught on the wire by the U0 probe; with both
            off the page makes ZERO requests off loopback, which vite.config.ts's
            no-remote-assets plugin and a Playwright assertion then keep true. */}
        <Willow fonts={false}>
          <Filemanager
            icons="simple"
            // The cast is the provider's parseDates: the wire carries `date`
            // as an ISO string and RestDataProvider.loadFiles rewrites each
            // one into a Date in place before this array is ever rendered, so
            // the runtime value matches IEntity even though the wire type
            // does not.
            data={boot.root as unknown as Parameters<typeof Filemanager>[0]["data"]}
            drive={drive}
            // A read-only session cannot lose anything, which is `pelfs
            // browse`'s default. Telling the component makes the menus match
            // the truth instead of offering a rename that will 403.
            readonly={(state?.mode ?? boot.info.mode) === "read-only"}
            init={init}
          />
        </Willow>
      </main>

      <div className="pelfs-statusline">
        <span data-testid="stream-status" data-stream={stream}>
          {stream === "open"
            ? "live"
            : stream === "reconnecting"
              ? "reconnecting…"
              : stream === "closed"
                ? "pelfs browse has exited — this page is now a snapshot"
                : "connecting…"}
        </span>
        <span className="pelfs-muted">
          whole-file upload only: a dropped connection restarts it, and there is no progress bar.
          For a large set of files use <code>pelfs mount</code> or a WebDAV client.
        </span>
      </div>

      <BrandFooter />
    </div>
  );
}

/** The header and footer, for the states that have no file manager in them. */
function Shell({ children }: { children: ReactNode }) {
  return (
    <div className="pelfs-app" data-testid="pelfs-shell">
      <header className="pelfs-header">
        <Brand />
      </header>
      <main className="pelfs-main pelfs-main--prose">{children}</main>
      <BrandFooter />
    </div>
  );
}

