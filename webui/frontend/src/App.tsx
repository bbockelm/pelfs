import { useEffect, useState } from "react";
import { Filemanager, Willow } from "@svar-ui/react-filemanager";
import { Brand, BrandFooter } from "./brand/Brand";
import { PelfsDataProvider, wireLazyLoading } from "./api/provider";

type Entry = { id: string; type?: "file" | "folder"; size?: number; lazy?: boolean };
type Info = { used?: number; total?: number; volume?: string; mode?: string };

// The session token is header-borne (no cookie, by design). How it gets into
// the page is M1's business -- a single-use bootstrap token in the URL
// fragment, exchanged for a session token -- so this shell reads whatever has
// been left for it and does not invent an auth protocol of its own.
function sessionToken(): string {
  const frag = new URLSearchParams(location.hash.replace(/^#/, ""));
  return frag.get("s") || (window as { __PELFS_SESSION__?: string }).__PELFS_SESSION__ || "";
}

const provider = new PelfsDataProvider("/api/v1", sessionToken());

export function App() {
  const [info, setInfo] = useState<Info | null>(null);
  const [root, setRoot] = useState<Entry[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    (async () => {
      try {
        const i = (await provider.loadInfo("")) as Info;
        const files = (await provider.loadFiles("")) as Entry[];
        if (!live) return;
        if (!i || !Array.isArray(files)) throw new Error("no data plane");
        setInfo(i);
        setRoot(files);
      } catch (e) {
        if (live) setError(String(e));
      }
    })();
    return () => {
      live = false;
    };
  }, []);

  return (
    <div
      data-testid="pelfs-shell"
      style={{ display: "flex", flexDirection: "column", height: "100%" }}
    >
      <header
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "0.6rem 1rem",
          borderBottom: "1px solid var(--pelfs-rule)",
        }}
      >
        <Brand subtitle={info?.volume} />
        <span data-testid="pelfs-mode" style={{ fontSize: "0.8rem", color: "var(--pelfs-ink-muted)" }}>
          {info?.mode ?? ""}
        </span>
      </header>

      <main style={{ flex: 1, minHeight: 0 }}>
        {root && info ? (
          // fonts={false}: the theme otherwise injects
          // <link rel=stylesheet href=https://cdn.svar.dev/fonts/wxi/wx-icons.css>
          // and a preconnect to the same host. icons="simple": the default
          // icon callback builds https://cdn.svar.dev/icons/... URLs per file
          // extension. Both were caught on the wire by the U0 probe; with
          // both off the page makes ZERO requests off loopback, which is what
          // vite.config.ts's no-remote-assets plugin then keeps true.
          <Willow fonts={false}>
            <Filemanager
              icons="simple"
              data={root}
              drive={info}
              init={(api: Parameters<typeof wireLazyLoading>[0]) => {
                wireLazyLoading(api, provider);
                (api as unknown as { setNext: (p: unknown) => void }).setNext(provider);
              }}
            />
          </Willow>
        ) : (
          <div data-testid="pelfs-status" style={{ padding: "2rem", maxWidth: "44rem" }}>
            <h1 style={{ fontSize: "1.1rem", fontWeight: 600 }}>
              The UI shell is served from the binary.
            </h1>
            <p style={{ color: "var(--pelfs-ink-muted)", lineHeight: 1.5 }}>
              This is the toolchain milestone: the bundle is built by{" "}
              <code>go generate ./internal/webui</code>, committed, and embedded, so a plain{" "}
              <code>go build</code> needs no Node. The file manager needs the JSON data plane
              (work item U11) and the session credential (U1, U2), which are not built yet.
            </p>
            {error ? (
              <p style={{ color: "var(--pelfs-local-only)", fontFamily: "var(--pelfs-font-mono)" }}>
                /api/v1 did not answer: {error}
              </p>
            ) : null}
          </div>
        )}
      </main>

      <BrandFooter />
    </div>
  );
}
