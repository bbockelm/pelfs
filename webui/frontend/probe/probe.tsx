// The U0 probe harness.
//
// It renders the REAL @svar-ui/react-filemanager through the REAL pelfs
// provider (../src/api/provider.ts), and exposes the store's api on
// window.__probe so a Playwright script can drive the actions a context menu
// would drive without depending on menu markup. Everything it measures is a
// property of the component, not of this file.
//
// This is not part of the shipped bundle: it has its own entry, its own vite
// config, and its output goes to .probe-dist/, which is not committed.
import { createRoot } from "react-dom/client";
import { useEffect, useState } from "react";
import { Filemanager, Willow } from "@svar-ui/react-filemanager";
import { RestDataProvider } from "@svar-ui/filemanager-data-provider";
import { PelfsDataProvider, wireLazyLoading } from "../src/api/provider";
import "@svar-ui/react-filemanager/style.css";

type Entry = { id: string; type?: "file" | "folder"; size?: number; lazy?: boolean };

declare global {
  interface Window {
    __probe: Record<string, unknown>;
  }
}

// Two providers on purpose: `pelfs` is the subclass the app ships, `shipped`
// is the component's own RestDataProvider, so the probe can record what each
// puts on the wire and the difference is a measurement rather than a claim.
const provider = new PelfsDataProvider("/api/v1", "PROBE-SESSION-TOKEN");
const shipped = new RestDataProvider("/api/v1");
// The documented way to attach a credential, so the probe can record whether
// it reaches the wire at all.
shipped.setHeaders({ "X-Pelfs-Session": "PROBE-SESSION-TOKEN" });

function Probe({ data, drive }: { data: Entry[]; drive: unknown }) {
  return (
    <Willow fonts={false}>
      <Filemanager
        icons="simple"
        data={data}
        drive={drive as never}
        // `api` is inferred (IApi) rather than annotated: an annotation of
        // `never` here does not typecheck at all -- a `(api: never) => void`
        // cannot stand in for a `(api: IApi) => void`, because a parameter
        // position is contravariant -- and `pnpm exec tsc --noEmit`, which CI
        // runs, failed on exactly that line.
        init={(api) => {
          window.__probe = { ...window.__probe, api, provider, shipped };
          wireLazyLoading(api as unknown as Parameters<typeof wireLazyLoading>[0], provider);
          (api as unknown as { setNext: (p: unknown) => void }).setNext(provider);
        }}
      />
    </Willow>
  );
}

function Boot() {
  const [state, setState] = useState<{ data: Entry[]; drive: unknown } | null>(null);
  useEffect(() => {
    (async () => {
      const t0 = performance.now();
      const data = (await provider.loadFiles("")) as Entry[];
      const drive = await provider.loadInfo("");
      window.__probe = { ...window.__probe, loadMs: performance.now() - t0, initialCount: data.length };
      setState({ data, drive });
    })();
  }, []);
  useEffect(() => {
    if (!state) return;
    const t = performance.now();
    requestAnimationFrame(() =>
      requestAnimationFrame(() => {
        window.__probe = { ...window.__probe, renderMs: performance.now() - t, ready: true };
      }),
    );
  }, [state]);
  return state ? <Probe data={state.data} drive={state.drive} /> : null;
}

createRoot(document.getElementById("root")!).render(<Boot />);
