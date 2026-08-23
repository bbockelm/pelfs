import type { BrowseState } from "./types";

/**
 * The durability stream.
 *
 * `/events` carries COMPLETE SNAPSHOTS, not deltas (cmd/pelfs/browse.go,
 * serveEvents), and that is the whole answer to reconnection: the browser
 * drops and re-establishes this stream on its own -- a suspended laptop, a
 * network blip -- and every frame on the new connection is the whole truth
 * again. So there is nothing to replay, no Last-Event-ID, and no way for a
 * reconnected page to show a half-updated view. This module therefore holds
 * no accumulated state of its own; the temptation to cache "the last known
 * staged count" and patch it is exactly the bug the snapshot design removes.
 *
 * The token goes in the query string because `EventSource` cannot set a
 * request header. That is acceptable here and only here: it never becomes a
 * navigation, never enters history, and the only access log is ours
 * (internal/httpguard, SurfaceStream).
 */
export type StreamStatus = "connecting" | "open" | "reconnecting" | "closed";

export function subscribeState(
  token: string,
  onState: (s: BrowseState) => void,
  onStatus: (s: StreamStatus) => void,
): () => void {
  const es = new EventSource(`/events?s=${encodeURIComponent(token)}`);
  onStatus("connecting");
  es.addEventListener("state", (e) => {
    onStatus("open");
    try {
      onState(JSON.parse((e as MessageEvent<string>).data) as BrowseState);
    } catch {
      /* a frame we cannot parse is a frame we ignore; the next one is whole */
    }
  });
  es.addEventListener("bye", () => {
    // The server says it is leaving. Everything on the screen is now a
    // snapshot of a process that has gone, and saying so beats "connection
    // lost", which reads like a network problem the user could fix.
    onStatus("closed");
    es.close();
  });
  es.onerror = () => {
    onStatus(es.readyState === EventSource.CONNECTING ? "reconnecting" : "closed");
  };
  return () => es.close();
}
