import { SESSION_HEADER } from "./session";
import type { TicketResponse } from "./types";

/**
 * The two routes the file manager needs that are not part of the SVAR
 * contract: publish, and the ticketed download.
 *
 * They are plain fetch rather than provider calls because neither is a
 * filesystem operation the component knows about, and routing them through
 * the provider would mean teaching it two actions the store never emits.
 */

function apiHeaders(token: string): Record<string, string> {
  return { "Content-Type": "application/json", [SESSION_HEADER]: token };
}

export type PublishOutcome =
  | { kind: "accepted"; job: string }
  | { kind: "busy"; job?: string }
  | { kind: "refused"; why: string };

/**
 * "Publish now" is 202-and-a-job-id, never a synchronous 200.
 *
 * `genSession.checkpoint` holds the overlay's lock across the entire seal --
 * fence, freeze, walk, upload, flip -- which on a large drag is minutes, so
 * the answer here says only that the work STARTED. Progress arrives on
 * `/events`, and a second concurrent request gets 409 with the id of the job
 * that already holds the lock, so the UI can follow that one instead of
 * retrying (cmd/pelfs/browse.go, servePublish).
 */
export async function publish(token: string): Promise<PublishOutcome> {
  const res = await fetch("/api/v1/publish", {
    method: "POST",
    headers: apiHeaders(token),
    body: "{}",
    credentials: "omit",
    cache: "no-store",
    referrerPolicy: "no-referrer",
  });
  const body = (await res.json().catch(() => ({}))) as { job?: string; error?: string };
  if (res.status === 202) return { kind: "accepted", job: body.job ?? "" };
  if (res.status === 409) return { kind: "busy", job: body.job };
  return { kind: "refused", why: body.error || `the server answered ${res.status}` };
}

/**
 * Downloads one file, in the only shape that does not weaken the threat
 * model.
 *
 * An `<a href>` or a `window.location` CANNOT send a custom request header,
 * so a download authorized by the session token would have to be authorized
 * by an AMBIENT credential on a GET -- and an ambient-credential GET is
 * exactly what a cross-origin `<img>`, `<script>`, `<iframe>` or top-level
 * navigation can trigger, and what DNS rebinding turned into arbitrary RPC in
 * CVE-2018-5702. So: an authenticated POST asks for a ticket, and the ticket
 * -- 256 bits, one use, 30 seconds, no credential of any kind -- is what the
 * navigation carries. The URL that lands in the browser's download history is
 * already spent by the time it is written there.
 *
 * The anchor is created, clicked and removed rather than assigning
 * `location.href`, so a server that answered with something other than an
 * attachment could not replace the page. (It cannot: the download route
 * serves `Content-Disposition: attachment` and
 * `Content-Type: application/octet-stream` unconditionally.)
 */
export async function downloadFile(token: string, path: string): Promise<void> {
  const res = await fetch("/api/v1/download", {
    method: "POST",
    headers: apiHeaders(token),
    body: JSON.stringify({ path }),
    credentials: "omit",
    cache: "no-store",
    referrerPolicy: "no-referrer",
  });
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { error?: string };
    throw new Error(body.error || `the server refused to mint a download ticket (${res.status})`);
  }
  const { url } = (await res.json()) as TicketResponse;
  if (!url || !url.startsWith("/d/")) {
    throw new Error("the server returned a download URL this page will not follow");
  }
  const a = document.createElement("a");
  a.href = url;
  a.rel = "noreferrer";
  // No `download` attribute: the server's Content-Disposition already names
  // the file, and letting the page choose the name would let a path from the
  // volume decide what lands in the user's Downloads folder.
  a.style.display = "none";
  a.setAttribute("data-testid", "pelfs-download-link");
  document.body.appendChild(a);
  a.click();
  a.remove();
}
