import type { ListingMeta } from "../api/types";

/**
 * THE ONE COUNT THIS PANE STILL SHOWS, AND THE TWO CAVEATS THAT ARE GONE.
 *
 * DELETED, on the owner's instruction, twice given: the search caveat. It was
 * a paragraph above the grid ("Search below is partial by design…"), then a
 * <details> chip beside the search box that opened to the same paragraph. The
 * second was the wrong fix for the first -- "SAME PROBLEM WITH SEARCH ('search
 * covers loaded rows'). I ASKED YOU TO DO THAT LAST ROUND." -- because moving
 * an implementation confession into a disclosure keeps it on the screen. A
 * tooltip would be the same move again, so there is no title attribute here
 * either.
 *
 * The FACT is unchanged and it is not hidden: the component's search filters
 * loaded rows and fires no request (measured, recording.json step "search"),
 * so "no results" is not "not in your volume". It lives in
 * docs/known-issues.md, where it is findable, dated and cross-referenced, and
 * webapi.PartialSearchNotice still carries it on the wire for a client that
 * wants to render it. This UI does not.
 *
 * WHAT STAYS is the COUNT, because it is not a caveat: a folder that holds two
 * million entries and shows five thousand has to say five thousand of two
 * million, or the pane is reporting a number that is not the directory's. That
 * is a fact about the user's data, said in six words, with no disclosure and
 * no explanation attached -- and it appears only when the numbers differ, so a
 * normal folder shows nothing at all.
 */
export function CapCaveat({ meta }: { meta: ListingMeta | null }) {
  if (!meta || meta.total === undefined || meta.total <= meta.returned) return null;
  return (
    <span
      className="pelfs-count"
      data-testid="listing-cap"
      data-listing-total={meta.total}
      data-listing-returned={meta.returned}
    >
      showing {meta.returned.toLocaleString()} of {meta.total.toLocaleString()}
    </span>
  );
}

/**
 * What "uploaded" means, said at the moment it is most likely to be
 * misunderstood.
 *
 * A browser upload finishes and the file appears in the grid. At that instant
 * the bytes are in the local overlay -- durable against `kill -9`, invisible
 * to the federation -- and the user's next action is to close the laptop.
 * docs/design-guiclients.md measured the trap: 200 documents at ~2 MB fires
 * neither the 1 GiB nor the 200,000-inode pressure trigger, so nothing is
 * published for up to five minutes, and a browser tab has no unmount.
 */
export function UploadNotice({ text }: { text: string }) {
  if (!text) return null;
  return (
    <p className="pelfs-note pelfs-note--staged" data-testid="upload-notice" role="status">
      {text}
    </p>
  );
}

/**
 * A failed operation, said out loud -- beside a listing that has already been
 * put back.
 *
 * The store applies every change optimistically, so a refused rename used to
 * leave the new name on the screen with this banner underneath it: two
 * answers, and the screen is the one a user believes. The provider now
 * re-lists the directories a failed mutation touched and hands the server's
 * answer back to the store (api/provider.ts, `getHandlers`), so by the time
 * this appears the row is the volume's row again and the banner says only what
 * did not happen.
 *
 * The reload button stays, for the case the repair cannot cover: a server that
 * is not answering at all fails the re-listing too, and then a full reload is
 * the only thing left. It is offered rather than performed, because a page
 * that reloads itself on an error is a page that can lose an unsent rename in
 * another folder.
 */
export function ErrorBanner({ text, onReload }: { text: string; onReload: () => void }) {
  if (!text) return null;
  return (
    <div className="pelfs-note pelfs-note--bad" data-testid="pelfs-error" role="alert">
      <span>{text}</span>{" "}
      <button type="button" className="pelfs-button pelfs-button--quiet" onClick={onReload}>
        Reload the listing
      </button>
      <span className="pelfs-note__more">
        The listing above has been read back from the volume, so what you see is what the volume
        holds — the change you asked for is not in it. If this folder still looks wrong, the server
        did not answer the re-read either, and a reload is the way to be sure.
      </span>
    </div>
  );
}
