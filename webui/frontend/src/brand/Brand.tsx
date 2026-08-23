import { markUrl } from "./mark";

/**
 * The wordmark: the Pelican mark, unmodified, beside "pelfs" with the "fs"
 * in the brand blue. Option 1 of the two the design offers, chosen because
 * nothing is drawn on top of the mark, so nothing about the mark can be got
 * wrong.
 */
export function Brand({ subtitle }: { subtitle?: string }) {
  return (
    <div className="pelfs-brand" data-testid="pelfs-brand">
      <img
        className="pelfs-brand__mark"
        src={markUrl}
        // Deliberately not "Pelican Platform logo": this is pelfs, wearing a
        // borrowed mark with permission.
        alt="Pelican Platform mark"
        width={28}
        height={28}
      />
      <span className="pelfs-brand__word">
        pel<em>fs</em>
      </span>
      {subtitle ? <span className="pelfs-brand__sub">{subtitle}</span> : null}
    </div>
  );
}

/*
 * THERE IS NO FOOTER, and its absence is a decision rather than an omission.
 *
 * This page used to carry a disclaimer -- "an independent tool for Pelican
 * federations; not an official Pelican Platform product" -- under the
 * borrowed mark. The Pelican Project's PI, who is the person whose mark it
 * is, asked for it off the page: not important to state, and it cost every
 * viewer a line. The attribution it was standing in for did not go anywhere:
 * it is in public/brand/NOTICE.txt, which ships beside the asset it is about
 * and is served at /brand/NOTICE.txt (internal/webui/webui_test.go asserts
 * both), and in the repository's own NOTICE.
 *
 * The MIT notices for the bundled packages are the OTHER obligation and it is
 * separate: they are embedded, served at /third_party.txt, and linked from
 * the status line at the bottom of App.tsx.
 */
