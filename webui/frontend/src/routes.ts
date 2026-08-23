/**
 * The two addresses `pelfs browse` serves, in one place.
 *
 * `/` is this app; `/connect` is the hand-written connection page
 * (cmd/pelfs/browse.html) — the credential desk, the generated Cyberduck
 * profile, and the federation-login cards. The route table that decides both
 * is cmd/pelfs/browse.go's `routes`.
 *
 * A constant rather than three string literals because a page that links to
 * the wrong half of its own product is a bug nobody notices until a user
 * clicks it, and because this file is what a reader greps for when they want
 * to know what else is on this origin.
 */
export const APP = "/";
export const CONNECT = "/connect";
