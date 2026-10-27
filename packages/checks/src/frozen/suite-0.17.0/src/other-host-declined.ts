/** Thrown by a FetchLike wrapper that refuses, before any request is made, to
 *  contact a host other than the endpoint's own — a host the endpoint pointed
 *  us at (a redirect hop, a `resource_metadata` URL) that the caller does not
 *  probe. Our decision, never the target's defect and never an ssrf-guard
 *  error: probe.ts maps it to `probe_declined_other_host`, which names neither
 *  the host nor why it was declined. The message is fixed, and the host is
 *  not carried on the error, so nothing about the declined host can reach a
 *  reason.
 *
 *  Its own module rather than wire.ts: the differential tests load probe.ts
 *  against frozen copies of wire.ts, and this class is vocabulary shared by
 *  the wrappers and probe.ts, not wire behaviour. */
export class OtherHostDeclined extends Error {
  constructor() {
    super('declined to contact a host other than the endpoint this run checks')
    this.name = 'OtherHostDeclined'
  }
}
