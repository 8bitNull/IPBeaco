"""Source parser registry; parsers extract snapshots without evidence admission."""

from . import blocklist_de, feodo, spamhaus

PARSERS = {
    "blocklist_de": blocklist_de.parse,
    "spamhaus_drop": spamhaus.parse,
    "feodo": feodo.parse,
}
