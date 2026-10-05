"""Source parser registry; parsers extract snapshots without evidence admission."""

from . import blocklist_de, cins, feodo, spamhaus

PARSERS = {
    "cins_army": cins.parse,
    "blocklist_de": blocklist_de.parse,
    "spamhaus_drop": spamhaus.parse,
    "feodo": feodo.parse,
}
