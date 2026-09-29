"""DNS glue-record extraction for iterative resolution."""

from idns.model import ARecord, AAAARecord, DNSMessage, DNSName


class GlueExtractor:
    """Extract address records for delegated nameservers."""

    @staticmethod
    def extract(
        response: DNSMessage,
        nameservers: list[DNSName],
    ) -> dict[DNSName, list[str]]:
        """Return addresses from Additional records for the nameservers."""

        selected_nameservers = set(nameservers)
        glue: dict[DNSName, list[str]] = {}

        for record in response.additionals:
            if record.name not in selected_nameservers:
                continue

            if isinstance(record, (ARecord, AAAARecord)):
                glue.setdefault(record.name, []).append(record.address)

        return glue