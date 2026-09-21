from dataclasses import dataclass


@dataclass(frozen=True)
class DNSName:
    """
    Represents a DNS domain name.

    Examples:
        google.com
        www.google.com
        ns1.example.com
        .
    """

    value: str

    def __post_init__(self):
        value = self.value.strip()

        if not value:
            raise ValueError("DNS name cannot be empty")

        # Root DNS name
        if value == ".":
            object.__setattr__(self, "value", ".")
            return

        # Normalize trailing dot
        value = value.rstrip(".")

        if not value:
            raise ValueError("Invalid DNS name")

        labels = value.split(".")

        for label in labels:

            if not label:
                raise ValueError(
                    "DNS name contains an empty label"
                )

            if len(label.encode("ascii")) > 63:
                raise ValueError(
                    f"DNS label is too long: {label}"
                )

        # DNS names are limited to 255 octets
        encoded_length = sum(
            len(label.encode("ascii")) + 1
            for label in labels
        ) + 1

        if encoded_length > 255:
            raise ValueError(
                "DNS name exceeds 255 octets"
            )

        object.__setattr__(
            self,
            "value",
            value
        )

    @property
    def labels(self) -> tuple[str, ...]:
        """Return DNS labels."""

        if self.value == ".":
            return ()

        return tuple(self.value.split("."))

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return f"DNSName({self.value!r})"