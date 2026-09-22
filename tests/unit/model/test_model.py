from idns.model import (
    DNSName,
    DNSHeader,
    DNSQuestion,
    DNSMessage,
    ARecord,
    AAAARecord,
    NSRecord,
    CNAMERecord,
    MXRecord,
    TXTRecord,
    SOARecord,
)


# ============================================================
# 1.1 DNS NAME
# ============================================================

def test_dns_name():
    name = DNSName("www.google.com")

    assert str(name) == "www.google.com"

    assert name.labels == (
        "www",
        "google",
        "com",
    )


def test_dns_name_trailing_dot():
    name = DNSName("www.google.com.")

    assert str(name) == "www.google.com"


def test_dns_root_name():
    name = DNSName(".")

    assert str(name) == "."
    assert name.labels == ()


def test_dns_name_rejects_empty():
    try:
        DNSName("")
        assert False
    except ValueError:
        assert True


# ============================================================
# 1.2 DNS HEADER
# ============================================================

def test_dns_header():

    header = DNSHeader(
        transaction_id=1234,
        qr=0,
        opcode=0,
        rd=1,
        qdcount=1,
    )

    assert header.transaction_id == 1234
    assert header.qr == 0
    assert header.opcode == 0
    assert header.rd == 1
    assert header.qdcount == 1


def test_dns_header_response():

    header = DNSHeader(
        transaction_id=5000,
        qr=1,
        aa=1,
        ra=1,
        rcode=0,
    )

    assert header.qr == 1
    assert header.aa == 1
    assert header.ra == 1
    assert header.rcode == 0


# ============================================================
# 1.3 DNS QUESTION
# ============================================================

def test_dns_question():

    question = DNSQuestion(
        qname=DNSName("google.com"),
        qtype="A",
        qclass="IN",
    )

    assert str(question.qname) == "google.com"
    assert question.qtype == "A"
    assert question.qclass == "IN"

    assert question.qtype_code == 1
    assert question.qclass_code == 1


def test_dns_question_aaaa():

    question = DNSQuestion(
        qname=DNSName("google.com"),
        qtype="AAAA",
        qclass="IN",
    )

    assert question.qtype == "AAAA"
    assert question.qtype_code == 28


# ============================================================
# 1.4 RESOURCE RECORDS
# ============================================================

def test_a_record():

    record = ARecord(
        name=DNSName("example.com"),
        address="93.184.216.34",
        ttl=300,
    )

    assert record.record_type == "A"
    assert record.record_class == "IN"
    assert record.address == "93.184.216.34"
    assert record.ttl == 300


def test_aaaa_record():

    record = AAAARecord(
        name=DNSName("example.com"),
        address="2001:db8::1",
        ttl=300,
    )

    assert record.record_type == "AAAA"
    assert record.record_class == "IN"
    assert record.address == "2001:db8::1"


def test_ns_record():

    record = NSRecord(
        name=DNSName("example.com"),
        nameserver=DNSName("ns1.example.com"),
        ttl=3600,
    )

    assert record.record_type == "NS"
    assert str(record.nameserver) == "ns1.example.com"
    assert record.ttl == 3600


def test_cname_record():

    record = CNAMERecord(
        name=DNSName("www.example.com"),
        canonical_name=DNSName("example.com"),
        ttl=300,
    )

    assert record.record_type == "CNAME"
    assert str(record.canonical_name) == "example.com"


def test_mx_record():

    record = MXRecord(
        name=DNSName("example.com"),
        preference=10,
        exchange=DNSName("mail.example.com"),
        ttl=3600,
    )

    assert record.record_type == "MX"
    assert record.preference == 10
    assert str(record.exchange) == "mail.example.com"


def test_txt_record():

    record = TXTRecord(
        name=DNSName("example.com"),
        text=("Hello DNS",),
        ttl=300,
    )

    assert record.record_type == "TXT"
    assert record.record_class == "IN"
    assert record.text == ("Hello DNS",)


def test_txt_multiple_strings():

    record = TXTRecord(
        name=DNSName("example.com"),
        text=(
            "Hello",
            "DNS",
        ),
        ttl=300,
    )

    assert record.text == (
        "Hello",
        "DNS",
    )


def test_soa_record():

    record = SOARecord(
        name=DNSName("example.com"),

        mname=DNSName("ns1.example.com"),
        rname=DNSName("admin.example.com"),

        serial=2026092101,
        refresh=3600,
        retry=600,
        expire=86400,
        minimum=300,

        ttl=300,
    )

    assert record.record_type == "SOA"

    assert str(record.mname) == "ns1.example.com"
    assert str(record.rname) == "admin.example.com"

    assert record.serial == 2026092101
    assert record.refresh == 3600
    assert record.retry == 600
    assert record.expire == 86400
    assert record.minimum == 300


# ============================================================
# 1.5 DNS MESSAGE
# ============================================================

def test_dns_message():

    header = DNSHeader(
        transaction_id=1234,
        qr=0,
        rd=1,
    )

    question = DNSQuestion(
        qname=DNSName("google.com"),
        qtype="A",
        qclass="IN",
    )

    message = DNSMessage(
        header=header,
        questions=[question],
    )

    message.update_counts()

    assert len(message.questions) == 1
    assert len(message.answers) == 0
    assert len(message.authorities) == 0
    assert len(message.additionals) == 0

    assert message.header.qdcount == 1
    assert message.header.ancount == 0
    assert message.header.nscount == 0
    assert message.header.arcount == 0


def test_dns_message_with_answer():

    header = DNSHeader(
        transaction_id=1234,
        qr=1,
        aa=1,
    )

    question = DNSQuestion(
        qname=DNSName("example.com"),
        qtype="A",
    )

    answer = ARecord(
        name=DNSName("example.com"),
        address="93.184.216.34",
        ttl=300,
    )

    message = DNSMessage(
        header=header,
        questions=[question],
        answers=[answer],
    )

    message.update_counts()

    assert message.header.qdcount == 1
    assert message.header.ancount == 1

    assert message.answers[0].record_type == "A"
    assert (
        message.answers[0].address
        == "93.184.216.34"
    )