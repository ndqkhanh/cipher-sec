from cipher_sec.audit import AuditEntry, AuditLog


def _entry(**over) -> AuditEntry:
    return AuditEntry(
        seq=0,
        engagement_id=over.pop("engagement_id", "e"),
        tool=over.pop("tool", "nmap"),
        technique=over.pop("technique", "recon.passive"),
        args_hash=over.pop("args_hash", "deadbeef"),
        decision=over.pop("decision", "auto"),
        result_hash=over.pop("result_hash", "cafef00d"),
        **over,
    )


def test_chain_starts_with_genesis_hash():
    log = AuditLog()
    log.append(_entry())
    assert log.entries()[0].prev_entry_hash == "0" * 64


def test_chain_verifies_when_untouched():
    log = AuditLog()
    for _ in range(5):
        log.append(_entry())
    assert log.verify_chain() is True


def test_tampering_breaks_chain():
    log = AuditLog()
    for _ in range(3):
        log.append(_entry())
    log._entries[1].tool = "TAMPERED"
    assert log.verify_chain() is False


def test_tampered_signature_breaks():
    log = AuditLog()
    log.append(_entry())
    log._entries[0].signature = "0" * 64
    assert log.verify_chain() is False


def test_sequence_numbers_monotonic():
    log = AuditLog()
    for _ in range(4):
        log.append(_entry())
    assert [e.seq for e in log.entries()] == [1, 2, 3, 4]
