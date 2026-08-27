# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) TrueNAS, 2026

import json

from truenas_audit_parse.formatter import audit_entry_to_json
from truenas_audit_parse.parsers import classify_event, parse_multipart_event
from truenas_audit_parse.event_types import AuditEvent
from truenas_audit_parse.s3 import process_s3, s3_record


# Captured from a live TrueNAS box: an s3d PutObject served 200 on an
# audited bucket, exactly as the kernel logged it (enriched suffix
# separator already normalized to a space, as the handler does).
SAMPLE_S3_PUT = (
    "type=TRUSTED_APP msg=audit(1787762617.917:352): pid=36505 uid=0 "
    "auid=0 ses=41 subj=unconfined "
    'msg=\'op=s3d:PutObject acct="s3user" acct_uid="3001" '
    'addr="127.0.0.1:36092" ts="1787762617.919980" req="86F8112727BF1799" '
    'keyid="dev-access-key" bucket="vault" obj="hello.txt" status="200" '
    'bytes_in="18" bytes_out="0" size="18" res=success\' '
    'UID="root" AUID="root"'
)

# Captured beside it: the same key requested with a wrong secret — no
# principal was ever named, the claimed key id rides, and the class is
# USER_AUTH.
SAMPLE_S3_BADSIG = (
    "type=USER_AUTH msg=audit(1787762617.945:354): pid=36505 uid=0 "
    "auid=0 ses=41 subj=unconfined "
    'msg=\'op=s3d:GetObject addr="127.0.0.1:36122" '
    'ts="1787762617.949777" req="C26905B2252A1FB3" keyid="dev-access-key" '
    'bucket="vault" obj="hello.txt" status="403" '
    'err="SignatureDoesNotMatch" bytes_in="0" bytes_out="294" '
    'res=failed\' UID="root" AUID="root"'
)

# A discretionary denial whose object key was hex-encoded by the
# producer (a space is outside the clean byte range).
SAMPLE_S3_DENIAL = (
    "type=DAC_CHECK msg=audit(1787762000.123:9999): pid=36505 uid=0 "
    "auid=0 ses=41 subj=unconfined "
    'msg=\'op=s3d:GetObject acct="alice" acct_uid="3001" '
    'addr="10.0.0.5:5234" ts="1787762000.123456" req="AB12CD34EF56AB78" '
    'keyid="AKTNAS7EXAMPLE" bucket="vault" obj=68656C6C6F20776F726C64 '
    'status="403" err="AccessDenied" bytes_in="0" bytes_out="294" '
    "res=failed'"
)

# A delete batch: counts partitioning an ordered, numbered key list,
# with a truncated remainder.
SAMPLE_S3_BATCH = (
    "type=TRUSTED_APP msg=audit(1787762900.500:10001): pid=36505 uid=0 "
    "auid=0 ses=41 subj=unconfined "
    'msg=\'op=s3d:DeleteObjects acct="s3user" acct_uid="3001" '
    'addr="127.0.0.1:40000" ts="1787762900.500100" req="AAAA1111BBBB2222" '
    'bucket="vault" status="200" bytes_in="321" bytes_out="512" '
    'deleted="3" denied="1" errors="0" obj_0="secret/a" obj_1="b.txt" '
    'obj_2=636166C3A9 truncated="2" res=success\''
)

# Captured from the same box after the multipart engine landed: one
# real upload's create, a part, and its completion — the field sets
# the producer's per-operation table promises for the family.
SAMPLE_S3_MPU_CREATE = (
    "type=TRUSTED_APP msg=audit(1787769772.646:947): pid=66563 uid=0 "
    "auid=0 ses=87 subj=unconfined "
    'msg=\'op=s3d:CreateMultipartUpload acct="s3user" acct_uid="3001" '
    'addr="127.0.0.1:47628" ts="1787769772.649584" req="86F8169B622C5FB9" '
    'keyid="dev-access-key" bucket="vault" obj="mpu/1787769772.bin" '
    'status="200" bytes_in="0" bytes_out="254" '
    'upload="000001a03f61da674b79d201b11c051b" res=success\' '
    'UID="root" AUID="root"'
)

SAMPLE_S3_MPU_PART = (
    "type=TRUSTED_APP msg=audit(1787769772.722:948): pid=66563 uid=0 "
    "auid=0 ses=87 subj=unconfined "
    'msg=\'op=s3d:UploadPart acct="s3user" acct_uid="3001" '
    'addr="127.0.0.1:47628" ts="1787769772.727420" req="24A19C50E3F2DB86" '
    'keyid="dev-access-key" bucket="vault" obj="mpu/1787769772.bin" '
    'status="200" bytes_in="5242880" bytes_out="0" '
    'upload="000001a03f61da674b79d201b11c051b" part="1" size="5242880" '
    'res=success\' UID="root" AUID="root"'
)

SAMPLE_S3_MPU_COMPLETE = (
    "type=TRUSTED_APP msg=audit(1787769772.814:950): pid=66563 uid=0 "
    "auid=0 ses=87 subj=unconfined "
    'msg=\'op=s3d:CompleteMultipartUpload acct="s3user" '
    'acct_uid="3001" addr="127.0.0.1:47628" ts="1787769772.819171" '
    'req="601289C7E04FD3F8" keyid="dev-access-key" bucket="vault" '
    'obj="mpu/1787769772.bin" status="200" bytes_in="271" '
    'bytes_out="327" upload="000001a03f61da674b79d201b11c051b" '
    'parts="2" res=success\' UID="root" AUID="root"'
)

# A PAM USER_AUTH that is not s3d's: it must stay on the credential
# path, untouched by the S3 recognizer.
SAMPLE_PAM_AUTH = (
    "type=USER_AUTH msg=audit(1736973000.100:600): pid=2222 uid=0 "
    "auid=4294967295 ses=4294967295 subj=unconfined "
    'msg=\'op=PAM:authentication grantors=pam_permit acct="root" '
    'exe="/usr/sbin/sshd" hostname=10.0.0.9 addr=10.0.0.9 '
    'terminal=ssh res=success\' UID="root" AUID="unset"'
)


def _tnaudit(line: str) -> dict:
    parsed = parse_multipart_event([line])
    event_type = classify_event(parsed)
    msgid = "audit(" + line.split("audit(")[1].split(")")[0] + ")"
    out = audit_entry_to_json(msgid, event_type, [line], parsed=parsed)
    assert out.startswith("@cee:")
    return json.loads(out[len("@cee:") :])["TNAUDIT"]


class TestClassifyS3:
    def test_trusted_app_with_s3d_op_is_s3(self):
        parsed = parse_multipart_event([SAMPLE_S3_PUT])
        assert classify_event(parsed) == AuditEvent.S3

    def test_dac_check_with_s3d_op_is_s3(self):
        parsed = parse_multipart_event([SAMPLE_S3_DENIAL])
        assert classify_event(parsed) == AuditEvent.S3

    def test_user_auth_with_s3d_op_is_s3(self):
        parsed = parse_multipart_event([SAMPLE_S3_BADSIG])
        assert classify_event(parsed) == AuditEvent.S3

    def test_pam_user_auth_stays_credential(self):
        parsed = parse_multipart_event([SAMPLE_PAM_AUTH])
        assert s3_record(parsed) is None
        assert classify_event(parsed) == AuditEvent.CREDENTIAL


class TestS3Envelope:
    def test_success_record_maps_the_envelope(self):
        parsed = parse_multipart_event([SAMPLE_S3_PUT])
        out = audit_entry_to_json(
            "audit(1787762617.917:352)",
            AuditEvent.S3,
            [SAMPLE_S3_PUT],
            parsed=parsed,
        )
        tn = json.loads(out[len("@cee:") :])["TNAUDIT"]
        assert tn["svc"] == "S3"
        assert tn["event"] == "PutObject"
        assert tn["user"] == "s3user"
        assert tn["addr"] == "127.0.0.1:36092"
        assert tn["success"] is True
        assert tn["sess"] is None
        # time comes from ts= — the settled moment, not the kernel's
        # send stamp on the msgid.
        assert tn["time"] == "2026-08-26 16:43:37.919980"
        data = json.loads(tn["event_data"])
        assert data["record_type"] == "TRUSTED_APP"
        assert data["bucket"] == "vault"
        assert data["obj"] == "hello.txt"
        assert data["req"] == "86F8112727BF1799"
        assert data["keyid"] == "dev-access-key"
        assert data["status"] == 200
        assert data["bytes_in"] == 18
        assert data["size"] == 18
        assert data["acct_uid"] == 3001
        assert data["vers"] == {"major": 0, "minor": 1}
        # The kernel's prefix names the sender, not the principal, and
        # must not leak into event_data.
        for sender_field in ("pid", "uid", "auid", "ses", "subj"):
            assert sender_field not in data

    def test_auth_failure_names_the_claimed_key_and_no_user(self):
        tn = _tnaudit(SAMPLE_S3_BADSIG)
        assert tn["svc"] == "S3"
        assert tn["event"] == "GetObject"
        assert tn["user"] is None
        assert tn["success"] is False
        data = json.loads(tn["event_data"])
        assert data["record_type"] == "USER_AUTH"
        assert data["keyid"] == "dev-access-key"
        assert data["err"] == "SignatureDoesNotMatch"
        assert data["status"] == 403

    def test_hex_encoded_values_are_decoded(self):
        tn = _tnaudit(SAMPLE_S3_DENIAL)
        assert tn["success"] is False
        data = json.loads(tn["event_data"])
        assert data["record_type"] == "DAC_CHECK"
        # The producer hex-encodes a key holding a space; the reader
        # undoes it.
        assert data["obj"] == "hello world"
        assert data["err"] == "AccessDenied"

    def test_multipart_family_carries_its_upload_facts(self):
        # The create's upload id is an outcome — it did not exist
        # until the answer — while a part's number and size and the
        # completion's manifest count are input facts.
        create = _tnaudit(SAMPLE_S3_MPU_CREATE)
        assert create["event"] == "CreateMultipartUpload"
        data = json.loads(create["event_data"])
        assert data["upload"] == "000001a03f61da674b79d201b11c051b"
        assert "part" not in data
        assert "parts" not in data

        part = _tnaudit(SAMPLE_S3_MPU_PART)
        assert part["event"] == "UploadPart"
        data = json.loads(part["event_data"])
        assert data["upload"] == "000001a03f61da674b79d201b11c051b"
        assert data["part"] == 1
        assert data["size"] == 5242880
        assert data["bytes_in"] == 5242880

        complete = _tnaudit(SAMPLE_S3_MPU_COMPLETE)
        assert complete["event"] == "CompleteMultipartUpload"
        assert complete["success"] is True
        data = json.loads(complete["event_data"])
        assert data["upload"] == "000001a03f61da674b79d201b11c051b"
        assert data["parts"] == 2
        # The manifest's own size, not the assembled object's.
        assert data["bytes_in"] == 271

    def test_batch_record_collects_its_numbered_keys(self):
        tn = _tnaudit(SAMPLE_S3_BATCH)
        assert tn["event"] == "DeleteObjects"
        data = json.loads(tn["event_data"])
        assert data["deleted"] == 3
        assert data["denied"] == 1
        assert data["errors"] == 0
        assert data["truncated"] == 2
        # Ordered by index, hex decoded where the producer encoded
        # ('café' carries a byte outside the clean range).
        assert data["objs"] == ["secret/a", "b.txt", "café"]


class TestProcessS3:
    def test_undecodable_hex_is_replaced_not_dropped(self):
        # Clipping can split a multibyte char; the field survives with
        # replacement characters rather than vanishing from the record.
        record = {
            "fields": {"obj": "C3"},
            "raw_fields": {"obj": "C3"},
        }
        data = process_s3(record)
        assert data["obj"] == "�"

    def test_quoted_hex_lookalike_stays_verbatim(self):
        # A clean value that happens to look like hex was quoted on the
        # wire; the raw quoting is the discriminator.
        record = {
            "fields": {"req": "AB12CD34EF56AB78"},
            "raw_fields": {"req": '"AB12CD34EF56AB78"'},
        }
        data = process_s3(record)
        assert data["req"] == "AB12CD34EF56AB78"
