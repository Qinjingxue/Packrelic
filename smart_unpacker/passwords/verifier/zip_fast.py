from __future__ import annotations

from smart_unpacker.passwords.verifier.base import PasswordBatchVerification


class ZipFastVerifier:
    def verify_batch(
        self,
        archive_path: str,
        passwords: list[str],
        *,
        part_paths: list[str] | None = None,
    ) -> PasswordBatchVerification:
        if part_paths:
            return PasswordBatchVerification(
                ok=False,
                status="unknown_need_fallback",
                attempts=0,
                error_text="zip fast verifier does not support split archives yet",
            )
        try:
            from smart_unpacker_native import zip_fast_verify_passwords
        except Exception as exc:
            return PasswordBatchVerification(
                ok=False,
                status="backend_unavailable",
                attempts=0,
                error_text=f"zip fast verifier unavailable: {exc}",
                terminal=False,
            )

        normalized_passwords = list(passwords or [""])
        try:
            outcome = zip_fast_verify_passwords(archive_path, normalized_passwords)
        except Exception as exc:
            return PasswordBatchVerification(
                ok=False,
                status="unknown_need_fallback",
                attempts=0,
                error_text=f"zip fast verifier failed: {exc}",
            )

        status = str(outcome.get("status") or "unknown_need_fallback")
        matched_index = int(outcome.get("matched_index", -1))
        attempts = int(outcome.get("attempts", 0))
        message = str(outcome.get("message") or "")
        return PasswordBatchVerification(
            ok=status == "match" and matched_index >= 0,
            status=status,
            matched_index=matched_index,
            attempts=attempts,
            error_text=message.lower(),
            terminal=status == "damaged",
        )
