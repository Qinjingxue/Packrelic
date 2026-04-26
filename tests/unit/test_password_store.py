from types import SimpleNamespace

from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.passwords import PasswordResolver, PasswordSession, PasswordStore


def test_password_store_orders_user_recent_builtin_and_dedupes():
    store = PasswordStore.from_sources(
        cli_passwords=["cli", "shared"],
        recent_passwords=["recent", "cli"],
        builtin_passwords=["builtin", "shared"],
    )

    assert store.candidates() == ["cli", "shared", "recent", "builtin"]


def test_password_store_remembers_success_at_front():
    store = PasswordStore.from_sources(
        cli_passwords=["cli"],
        recent_passwords=["old", "secret"],
        builtin_passwords=["secret"],
    )

    store.remember_success("secret")

    assert store.recent_passwords == ["secret", "old"]
    assert store.candidates() == ["cli", "secret", "old"]


class FakePasswordTester:
    passwords = ["secret"]

    def __init__(self):
        self.test_without_password_calls = 0
        self.find_working_password_calls = 0

    def test_without_password(self, archive_path, part_paths=None):
        self.test_without_password_calls += 1
        return SimpleNamespace(returncode=2), "wrong password"

    def find_working_password(self, archive_path, part_paths=None):
        self.find_working_password_calls += 1
        return "secret", SimpleNamespace(returncode=0), ""


def test_password_resolver_records_archive_password_in_session():
    session = PasswordSession()
    resolver = PasswordResolver(FakePasswordTester(), session)

    result = resolver.resolve("sample.zip", archive_key="archive-key")

    assert result.password == "secret"
    assert result.archive_key == "archive-key"
    assert session.get_resolved("archive-key") == "secret"


def test_password_resolver_trusts_unencrypted_resource_health_without_retesting():
    bag = FactBag()
    bag.set("resource.health", {
        "is_archive": True,
        "is_encrypted": False,
        "is_wrong_password": False,
    })
    tester = FakePasswordTester()
    session = PasswordSession()
    resolver = PasswordResolver(tester, session)

    result = resolver.resolve("sample.zip", fact_bag=bag, archive_key="archive-key")

    assert result.password == ""
    assert result.encrypted is False
    assert session.get_resolved("archive-key") == ""
    assert tester.test_without_password_calls == 0
    assert tester.find_working_password_calls == 0
    assert result.archive_key == "archive-key"


def test_password_resolver_reuses_session_password_without_retesting():
    session = PasswordSession()
    session.set_resolved("archive-key", "secret")
    tester = FakePasswordTester()
    resolver = PasswordResolver(tester, session)

    result = resolver.resolve("sample.zip", archive_key="archive-key")

    assert result.password == "secret"
