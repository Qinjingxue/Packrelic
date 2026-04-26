from smart_unpacker.contracts.filesystem import DirectorySnapshot
from smart_unpacker.relations.internal.group_builder import RelationsGroupBuilder
from smart_unpacker.relations.internal.models import CandidateGroup


class RelationsScheduler:
    """Public facade for relation grouping.

    The relation layer is intentionally a black box to callers: it receives a
    directory snapshot and returns logical archive candidates. Internal filename
    parsing, split expansion, and companion discovery live under
    smart_unpacker.relations.internal.
    """

    def __init__(self):
        self._builder = RelationsGroupBuilder()

    def build_candidate_groups(self, snapshot: DirectorySnapshot) -> list[CandidateGroup]:
        return self._builder.build_candidate_groups(snapshot)

    def detect_split_role(self, filename: str) -> str | None:
        return self._builder.detect_split_role(filename)
