# C9 implementation contract — QuantTaskPlugin and EvaluationResult

This document is the binding implementation contract for C9. It implements the
frozen C6 `QuantTaskPlugin`, `EvaluationRequest`, and `EvaluationResult` seam;
a development-only known-truth synthetic plugin; a mock-only HM1 futures
adapter; and a formula-alpha validation skeleton. C10 owns authorization,
protected-resource access, query accounting, the evidence ledger, contamination
handling, and every real gate/final action. C11 owns the live Arbor loop. C13
owns the bounded real HM1 pilot.

The packaged C6 schema remains byte-identical. Its shapes and enums override
older prose examples. C9 creates no statistical-control claim and keeps sealed
final closed.

## 1. Public surface and value categories

`q_arbor.evaluation` exports exactly:

```python
class EvaluationError(Exception): ...
class EvaluationDecodeError(EvaluationError): ...
class EvaluationSchemaError(EvaluationError): ...
class EvaluationInvariantError(EvaluationError): ...
class EvaluationIntegrityError(EvaluationError): ...
class EvaluationPersistenceError(EvaluationError):
    committed: bool
class EvaluationBoundaryError(EvaluationError): ...
class EvaluationPluginError(EvaluationError): ...

class ReasonCode: ...
class ArtifactRef: ...
class PluginIdentity: ...
class CheckResult: ...
class MetricValue: ...
class EvaluationFailure: ...
class FamilyEvidence: ...
class MaterializationReceipt: ...
class CandidateArtifact: ...
class CandidateValidation: ...
class CandidateReceipt: ...
class ValidatedCandidate(CandidateReceipt): ...
class EvaluationRequest: ...
class FoldPolicy: ...
class VerifiedRuntimeLock: ...
class EvaluationBinding: ...
class EvaluationResult: ...
class EvaluationSummary: ...
class SplitDataView(Protocol): ...
class ArtifactResolver(Protocol): ...
class ArtifactSink(Protocol): ...
class AuthorizedSplit(Protocol): ...
class QuantTaskPlugin(Protocol): ...
class ContentAddressedArtifactStore: ...

freeze_candidate_validation(mapping, *, candidate, contract,
                            plugin_identity) -> CandidateValidation
validate_candidate_validation(mapping, *, candidate, contract,
                              plugin_identity) -> CandidateValidation
load_candidate_validation(path, *, candidate, contract,
                          plugin_identity) -> CandidateValidation

freeze_evaluation_request(mapping, *, contract,
                          candidate_receipt) -> EvaluationRequest
validate_evaluation_request(mapping, *, contract,
                            candidate_receipt) -> EvaluationRequest
load_evaluation_request(path, *, contract,
                        candidate_receipt) -> EvaluationRequest

freeze_evaluation_result(mapping, *, binding) -> EvaluationResult
validate_evaluation_result(mapping, *, binding) -> EvaluationResult
load_evaluation_result(path, *, binding,
                       expected_sha256=None) -> EvaluationResult

make_candidate_failure_result(*, binding, reason_code) -> EvaluationResult
make_access_denied_result(*, binding, reason_code) -> EvaluationResult
validate_evaluation_evidence(result, *, request, node, evidence) -> None
canonical_evaluation_result_bytes(result) -> bytes
compute_evaluation_result_hash(result) -> str
```

The JSON-backed values are `ArtifactRef`, `PluginIdentity`, `CheckResult`,
`MetricValue`, `EvaluationFailure`, `FamilyEvidence`,
`MaterializationReceipt`, `CandidateValidation`, `EvaluationRequest`,
`FoldPolicy`, `VerifiedRuntimeLock`, `EvaluationResult`, and
`EvaluationSummary`. They are deeply immutable and hashable; `to_dict()` returns
a detached copy, `to_json()` returns compact sorted NFC UTF-8 JSON, `.sha256`
hashes the complete canonical value, and `write(path)` is atomic. A self-hash is
never inserted into a C6 payload.

`ArtifactRef` is the single deliberate property-name exception because its C6
wire shape already owns a normative `sha256` field: `ArtifactRef.sha256` returns
the referenced content digest, while `ArtifactRef.canonical_sha256` returns the
hash of the complete canonical ArtifactRef object. Every other JSON-backed
value uses `.sha256` for its complete canonical value.

`CandidateArtifact`, `CandidateReceipt`, `ValidatedCandidate`,
`EvaluationBinding`, split/data/sink/resolver objects, and plugins are runtime
carriers. They are immutable where concrete, expose only the properties below,
and do not promise whole-object JSON serialization. `CandidateArtifact` identity
is its `candidate_hash`; capabilities and filesystem objects are never hashed as
if they were research facts.

All schema `Identifier` and SHA values are runtime checked with full-match,
closing JSON Schema `$`/terminal-newline ambiguity. Artifact paths additionally
use the C7 literal-path byte/segment limits and reject absolute/drive paths,
backslash, dot segments, repeated separators, controls, and glob metacharacters.
`ReasonCode.parse(value)` accepts only ASCII
`[a-z][a-z0-9_.-]{0,127}`. Check evidence, failure summary, and warnings are
ReasonCodes; they cannot carry paths, URIs, traceback text, rows, secrets,
stdout, or stderr.

### Exact constructors

```python
ReasonCode.parse(value: str) -> ReasonCode
ArtifactRef.from_mapping(mapping) -> ArtifactRef
PluginIdentity.from_mapping(mapping) -> PluginIdentity
CheckResult.from_mapping(mapping) -> CheckResult
MetricValue.from_mapping(mapping) -> MetricValue
EvaluationFailure.from_mapping(mapping) -> EvaluationFailure
FamilyEvidence.from_mapping(mapping) -> FamilyEvidence
FoldPolicy.from_mapping(mapping) -> FoldPolicy
EvaluationSummary.from_result(result) -> EvaluationSummary

MaterializationReceipt.scan(root, relative_paths) -> MaterializationReceipt
CandidateArtifact.from_bytes(
    artifact, payload, *, code_commit, changed_paths, materialization
) -> CandidateArtifact
CandidateReceipt.bind(candidate, validation, receipt_ref, *,
                      contract, plugin_identity) -> CandidateReceipt
ValidatedCandidate.bind(candidate, validation, receipt_ref, *,
                        contract, plugin_identity) -> ValidatedCandidate

VerifiedRuntimeLock.from_artifacts(
    evaluator_ref, config_ref, *, resolver
) -> VerifiedRuntimeLock
EvaluationBinding.create(
    request, contract, candidate_receipt, plugin_identity, runtime_lock, *,
    result_id, seed, artifact_resolver
) -> EvaluationBinding

ContentAddressedArtifactStore.create(root) -> ContentAddressedArtifactStore
store.scope(*, request_id, produced_by_event_id,
            runtime_lock) -> ArtifactSink
```

Direct slot/dataclass construction is not public. Each mapping constructor
copies its input. Every property returns an immutable value or detached copy.
JSON-backed wrappers expose one readonly property per serialized key plus
`sha256`, `to_dict`, `to_json`, and `write`. `CandidateReceipt` exposes
`candidate`, `validation`, `receipt_ref`, `contract_hash`, `plugin_identity`,
and `status`; `ValidatedCandidate` exposes the same properties and is a positive
type witness for `status=valid`. `VerifiedRuntimeLock` exposes `evaluator_ref`,
`config_ref`, `policy`, `evaluator_sha256`, `config_sha256`, and `verify()`.
`EvaluationBinding` exposes `request`, `contract`, `candidate_receipt`,
`plugin_identity`, `runtime_lock`, `result_id`, `seed`, and
`artifact_resolver`. `ContentAddressedArtifactStore` implements both resolver
and scoped-sink creation; it does not expose its root through a serialized
value.

## 2. Strict decoding, canonicalization, and persistence

Raw decoders reject invalid UTF-8, BOM, duplicate keys, normalized-key
collisions, NaN/Infinity, recursion overflow, unsupported Python values, and
non-object roots. Frozen C6 shape failures are `EvaluationSchemaError`;
schema-valid cross-field contradictions are `EvaluationInvariantError`;
identity/digest contradictions are `EvaluationIntegrityError`;
resource/sink escapes are `EvaluationBoundaryError`; filesystem failures are
`EvaluationPersistenceError`; plugin construction/programmer failures before a
terminal result exists are `EvaluationPluginError`.

`freeze_*` normalizes unordered input into canonical order. `validate_*` and
`load_*` require already canonical order and never silently rewrite signed
payloads. Orders are:

- requested metrics: contract primary, then diagnostics declaration order;
- candidate changed paths/materialization entries and validation checks:
  Unicode-code-point order;
- constraints and diagnostics: contract declaration order;
- folds: `FoldPolicy.expected_fold_ids`; fold metrics: primary then contract
  diagnostics order;
- result artifacts: `(artifact_id, relative_path)`;
- result checks: runtime-lock required-check order followed by lexical optional
  names; warnings: unique lexical ReasonCodes.

Array-name uniqueness is enforced within each array. A constraint, diagnostic,
and check may share a human name because they have different typed roles.

For file writing, `os.replace` is the commit point. A failure before replace
sets `committed=False`, leaves an existing destination byte-identical, leaves an
absent destination absent, and cleans the temp file where possible. A directory
`fsync` failure after replace raises `EvaluationPersistenceError(committed=True)`;
the destination contains the complete new canonical bytes but durability is
uncertain. Cleanup failure never hides the primary exception. Callers must
recover/verify after any committed durability error.

## 3. Candidate materialization and three identities

`MaterializationReceipt.scan` is the public host intake seam. It resolves the
caller root once and walks relative components from a held root directory file
descriptor. On Linux/WSL every final read opens with `openat`/`dir_fd` plus
`O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC` (or an equivalent fail-fast platform
primitive), then `fstat`s the opened descriptor, requires one regular file,
hashes bytes from that same descriptor, and checks
the device/inode/size/mtime identity did not drift before close. An unavailable
equivalent, replacement, symlink, `st_nlink != 1`, or identity change fails
closed. It also verifies each entry remains under the root and serializes no
root path or root-derived digest. Its closed payload contains `schema_version`,
`symlink_policy="deny"`, and sorted entries of
`{path, kind="regular_file", sha256}`. Its own canonical `.sha256` is the
inventory identity, so safe relocation leaves it unchanged. C10 repeats this
scan inside its isolated process.

`CandidateArtifact.from_bytes` verifies payload hash against `ArtifactRef`, a
lowercase 40/64-hex code commit, lexical/sorted/unique changed paths, and an
immutable materialization receipt. The candidate artifact path must occur in
the receipt with the same hash. Its readonly properties are `artifact`,
`payload`, `code_commit`, `changed_paths`, `materialization`, and
`candidate_hash`.

Three hashes stay distinct:

1. `ArtifactRef.sha256`: exact candidate payload bytes.
2. `CandidateArtifact.candidate_hash`: SHA-256 of this exact canonical JSON;
   storage ID/path are excluded:

   ```json
   {
     "schema_version":"1.0",
     "artifact_kind":"...",
     "artifact_sha256":"<64hex>",
     "code_commit":"<40-or-64hex>",
     "changed_paths":["..."],
     "materialization_sha256":"<64hex>"
   }
   ```
3. `CandidateValidation.canonical_form_sha256`: plugin-normalized domain meaning
   for exact-duplicate evidence. It is neither a family assignment nor an
   effective trial count.

At validation, artifact kind equals the contract objective artifact type,
contract plugin artifact type, and live plugin artifact type. Changed paths
must match the editable surface and no protected pattern under pinned Arbor's
`fnmatch.fnmatch` semantics. Required literal outputs must occur in the trusted
materialization receipt.

## 4. CandidateValidation and pre-evaluation terminal results

`CandidateValidation.to_dict()` has exactly:

```json
{
  "schema_version": "1.0",
  "status": "valid",
  "contract_hash": "<64hex>",
  "plugin": {"name":"...","version":"...","code_sha256":"<64hex>","artifact_type":"..."},
  "candidate": {"artifact_id":"...","kind":"...","relative_path":"...","sha256":"<64hex>"},
  "candidate_hash": "<64hex>",
  "canonical_form_sha256": "<64hex-or-null>",
  "family_evidence": {"family_hint":null,"method":"exact-ast-v1","evidence_sha256":"<64hex>"},
  "changed_paths": ["..."],
  "checks": [{"name":"candidate.syntax","status":"pass","evidence":"candidate.syntax.ok"}],
  "failure": null
}
```

Status is `valid`, `invalid_candidate`, or `implementation_failure`. Every row
binds the exact contract hash, plugin identity, candidate artifact, candidate
hash, and changed paths. This prevents receipt replay across contracts/plugins.
`valid` requires a canonical hash, all checks pass, and null failure.
`invalid_candidate` requires a failed check and failure type
`invalid_candidate`. `implementation_failure` requires the same failure type;
a previously computed canonical hash may remain, but cannot make it valid.

The three C9 adapters freeze one shared surface check in addition to their
domain checks.  After the lexical ordering required by Section 2, the exact
check-name sets are:

- synthetic: `candidate.kind`, `candidate.surface`, `synthetic.payload`;
- HM1: `candidate.kind`, `candidate.surface`, `hm1.ast`;
- formula alpha: `candidate.kind`, `candidate.surface`,
  `formula.expression`, `formula.public_schema`.

`candidate.surface` is `pass/candidate.surface.ok` exactly when the changed
paths and required outputs satisfy Section 3.  Otherwise it is `fail` and its
evidence is exactly one of `candidate.surface.protected`,
`candidate.surface.outside_editable`, or `candidate.surface.missing_output`.
When surface and domain checks both fail, the surface ReasonCode is the
deterministic failure summary; every failed check remains present in the
receipt.  The common receipt freezer independently repeats the surface check,
so a plugin cannot convert an invalid surface into a valid receipt.

The canonical payload deliberately omits its own ArtifactRef. The host writes it
below `artifacts/validations/`; the receipt ref kind is
`q-arbor.validation-receipt.v1` and its hash equals validation `.sha256`.
`CandidateReceipt.bind` accepts all three statuses and verifies candidate,
contract, plugin, and receipt identities. `ValidatedCandidate.bind` additionally
requires `status=valid`; it is the only candidate type accepted by an
`AuthorizedSplit`.

An `EvaluationRequest` can bind any `CandidateReceipt`, allowing one uniform
terminal record even when evaluation never starts. For invalid or validation-
implementation-failure receipts, `make_candidate_failure_result` maps status to
`invalid_candidate/invalid_candidate` or
`implementation_failure/implementation_failure`; it calls no plugin, split,
evaluator, sink, or resource. All terminal factories require a host-allocated
request and binding, then can be summarized through the common API.

## 5. Plugin protocol, request, runtime lock, and binding

```python
@runtime_checkable
class QuantTaskPlugin(Protocol):
    @property
    def identity(self) -> PluginIdentity: ...
    def validate(
        self, candidate: CandidateArtifact, contract: QuantResearchContract
    ) -> CandidateValidation: ...
    def evaluate(
        self, candidate: ValidatedCandidate, split: AuthorizedSplit
    ) -> EvaluationResult: ...
    def summarize(self, result: EvaluationResult) -> EvaluationSummary: ...
```

The method names/signatures are identical for all adapters. `validate` cannot
read a split. `evaluate` uses only the authorized view/sink/result builder.
`summarize` is a pure projection. Plugins do not mint capabilities, reserve
queries, write ledger events, mutate candidate/tree state, choose admission, or
define a statistical family.

`EvaluationRequest` is exactly the C6 payload. Freeze/load verifies contract,
candidate artifact/hash/receipt, plugin, selected split role/manifest, requested
metrics, and full-match IDs/hashes. A request for an invalid receipt is a
terminal bookkeeping request; it cannot enter an `AuthorizedSplit`.

### VerifiedRuntimeLock

The evaluator ref kind is `q-arbor.evaluator.v1`; config ref kind is
`q-arbor.evaluator-config.v1`. The resolver verifies containment, regular-file
status, and digest at construction and whenever `.verify()` is called. Config
bytes are strict canonical JSON with exact shape:

```json
{
  "schema_version":"1.0",
  "plugin_config":{},
  "policy":{
    "required_check_names":["candidate.identity","cost.reconciled","split.identity"],
    "fold_policy":{"mode":"required","expected_fold_ids":["fold.a","fold.b"],"required_metric_names":["mean_net_return"]},
    "allowed_artifacts":[
      {"kind":"q-arbor.aggregate-metrics.v1","media_type":"application/json"}
    ]
  }
}
```

`VerifiedRuntimeLock.to_dict()` is exactly
`{"schema_version":"1.0","evaluator":ArtifactRef,"config":ArtifactRef,
"policy":<the exact decoded config policy>}`. The policy copy must equal the
config bytes; evaluator/config derived SHA properties are their ArtifactRef
digests and are not extra serialized fields. Thus an independent oracle can
recompute both the lock hash and the two provenance hashes.

Policy names/kinds are sorted unique ReasonCodes. Each artifact media type is a
lowercase RFC 6838 token pair matching
`[a-z0-9][a-z0-9!#$&^_.+-]{0,63}/[a-z0-9][a-z0-9!#$&^_.+-]{0,63}`;
allowed `(kind, media_type)` pairs are unique and lexical. `FoldPolicy.mode` is
`required` or `aggregate_only`; aggregate-only requires empty fold IDs, while
required uses a nonempty unique ordered tuple. Because policy is inside hashed
config bytes, changing checks/folds/artifact kinds changes `config_sha256`.
`plugin_config` is a closed adapter-owned JSON object and is empty for all C9
fixtures; it passes the C7 recursive secret/credential/locator-key guard.
Adapters cannot self-attest evaluator/config digests. C9 factories call
`.verify()` immediately before and after their mock/in-memory evaluation; C10
will repeat live protected-file verification around isolated execution.

`EvaluationBinding.create` takes a `CandidateReceipt`, exact request/contract/
plugin, verified runtime lock, host-allocated `result_id`, allowed contract seed,
and an ArtifactResolver. It is an identity bundle, never an authorization token.
Result-ID uniqueness is local to a binding in C9; C10 makes it durable.
Every `freeze_evaluation_result`, `validate_evaluation_result`, and
`load_evaluation_result` call first invokes `binding.runtime_lock.verify()`.
Pre-existing drift raises `EvaluationIntegrityError`. Each concrete C9 plugin
verifies immediately before its mock computation. Its concrete
`AuthorizedSplit.make_result` verifies again immediately before freezing the
proposed result and once more before returning it. A failure in either of those
post-computation checks discards every proposed metric, fold, statistic, and
artifact and emits `contaminated/contamination`.

That terminal value is built only through the package-private
`_freeze_controlled_evaluation_result(mapping, *, binding,
runtime_drift_observed=True)` seam. It skips the now-impossible live runtime
reverification, but accepts only the exact contaminated minimal-result template
below, revalidates every frozen request/contract/plugin/candidate/provenance
identity against the already verified binding, and rejects non-null metrics,
folds, statistics, artifacts, warnings, or a failure other than
`contamination`. The helper is not exported from `q_arbor.evaluation`; callers
cannot use it to turn pre-execution drift or an arbitrary integrity error into a
result. The returned object carries a private, non-serialized drift attestation
so its exact null payload can still be written atomically while the observed
runtime remains drifted. Every normally frozen result re-verifies before
`write`; the attestation cannot be constructed through a public factory and
does not alter bytes or hash. Public `load_evaluation_result` continues to
re-verify the expected runtime and therefore cannot bless a drifted evaluator.

### Resource and artifact protocols

```python
class SplitDataView(Protocol):
    @property
    def role(self) -> str: ...
    @property
    def data_snapshot_sha256(self) -> str: ...
    @property
    def split_manifest_sha256(self) -> str: ...


class ArtifactResolver(Protocol):
    def read_bytes(self, ref: ArtifactRef) -> bytes: ...
    def verify(self, ref: ArtifactRef) -> None: ...
    def verify_issued(
        self, ref: ArtifactRef, *, request_id: str, runtime_lock: VerifiedRuntimeLock
    ) -> None: ...


class ArtifactSink(Protocol):
    @property
    def issued_refs(self) -> tuple[ArtifactRef, ...]: ...
    def put(self, *, kind: str, media_type: str, content: bytes) -> ArtifactRef: ...


class AuthorizedSplit(Protocol):
    @property
    def request(self) -> EvaluationRequest: ...
    @property
    def contract(self) -> QuantResearchContract: ...
    @property
    def binding(self) -> EvaluationBinding: ...
    @property
    def data(self) -> SplitDataView: ...
    @property
    def artifacts(self) -> ArtifactSink: ...
    def make_result(
        self,
        *,
        status: str,
        primary_metric: MetricValue,
        constraints: Sequence[CheckResult],
        diagnostics: Sequence[MetricValue],
        fold_metrics: Sequence[Mapping[str, object]],
        costs: Mapping[str, object],
        checks: Sequence[CheckResult],
        artifacts: Sequence[ArtifactRef] = (),
        failure: EvaluationFailure | None = None,
        warnings: Sequence[ReasonCode] = (),
    ) -> EvaluationResult: ...
```

`EvaluationSummary.from_result` is the only public summary constructor and is
the shared implementation behind all three plugin `summarize` methods.
`make_result` accepts only the common wrappers and the two frozen closed mapping
shapes for folds/costs; it never accepts an adapter-specific result object or an
arbitrary object whose fields are guessed at runtime.

There is no generic public `AuthorizedSplit` constructor. C10 owns production
minting. C9 adapter modules expose only their fixed development mock/fixture
factories; each requires a `ValidatedCandidate`, `VerifiedRuntimeLock`, and
host-created `ContentAddressedArtifactStore`, scopes its own sink using the
request/event identities, verifies exact development identities, and rejects gate/final
before data/sink access.

The common data view exposes no path, URI, token, credential, environment,
subprocess, or network method. Task-specific views expose closed typed data.
Candidate code never receives a view.

`ContentAddressedArtifactStore` is symlink-safe and create-only. `scope` first
verifies the supplied runtime lock and freezes its complete lock hash, config
hash, and allowed artifact pairs into the create-only issuance record. A request scope
uses `sha256(request_id.encode("utf-8"))` as its directory, never raw request ID,
under `artifacts/evaluations/`. The sink alone chooses IDs/paths/digests. Result
freeze/load calls `verify_issued(ref, request_id=...,
runtime_lock=binding.runtime_lock)`. The store re-verifies that trusted lock and
reconstructs the complete expected scope record from it. The raw scope bytes
must equal the exact canonical record; parsed semantic equality is insufficient.
The store then verifies the request namespace, containment, regular-file state,
allowed `(kind, media_type)` pair, and current digest. It recomputes
`identity_digest = SHA256(canonical({kind, media_type, sha256}))` and requires
exact artifact ID `artifact.<identity_digest>`, exact path
`<hashed-request-scope>/<identity_digest>`, exact issuance-record filename, and
raw issuance bytes equal to canonical `ArtifactRef`. A merely pre-existing file
inside the root is not issued. Duplicate ID/path is rejected.

The request-scope sidecar layout is frozen for recovery and boundary tests:
`.scope.json` is the canonical create-only scope/runtime-lock record, and
`.issued/<sha256(artifact_id UTF-8)>.json` is the canonical create-only
ArtifactRef record. Both live below the hashed request directory and are opened
through the same anchored no-follow directory chain as artifact content; an
existing symlink/non-regular sidecar or parent, unknown/missing field, wrong
schema/config/policy value, or noncanonical encoding fails before artifact
content is trusted. Artifact-content, sidecar, existence-check, and recovery
reads use the same nonblocking close-on-exec final-open rule, so a FIFO/device
cannot block before the regular-file check.

## 6. Provenance and status invariants

Every status has complete C6 provenance. Denied expected identities do not mean
a resource was opened.

```text
candidate_sha256     = CandidateArtifact.candidate_hash
code_commit          = CandidateArtifact.code_commit
data_snapshot_sha256 = contract.data.snapshot_sha256
split_manifest_hash  = request = selected contract split manifest
contract_hash        = contract.sha256
plugin_code_sha256   = contract = request = live plugin identity
evaluator_sha256     = VerifiedRuntimeLock evaluator ref hash
config_sha256        = VerifiedRuntimeLock config ref hash
seed                 = EvaluationBinding seed
```

`AuthorizedSplit.make_result` injects result/request/split/provenance fields;
plugins supply domain observations. Direct freeze/load checks the same closure.

| status | permitted failure |
|---|---|
| `success` | null |
| `invalid_candidate` | `invalid_candidate` or `constraint_violation` |
| `implementation_failure` | `implementation_failure` |
| `access_denied` | `access_denied` |
| `evaluation_failure` | `evaluation_failure`, `timeout`, or `interruption` |
| `incomparable` | `incomparable` |
| `contaminated` | `contamination` |

Success requires a finite primary (zero/negative allowed), exact metric
name/direction/unit, all constraints and required checks pass, complete ordered
diagnostics, the runtime fold policy, nonnegative transaction cost/turnover,
contract cost hash, and exact `Decimal(str(gross)) -
Decimal(str(transaction_cost)) == Decimal(str(net))`. Every referenced artifact
must be issued and reverified.

Every non-success has null primary and no fold metric named as the contract
primary. `failure_type=none` is never serialized. A hard-constraint failure is
`invalid_candidate/constraint_violation`; it may retain aggregate diagnostics
and actual ordered constraint states but no primary/fold-primary projection.
Partial coverage, missing cost semantics, or a domain-schema/comparison
prerequisite failure is `incomparable`. Any expected identity/digest mismatch
before execution is an integrity failure and broker deny; if first observed
after execution it is `contaminated`. Timeout is `evaluation_failure/timeout`. Detected leakage or
protected drift is `contaminated/contamination` with suspect values/artifacts
suppressed.

Host-created candidate-failure, access-denied, implementation-failure,
evaluation-failure, and contaminated minimal results have one exact null shape:
constraints in contract order as `not_observed`, diagnostics in contract order
with null values, empty folds/artifacts/statistics, null cost values plus exact
cost hash, and runtime required checks as `not_observed`. For each null
diagnostic, the required check set contains
`diagnostic.<first16(sha256(metric-name UTF-8))>.observed`; the runtime config
therefore freezes this deterministic name. Factories only vary IDs, provenance,
status/failure, and the supplied ReasonCode.

The two pre-split terminal factories use this exact template: primary copies the
contract name/direction/unit with `value=null`; each contract constraint is
`{"name":name,"status":"not_observed","evidence":"evaluation.not_observed"}`;
each diagnostic copies name/direction/unit with `value=null`; folds and artifacts
are `[]`; costs are `gross/transaction_cost/net/turnover=null` plus the exact
contract cost hash; every runtime required check is `not_observed` with evidence
`evaluation.not_observed`; `statistical_diagnostics=[]`; `warnings=[]`; failure
uses the mapped type, the supplied ReasonCode as `summary`, and
`evidence_ids=[]`. `make_candidate_failure_result` accepts only a non-valid
`CandidateReceipt` and maps its status exactly. `make_access_denied_result`
accepts only a `ValidatedCandidate` binding and always maps to
`access_denied/access_denied`. Both reject an inapplicable receipt before
creating bytes.

`statistical_diagnostics` is exactly `[]` for every C9-created result. Null and
planted fixtures are mechanism smoke only; no power, Type-I, FDR/FWER, or
benchmark statement is allowed.

### Operation-to-failure ownership

| observation | direct model call | controlled plugin path |
|---|---|---|
| malformed JSON/schema/cross-invariant | decode/schema/invariant exception | no result if request cannot be trusted |
| expected identity/hash mismatch before execution | integrity exception | broker terminal deny; plugin/data zero calls |
| sink/resource boundary failure during execution | boundary exception | `evaluation_failure` unless leakage/identity risk makes `contaminated` |
| evaluator/candidate runtime exception | n/a | sanitized `implementation_failure` |
| evaluator service/timeout | n/a | `evaluation_failure` / timeout |
| persistence failure | persistence exception with commit flag | no success/admission; recover and verify |
| invalid candidate before split | validation value | candidate-failure factory; split/plugin-evaluate zero calls |

`KeyboardInterrupt`, `SystemExit`, and process-fatal signals are never converted
to success. Arbitrary exception text is discarded; only a fixed ReasonCode is
stored.

## 7. Deterministic summary

`EvaluationSummary` is a mechanical projection with exact keys:

```text
schema_version, result_id, request_id, status, split_role, primary_metric,
constraints[{name,status}], diagnostics[MetricValue],
fold_metrics[{fold_id,metrics}], costs{gross,transaction_cost,net,turnover},
checks[{name,status}], failure_type, failure_code, warning_codes
```

It preserves source array order. It omits artifacts/IDs/paths, provenance,
hashes, seed, fold time ranges, check evidence, free text, rows, stdout, and
stderr. `failure_code` is the ReasonCode stored in failure summary. The same
validated result always yields identical summary bytes/hash. C10 may further
redact gate output. A final summary is terminal-only and cannot feed prompts,
tree observations, propagation, proposals, or another request.

### C8 evidence binding

`validate_evaluation_evidence(result, *, request, node, evidence)` is a pure
read-only seam over `EvaluationResult`, `EvaluationRequest`, C8
`QuantHypothesisNode`, and one proposed C6 `EvidenceRef` mapping. It returns
`None` only when:

- result request ID and split equal the request, while result provenance
  `candidate_sha256`, `contract_hash`, `plugin_code_sha256`, and
  `split_manifest_hash` equal the corresponding request identities;
- `request.node_id == node.id` and `request.attempt_id` occurs in
  `node.attempt_ids`;
- evidence has `level=observed`, `status=valid`, the same attempt/result/split,
  and every evidence artifact is byte-identical to a result artifact;
- result status is success, failure is null, the primary is finite, and every
  hard constraint/runtime-required check passes;
- node scope data snapshot and cost-model hashes equal result provenance/costs;
  a non-null node candidate artifact equals the request candidate;
- if node score is already non-null, it equals the result primary exactly.

The evidence need not already occur in the node, so C11 can validate before its
event-first mutation. Any non-success, failed hard check, ID/scope/artifact
mismatch, or score mismatch raises `EvaluationIntegrityError` and leaves the
node unchanged. Finite zero and negative primary values are valid and are never
tested by truthiness.

## 8. Adapter contracts

### 8.1 SyntheticSignalPlugin

`q_arbor.plugins.synthetic` exports:

```python
class SyntheticSplitData(SplitDataView): ...
class SyntheticSignalPlugin(QuantTaskPlugin):
    @classmethod
    def create(cls, identity: PluginIdentity) -> SyntheticSignalPlugin: ...

canonical_synthetic_candidate(*, signal_column: str) -> bytes
synthetic_fixture_identities() -> Mapping[str, str]
synthetic_contract_draft(*, plugin_identity, baseline_ref) -> dict
make_synthetic_development_split(
    request, contract, candidate, plugin, runtime_lock, *,
    result_id, evaluation_seed, artifact_store, produced_by_event_id,
) -> AuthorizedSplit
```

Candidate kind is `q-arbor.synthetic-signal.v1`; the only payloads are closed
JSON `{"schema_version":"1.0","kind":"signal","signal_column":X}` where X
is `null_signal` or `planted_signal`. They cannot name data, split, scenario,
seed, path, evaluator, cost model, metric, output, or code.

The exported fixture identity helper returns only hashes/IDs, never rows. The
mapping has exactly six keys, each a lowercase 64-hex SHA-256:
`data_snapshot_sha256`, `data_schema_sha256`,
`development_manifest_sha256`, `gate_manifest_sha256`,
`final_manifest_sha256`, and `cost_model_sha256`. The latter three manifests are
distinct; gate/final values identify public opaque placeholder manifests and do
not create a data view or access path. The
split factory accepts no external rows/scenario and internally regenerates two
four-row folds. Position is the signal; gross is mean
`position*forward_return`; turnover is mean absolute position change from zero
at each fold start; cost is `0.001*turnover`; fold net is gross minus cost; the
primary is median fold net.

| candidate | fold gross | turnover | cost | fold net | primary |
|---|---|---:|---:|---|---:|
| null | 0, 0 | 0.75 | 0.00075 | -0.00075, -0.00075 | -0.00075 |
| planted | 0.02, 0.025 | 1.75 | 0.00175 | 0.01825, 0.02325 | 0.02075 |

Snapshot/manifest canonical bytes are internal constants regenerated and
checked against the contract. The factory accepts only development and a
prebuilt store, then creates the request-scoped sink itself. Raw rows/targets
are never serialized. This ordering is known-
truth interface evidence only.

### 8.2 HM1FuturesPlugin

`q_arbor.plugins.hm1` exports:

```python
class HM1EngineOutput: ...
class HM1SplitData(SplitDataView): ...
class HM1FuturesPlugin(QuantTaskPlugin):
    @classmethod
    def create(cls, identity: PluginIdentity) -> HM1FuturesPlugin: ...

HM1EngineOutput.from_mapping(mapping) -> HM1EngineOutput
```

Engine output has exact keys: `schema_version`, `status` (`complete`,
`implementation_failure`, `evaluation_failure`, `timeout`, `incomparable`),
`portfolio_daily_sharpe`, `annualized_return`, `max_drawdown`, `calmar`,
`win_rate`, `trade_count`, `coverage_count`, `expected_coverage_count`,
`cost_semantics` (C9 constant `unavailable`), and sorted `warning_codes`.
Numeric values are finite or null; counts are nonnegative integers. It has no
path, command, module, raw-row, stdout/stderr, or arbitrary-detail field.

The engine-output truth table is exact:

| engine status | field requirements | C6 result |
|---|---|---|
| `complete` | all five metric values and all three counts non-null; expected coverage >=1 | coverage mismatch first yields `incomparable/incomparable` with code `hm1.coverage_mismatch`; exact coverage then yields `incomparable/incomparable` with code `hm1.cost_semantics_unavailable` |
| `implementation_failure` | all metrics and observed counts null; expected coverage >=1 | `implementation_failure/implementation_failure`, code `hm1.implementation_failure` |
| `evaluation_failure` | all metrics and observed counts null; expected coverage >=1 | `evaluation_failure/evaluation_failure`, code `hm1.evaluation_failure` |
| `timeout` | all metrics and observed counts null; expected coverage >=1 | `evaluation_failure/timeout`, code `hm1.timeout` |
| `incomparable` | all metrics and observed counts null; expected coverage >=1 | `incomparable/incomparable`, code `hm1.incomparable` |

The three counts are `trade_count`, `coverage_count`, and
`expected_coverage_count`; in non-complete rows the first two are null. Warning
codes remain sorted ReasonCodes. Engine status is resolved before any coverage
test; coverage precedence applies only to `complete`. No text-only or ambiguous
metric is parsed.

Candidate kind is `q-arbor.hm1-strategy-python.v1`. Validation UTF-8 decodes and
AST-parses without import. Top level permits one optional docstring, imports
only from `math`, `typing`, `dataclasses`, `research_env.backtest.strategy`, or
`research_env.backtest.models`, JSON-scalar constant assignments, and exactly
one `CandidateStrategy(BaseStrategy)` class. That class requires
`on_bar(self, context)` and permits the audited HM1 lifecycle signatures
`on_start(self, bars)` and `on_finish(self, result)`. Nested imports, `global`,
`nonlocal`, dunder attribute access, calls to
`open/eval/exec/compile/__import__/input`, and names or
attribute roots `os`, `sys`, `subprocess`, `socket`, `pathlib`, `shutil`,
`requests`, `httpx`, `urllib`, or `importlib` are rejected. This deterministic
static guard is not a sandbox; C10 owns runtime confinement.

`q_arbor.plugins.hm1.testing` exports:

```python
make_hm1_mock_development_split(
    request, contract, candidate, plugin, runtime_lock, *,
    result_id, evaluation_seed, artifact_store, produced_by_event_id,
    engine_output, untrusted_failure_detail=None,
) -> AuthorizedSplit
```

It takes a closed `HM1EngineOutput`, valid identities/runtime lock, and prebuilt
store. It creates the request-scoped sink internally. The optional untrusted
detail exists only in this testing module: when
present the mock view raises an internal failure containing it, so qualification
can prove the plugin emits only a fixed ReasonCode. It is never serialized or
returned. The factory has no locator or command input and rejects gate/final.
Every C9 HM1 result is non-success with null primary because cost semantics are
unavailable; fabricated aggregates may appear only as diagnostics of an
`incomparable` result.

Legacy `dev` maps to Q development only after C10 authorization for real data;
legacy `test` maps only to Q gate; HM1 has no final and it remains sealed/
unavailable. C9 never locates an HM1 workspace, reads environment variables,
imports a candidate, reads/hashes raw files, or invokes an HM1 evaluator.

### 8.3 FormulaAlphaPlugin

`q_arbor.plugins.formula_alpha` exports:

```python
class PublicFormulaSchema: ...
class FormulaMockOutcome(str, Enum):
    BACKEND_UNAVAILABLE = "backend_unavailable"
    SCHEMA_INCOMPATIBLE = "schema_incompatible"
class FormulaAlphaSplitData(SplitDataView): ...
class FormulaAlphaPlugin(QuantTaskPlugin):
    @classmethod
    def create(cls, identity, public_schema) -> FormulaAlphaPlugin: ...

PublicFormulaSchema.from_mapping(mapping) -> PublicFormulaSchema
```

Public schema exact shape is
`{"schema_version":"1.0","fields":[{"name":Identifier,"dtype":Identifier}]}`;
fields are sorted and unique. Its canonical `.sha256` must equal
`contract.data.schema_sha256` before validation. It is an already materialized
in-memory value; C9 performs no filesystem, environment, import, registry,
network, or backend discovery.

Candidate kind is `q-arbor.formula-alpha.v1`; grammar is:

```text
document := {"schema_version":"1.0","expression":expr}
expr := {"op":"field","name":Identifier}
      | {"op":"constant","value":finite-number}
      | {"op":"lag","periods":integer[1,252],"arg":expr}
      | {"op":"neg","arg":expr}
      | {"op":"add"|"sub"|"mul"|"div","left":expr,"right":expr}
```

Objects are closed; depth <=16; node count <=256; fields must be public-schema
members. Canonicalization preserves structure/operand order and claims no
algebraic equivalence.

`q_arbor.plugins.formula_alpha.testing` exports:

```python
make_formula_alpha_mock_development_split(
    request, contract, candidate, plugin, runtime_lock, *,
    result_id, evaluation_seed, artifact_store, produced_by_event_id, outcome,
) -> AuthorizedSplit
```

It accepts one closed `FormulaMockOutcome`, identities/runtime lock, and
prebuilt store; it scopes the sink internally. It has no success outcome or
locator and rejects gate/final. Backend
unavailable becomes `implementation_failure`; schema incompatible becomes
`incomparable`; every C9 formula result has null primary. Real data, PIT
semantics, baseline, backend, score, and performance belong to Goal B.

## 9. C9/C10 boundary and qualification

| concern | C9 | C10 |
|---|---|---|
| candidate syntax/canonical form | validate/receipt | duplicate/family ledger |
| typed result and intrinsic binding | implement | anchor/replay |
| domain calculation/mapping | fixed adapters | authorize isolated launch |
| split resource | consume view | capability, registry, mount, budget |
| artifact bytes | scoped sink/resolver | process filtering and durable event |
| runtime identity | verified lock | protected live attestation |
| deny/contamination | typed factory/validator | detect, quarantine, append event |
| statistical family | empty diagnostics | freeze family/count/assumptions |
| summary | closed deterministic projection | gate/final release redaction |

Required tests cover strict decode/hash/immutability/persistence, every status
and factory, zero/negative success, all identity edges, evaluator/config
reverification, metric/fold/cost invariants, split and artifact escapes,
symlink/tamper/canary cases, exact synthetic values, mock-only HM1/formula
failure paths, and a parameterized `validate -> evaluate -> summarize`
controller with no task-kind branch. C7/C8 regressions, frozen schema hash,
build/clean install, clean Arbor/Q worktrees, unchanged dirty HM1 worktrees, and
sealed final are mandatory exit evidence.

Passing C9 proves a typed development evaluator and adapter compatibility. It
does not prove capability enforcement, ledger/query accounting, gate/final
isolation, false-discovery control, a live Arbor refinement loop, a real HM1 or
formula result, C13 naming qualification, or the `Q-Arbor prototype` name.
