# Flag Detection

## Overview
Centralized pattern registry for detecting CTF flags across platforms, plus auto-submission to CTF platform APIs. Two classes: `CTFFlagDetector` for scanning responses and text, and `CTFFlagSubmitter` for submitting captured flags.

## CTFFlagDetector
File: `backend/core/ctf_flag_detector.py`

### Constructor
```python
CTFFlagDetector(custom_patterns: Optional[List[str]] = None)
```
- Initializes `patterns` dict from `BUILTIN_FLAG_PATTERNS` (deep copy)
- Initializes `_seen_flags` set for deduplication
- Initializes `captured_flags` list, `start_time`, `first_flag_time`, `_flag_timeline`
- Compiles user-supplied custom regex strings into a `"custom"` platform key (invalid regexes silently skipped)

### Built-in Pattern Registry
Compiled `re.Pattern` objects keyed by platform:

| Platform | Patterns |
|----------|----------|
| netwars | `(?:flag\|FLAG)\{[^\}]{1,200}\}` |
| htb | `HTB\{[^\}]{1,200}\}`, bare 32-char hex (`[a-f0-9]{32}` with negative lookbehind/ahead), bare 64-char hex (`[a-f0-9]{64}` with negative lookbehind/ahead) |
| tryhackme | `[Tt][Hh][Mm]\{[^\}]{1,200}\}` (case-insensitive per-character) |
| portswigger | `Congratulations,?\s+you\s+solved\s+the\s+lab` (IGNORECASE), `class\s*=\s*["\']congratulations-message["\']` (IGNORECASE) |
| picoctf | `picoCTF\{[^\}]{1,200}\}` |
| metactf | `MetaCTF\{[^\}]{1,200}\}` |
| generic | `[Cc][Tt][Ff]\{[^\}]{1,200}\}` (case-insensitive per-character) |

### CapturedFlag Dataclass
```python
@dataclass
class CapturedFlag:
    flag_value: str       # The matched flag string
    platform: str         # Platform key (netwars, htb, custom, etc.)
    source: str           # "body", "header", or "log"
    found_in_url: str = ""
    found_in_field: str = ""     # "response_body", header name, or empty
    request_method: str = ""
    request_payload: str = ""    # Truncated to 500 chars
    timestamp: str = ""          # ISO 8601 UTC format
    finding_id: str = ""
    submitted: bool = False      # Updated by CTFFlagSubmitter
    submit_message: str = ""     # Response from platform on submission
```

### Key Methods

#### scan_response()
```python
def scan_response(self, response_dict: dict, request_url: str = "", method: str = "", payload: str = "") -> List[CapturedFlag]
```
Scans an HTTP response for flag patterns:
1. Extracts `body` (string) and `headers` (dict) from `response_dict`
2. For each platform and pattern: runs `finditer()` on body
3. For each header value: runs `finditer()` on header value string
4. New (non-duplicate) matches create `CapturedFlag` instances with source `"body"` or `"header"`
5. Updates `first_flag_time` on first capture
6. Appends to `_flag_timeline` with elapsed seconds
7. Returns list of newly captured flags only

#### scan_text()
```python
def scan_text(self, text: str, source: str = "log", url: str = "") -> List[CapturedFlag]
```
Scans arbitrary text (log messages, etc.) for flag patterns:
1. For each platform and pattern: runs `finditer()` on text
2. New matches create `CapturedFlag` with the specified `source`
3. Appends directly to `captured_flags` list
4. Returns list of newly captured flags

#### register_flag()
```python
def register_flag(self, captured: CapturedFlag) -> bool
```
Manually register a pre-constructed `CapturedFlag`. Returns `True` if new, `False` if duplicate.

#### to_serializable()
```python
def to_serializable(self) -> List[dict]
```
Returns list of `CapturedFlag` dicts (via `dataclasses.asdict`).

#### get_metrics()
```python
def get_metrics(self) -> dict
```
Returns:
```python
{
    "flags_captured": int,          # Total unique flags
    "unique_platforms": List[str],  # Distinct platform keys
    "time_to_first_flag": float|None,  # Seconds from start to first flag
    "elapsed_seconds": float,       # Total elapsed time
    "flag_timeline": List[dict],    # [{flag, platform, elapsed_seconds}, ...]
}
```

### Deduplication
- `_seen_flags` set tracks `flag_value` strings
- Same flag value is never captured twice, regardless of source (body, header, log) or URL
- Checked via `if flag_val not in self._seen_flags` before creating `CapturedFlag`

### Timeline
- `start_time` recorded at `__init__` via `time.time()`
- `first_flag_time` set on first capture (any method)
- Each capture appended to `_flag_timeline` with:
  - `flag`: flag value truncated to 80 chars
  - `platform`: platform key
  - `elapsed_seconds`: rounded to 2 decimal places, relative to `start_time`

## CTFFlagSubmitter
File: `backend/core/ctf_flag_submitter.py`

### Constructor
```python
CTFFlagSubmitter(submit_url: str, platform_token: str = "")
```
- `submit_url`: CTF platform flag submission endpoint (trailing slash stripped)
- `platform_token`: Bearer token for platform API auth (sent as `Authorization: Bearer <token>` header)

### submit_flag()
```python
async def submit_flag(self, flag_value: str, session: aiohttp.ClientSession) -> Dict
```
Returns `{"success": bool, "message": str, "flag_value": str}`.

Submission strategy -- tries multiple JSON body formats in order:
1. `{"flag": flag_value}`
2. `{"answer": flag_value}`
3. `{"submission": flag_value}`
4. `{"key": flag_value}`
5. Fallback: form-encoded `flag=flag_value`

For each attempt:
- POST to `submit_url` with `ssl=False` and 5-second timeout
- Headers: `User-Agent: sploit.ai/3.0` + optional `Authorization: Bearer <token>`

**Success detection**:
- HTTP 200/201 with response body containing any of: "correct", "success", "accepted", "solved", "already"
- HTTP 200/201/400 with "already" in body (previously submitted flag, still counts as success)

**Failure**: If all 5 formats fail, returns `{"success": False, "message": "Flag not accepted by platform"}`.

### submit_all()
```python
async def submit_all(self, flags: List[CapturedFlag], session: aiohttp.ClientSession) -> List[Dict]
```
Iterates over `flags` list, calls `submit_flag()` for each, returns list of result dicts. Returns empty list if no `submit_url` or no flags.

Note: Submission is sequential (not parallel) to avoid overwhelming the CTF platform and to handle rate limits gracefully.

### Integration with CTFCoordinator
In `CTFCoordinator._submit_captured_flags()`:
1. Get captured flags from `self.flag_detector.captured_flags`
2. Create `CTFFlagSubmitter(self.ctf_submit_url, self.ctf_platform_token)`
3. Create shared `aiohttp.ClientSession` with `ssl=False`
4. Call `submitter.submit_all(flags, session)`
5. Update each `CapturedFlag` object's `submitted` and `submit_message` fields from results
6. Log accepted/rejected counts
