# acvp_fetch.py  (replace pick_one with this; add pick_many if you like)
import io, os, zipfile, urllib.request, pathlib, json
ACVP_ZIP_URL = "https://codeload.github.com/usnistgov/ACVP-Server/zip/refs/heads/master"
CACHE_ROOT = pathlib.Path(__file__).resolve().parent / ".acvp_cache"

def _ensure_repo_cached():
    CACHE_ROOT.mkdir(exist_ok=True)
    marker = CACHE_ROOT / ".unzipped.ok"
    if marker.exists():
        return
    print("[ACVP] downloading ACVP-Server (first run only)…")
    data = urllib.request.urlopen(ACVP_ZIP_URL).read()
    zf = zipfile.ZipFile(io.BytesIO(data))
    zf.extractall(CACHE_ROOT)
    marker.touch()

def _json_root():
    return CACHE_ROOT / "ACVP-Server-master" / "gen-val" / "json-files"

def read_json(path: pathlib.Path):
    with open(path, "r") as f:
        return json.load(f)

def pick_one_rel(rel_glob: str, *name_contains: str) -> pathlib.Path:
    """
    Search **recursively** under gen-val/json-files/<rel_glob> (glob allowed)
    and return the first JSON whose filename contains all substrings.
    """
    _ensure_repo_cached()
    base = _json_root()
    candidates = list(base.glob(rel_glob))  # can be "ML-DSA-sigGen-FIPS204/*.json" etc.
    if not candidates:
        raise FileNotFoundError(f"No folder(s) matching: {rel_glob}")
    for p in sorted(candidates):
        if p.is_dir():
            for j in sorted(p.rglob("*.json")):  # recurse
                s = j.name.lower()
                if all(sub.lower() in s for sub in name_contains):
                    return j
        elif p.suffix.lower() == ".json":
            s = p.name.lower()
            if all(sub.lower() in s for sub in name_contains):
                return p
    raise FileNotFoundError(f"No JSON under {rel_glob} matching {name_contains}")
