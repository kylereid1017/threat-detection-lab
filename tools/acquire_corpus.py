import zipfile, os, shutil, hashlib

z = os.path.expandvars(r"$LOCALAPPDATA/Temp/bootstrap-icons.zip")
archive_sha256 = "999021e12fab5c9ede5e4e7072eb176122be798b2f99195acf5dda47aef8fc93"

# verify pinned hash before trusting the archive
h = hashlib.sha256(open(z, "rb").read()).hexdigest()
assert h == archive_sha256, f"hash mismatch: {h}"
print("hash verified:", h)

dest = os.path.join(os.getcwd(), "corpus", "benign")
os.makedirs(dest, exist_ok=True)
with zipfile.ZipFile(z) as zf:
    svg = sorted(n for n in zf.namelist() if n.lower().endswith(".svg"))
    for n in svg:
        with zf.open(n) as src, open(os.path.join(dest, os.path.basename(n)), "wb") as out:
            shutil.copyfileobj(src, out)
print("extracted:", len(svg))