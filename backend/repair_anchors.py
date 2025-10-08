# save as repair_anchors.py and run: python repair_anchors.py
import csv, os

ANCHORS_PATH = os.path.join(os.path.dirname(__file__), "anchors.csv")
if not os.path.exists(ANCHORS_PATH):
    print("anchors.csv not found")
    raise SystemExit(1)

rows = []
with open(ANCHORS_PATH, "r", encoding="utf-8") as f:
    rdr = csv.reader(f)
    header = next(rdr, None)
    for r in rdr:
        # if row longer than header, keep extras in last column as joined string
        if len(r) > len(header):
            main = r[:len(header)]
            extras = r[len(header):]
            main[-1] = main[-1] + " | EXTRA: " + ", ".join(extras)
            rows.append(main)
        else:
            rows.append(r)

# write back safely to a new file then replace
tmp = ANCHORS_PATH + ".fixed"
with open(tmp, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(header)
    for r in rows:
        w.writerow(r)

print("Wrote", tmp, "- inspect and replace anchors.csv if OK.")
