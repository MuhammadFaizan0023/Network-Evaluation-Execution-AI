"""Fast offline validation: load the model ONCE and score synthetic flows for
every scenario. Usage: python score_all.py [count]"""
import os, sys, collections
import numpy as np, pandas as pd, joblib
from schema import IOT_FEATURE_COLS
import gen_testcase as g

MODELS = r"D:\VS JAVA\NEXA-FYP2\Models"
count = int(sys.argv[1]) if len(sys.argv) > 1 else 400

model = joblib.load(os.path.join(MODELS, "multiclass_xgb_model.pkl"))
le = joblib.load(os.path.join(MODELS, "label_encoder.pkl"))
order = list(model.feature_names_in_)

scenarios = ["benign", "iotdos", "iotddos", "iotslowloris", "iotbruteforce",
             "iotmitm", "iotevasion", "iotc2beac", "iotexfil", "iottlsssl"]

print("%-14s %-12s %7s %7s" % ("scenario", "label", "hit%", "conf"))
tot = 0.0
for s in scenarios:
    prof = g.load_profile(s)
    x = g.sample_rows(prof, count)
    df = pd.DataFrame(x, columns=IOT_FEATURE_COLS)
    pred = le.inverse_transform(model.predict(df[order]))
    conf = model.predict_proba(df[order]).max(axis=1)
    label = prof["label"]
    hit = 100.0 * np.mean(pred == label)
    tot += hit
    top = collections.Counter(pred).most_common(2)
    topstr = " ".join("%s=%d" % (k, v) for k, v in top)
    print("%-14s %-12s %6.1f%% %6.3f   %s" % (s, label, hit, conf.mean(), topstr))
print("mean hit%%: %.1f" % (tot / len(scenarios)))
