import json, random, joblib
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, f1_score
random.seed(42)

rows=[json.loads(l) for l in open("data.jsonl",encoding="utf-8") if l.strip()]
X=[f"{r.get('error_message','')} [CMD] {r.get('command','')}" for r in rows]
y=[r["error_type"] for r in rows]
Xtr,Xte,ytr,yte=train_test_split(X,y,test_size=0.2,random_state=42,stratify=y)

def noise(s):
    s=list(s); s=[c for c in s if random.random()>0.08]
    s=[c.upper() if (c.isalpha() and random.random()<0.1) else c for c in s]
    t="".join(s)
    if random.random()<0.3: t=t[:max(5,int(len(t)*0.6))]
    return t

# char n-grams (3-5) = robust to typos/truncation
clf=Pipeline([("tfidf",TfidfVectorizer(analyzer="char_wb",ngram_range=(3,5),min_df=2,sublinear_tf=True)),
              ("svm",LinearSVC(C=1.0))]).fit(Xtr,ytr)

cp=clf.predict(Xte); npred=clf.predict([noise(s) for s in Xte])
print(f"Clean test -> Acc {accuracy_score(yte,cp)*100:5.2f}% | MacroF1 {f1_score(yte,cp,average='macro')*100:5.2f}%")
print(f"Noisy test -> Acc {accuracy_score(yte,npred)*100:5.2f}% | MacroF1 {f1_score(yte,npred,average='macro')*100:5.2f}%")
joblib.dump(clf,"error_classifier.joblib")
print("Saved -> error_classifier.joblib")
