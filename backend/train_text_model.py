"""Reproducible model evaluation. JSONL rows: text, label (0/1), language, group.

Training dependencies are build-only. Models export numeric JSON, not executable pickle.
Demo mode never produces a model accepted by the application.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import precision_recall_fscore_support, confusion_matrix


def canonical(text):
    text = re.sub(r'https?://\S+', 'URL', text.lower())
    text = re.sub(r'\d+', 'N', text)
    return ' '.join(text.split())


def train(source, output, demo=False):
    rows, seen = [], {}
    for line in Path(source).read_text(encoding='utf-8').splitlines():
        row = json.loads(line)
        key = canonical(row['text'])
        if row['label'] not in (0, 1) or not row.get('group'):
            raise ValueError('Each sample needs a binary label and campaign/source group.')
        if key in seen:
            if seen[key] != row['label']:
                raise ValueError('Conflicting labels for duplicate content.')
            continue
        seen[key] = row['label']
        rows.append(row)
    if len(rows) < 12:
        raise ValueError('At least 12 distinct samples required even for a smoke evaluation.')
    split = GroupShuffleSplit(n_splits=1, test_size=.3, random_state=42)
    train_idx, test_idx = next(split.split(rows, groups=[r['group'] for r in rows]))
    xtrain = [' '.join(rows[i]['text'].lower().split()) for i in train_idx]
    ytrain = [rows[i]['label'] for i in train_idx]
    xtest = [' '.join(rows[i]['text'].lower().split()) for i in test_idx]
    ytest = [rows[i]['label'] for i in test_idx]
    vector = TfidfVectorizer(analyzer='char', ngram_range=(3,5), max_features=30000, lowercase=True)
    model = LogisticRegression(random_state=42, max_iter=1000, class_weight='balanced')
    model.fit(vector.fit_transform(xtrain), ytrain)
    pred = model.predict(vector.transform(xtest)).tolist()
    def metrics(indices):
        truth, guesses = [ytest[i] for i in indices], [pred[i] for i in indices]
        if not truth:
            return {'samples': 0, 'status': 'not evaluated'}
        p,r,f,_ = precision_recall_fscore_support(truth, guesses, average='binary', zero_division=0)
        return {'samples': len(truth), 'precision':float(p),'recall':float(r),'f1':float(f),
                'confusion_matrix_tn_fp_fn_tp': confusion_matrix(truth, guesses, labels=[0,1]).tolist(),
                'false_positive_ids':[int(test_idx[i]) for i in indices if ytest[i]==0 and pred[i]==1],
                'false_negative_ids':[int(test_idx[i]) for i in indices if ytest[i]==1 and pred[i]==0]}
    version = hashlib.sha256(Path(source).read_bytes()).hexdigest()[:12]
    data={'schema':1,'version':version,'evaluation_only':demo,'vocabulary':{k:int(v) for k,v in vector.vocabulary_.items()},
          'idf':vector.idf_.tolist(),'weights':model.coef_[0].tolist(),'intercept':float(model.intercept_[0])}
    Path(output).parent.mkdir(parents=True,exist_ok=True)
    Path(output).write_text(json.dumps(data),encoding='utf-8')
    report={'dataset_sha256':hashlib.sha256(Path(source).read_bytes()).hexdigest(),'seed':42,
            'train_samples':len(train_idx),'test_samples':len(test_idx),'deduplicated_samples':len(rows),
            'evaluation_only':demo,'overall':metrics(range(len(test_idx))),
            'languages':{lang:metrics([j for j,i in enumerate(test_idx) if rows[i].get('language')==lang]) for lang in ('en','hi','hinglish')},
            'limitations':'Small authored fixtures are smoke tests only, not general accuracy evidence. Campaign groups are disjoint. Review source grouping, near duplicates and a separate representative holdout before deployment.'}
    Path(output).with_suffix('.evaluation.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('source');p.add_argument('output');p.add_argument('--demo',action='store_true');a=p.parse_args();train(a.source,a.output,a.demo)
