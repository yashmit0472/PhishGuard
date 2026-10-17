import json
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from local_core.classifier import TextModel


class PortableTests(unittest.TestCase):
    def test_demo_model_cannot_be_enabled(self):
        path=Path(__file__).resolve().parents[2]/'docs/evaluation/demo-model.json'
        with self.assertRaises(ValueError):TextModel.load(path)

    def test_exported_inference_matches_sklearn(self):
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        texts=['meeting at noon','see you tomorrow','send password immediately','pay fee to claim lottery']
        v=TfidfVectorizer(analyzer='char',ngram_range=(3,5));x=v.fit_transform(texts)
        m=LogisticRegression(random_state=42).fit(x,[0,0,1,1])
        portable=TextModel({'version':'test','vocabulary':v.vocabulary_,'idf':v.idf_.tolist(),'weights':m.coef_[0].tolist(),'intercept':float(m.intercept_[0])})
        for text in texts:
            self.assertAlmostEqual(portable.predict(text),m.predict_proba(v.transform([text]))[0,1],places=10)


if __name__=='__main__':unittest.main()
