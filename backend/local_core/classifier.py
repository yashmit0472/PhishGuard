"""Portable character TF-IDF + logistic regression inference, no pickle or downloads."""
import json
import math
from collections import Counter
from pathlib import Path


def grams(text):
    text = ' '.join(text.lower().split())
    return Counter(text[i:i+n] for n in (3, 4, 5) for i in range(max(0, len(text)-n+1)))


class TextModel:
    def __init__(self, data):
        self.data = data
        self.version = data['version']

    @classmethod
    def load(cls, path):
        data = json.loads(Path(path).read_text(encoding='utf-8'))
        if data.get('schema') != 1 or data.get('evaluation_only', True):
            raise ValueError('Model is missing validation or is evaluation-only.')
        return cls(data)

    def predict(self, text):
        counts = grams(text[:100000])
        vocab = self.data['vocabulary']
        values = [(vocab[g], count * self.data['idf'][vocab[g]]) for g, count in counts.items() if g in vocab]
        norm = math.sqrt(sum(value * value for _, value in values)) or 1
        logit = self.data['intercept'] + sum(self.data['weights'][i] * value / norm for i, value in values)
        return 1 / (1 + math.exp(-max(-50, min(50, logit))))
