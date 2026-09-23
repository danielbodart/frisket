"""Documents made to find where two GraphQL readers disagree: the seeds in
../../internal/graphql/testdata/clients.json and the corpus below, edited at
random, and documents generated around the places a mutation could hide --
comments, strings, block strings, fragments, and whitespace one lexer ends a
line at and another does not.

    python3 generate.py N SEED > docs.json
"""
import json, os, random, sys

rnd = random.Random(int(sys.argv[2]))
N = int(sys.argv[1])
here = os.path.dirname(os.path.abspath(__file__))
seeds = json.load(open(os.path.join(here, "seeds.json")))
seeds += [c["query"] for c in json.load(open(os.path.join(here, "../../internal/graphql/testdata/clients.json")))]
SNIPS = ['\r', '\n', '\r\n', '\t', ' ', ',', '#', '# x', '"', '"""', '\\"""', '\\', '\\u', '\\u0022', '\\"', '\ufeff', '\xa0',
         '\u2028', '\u2029', '\x00', '\x0b', '\x0c', '\x85', '{', '}', '(', ')', '...', '... on Mutation ', 'mutation ', 'query ',
         'subscription ', 'fragment F on Mutation { deleteIssue } ', '...F ', 'deleteIssue ', '@include(if: false) ', '$v', '[', ']',
         ':', 'a: ', '=', '!', 'on ', '0', '-', '1e5', '"x"', '"""x"""', '\u0301', '\u200b']
def mutate(s):
    for _ in range(rnd.randint(1, 4)):
        op = rnd.random(); i = rnd.randint(0, len(s))
        if op < 0.5: s = s[:i] + rnd.choice(SNIPS) + s[i:]
        elif op < 0.7 and s: j = min(len(s), i + rnd.randint(1, 8)); s = s[:i] + s[j:]
        elif op < 0.85 and s: j = min(len(s), i + rnd.randint(1, 20)); k = rnd.randint(0, len(s)); s = s[:k] + s[i:j] + s[k:]
        else: s = s[:i] + chr(rnd.choice([0x0d, 0x0a, 0x22, 0x5c, 0x23, 0x2028, 0xfeff, 0xa0, rnd.randint(0, 0x7f)])) + s[i:]
    return s
WS = [' ', '\n', '\t', ',', '\r\n', ' # c\n', '\r', ' # c\r', '\u2028', '\ufeff', '\xa0', '#"\n']
def ws(): return rnd.choice(WS) if rnd.random() < 0.3 else ' '
def val(d=0):
    r = rnd.random()
    if r < 0.2: return '"' + rnd.choice(['x', '}', 'mutation{deleteIssue}', '\\"', '\\u0022}', '#', '\\\\"', '\r', '\n']) + '"'
    if r < 0.3: return '"""' + rnd.choice(['x', '"', '\\"""', '}', '"" ', '\n}\n']) + '"""'
    if r < 0.4 and d < 3: return '{' + ws() + 'k:' + val(d + 1) + ws() + '}'
    if r < 0.5 and d < 3: return '[' + val(d + 1) + ws() + val(d + 1) + ']'
    if r < 0.6: return '$v'
    return rnd.choice(['1', '-0', '1.5e3', 'true', 'null', 'ENUM', '0x1', '1.'])
def sel(d=0):
    out = []
    for _ in range(rnd.randint(1, 3)):
        r = rnd.random()
        if r < 0.15: out.append('...F' + ws())
        elif r < 0.25 and d < 3: out.append('... on Mutation ' + sel(d + 1))
        else:
            f = rnd.choice(['a', 'deleteIssue', 'closePullRequest', 'mutation', 'query', 'on', '__typename'])
            if rnd.random() < 0.3: f = 'x:' + ws() + f
            if rnd.random() < 0.4: f += '(input:' + ws() + val() + ')'
            if rnd.random() < 0.2: f += ' @include(if: false)'
            if rnd.random() < 0.3 and d < 3: f += ws() + sel(d + 1)
            out.append(f)
    return '{' + ws() + (ws()).join(out) + ws() + '}'
def gen():
    parts = []
    for _ in range(rnd.choice([1, 1, 1, 2])):
        t = rnd.choice(['', 'query', 'mutation', 'subscription'])
        parts.append((t + ' ' + rnd.choice(['', 'Q ', 'M '])) * (t != '') + sel())
    if rnd.random() < 0.4: parts.append('fragment F on ' + rnd.choice(['Mutation', 'Query']) + ' ' + sel(1))
    return ws().join(parts)
print(json.dumps([mutate(rnd.choice(seeds)) if i % 2 else gen() for i in range(N)], ensure_ascii=False))
