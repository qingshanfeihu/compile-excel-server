"""Synthetic terminal protocol checks; no SSH client or real device is used."""
import re
from gateway.agent import jumphost_agent as agent

class Channel:
    def __init__(self, chunks, pages=()):
        self.chunks = list(chunks)
        self.pages = list(pages)
        self.sent = []
    def recv_ready(self):
        return bool(self.chunks)
    def recv(self, size):
        return self.chunks.pop(0)
    def send(self, value):
        self.sent.append(value)
        self.chunks.extend(self.pages.pop(0) if self.pages else [])

class Clock:
    now = 0
    def tick(self):
        return self.now
    def sleep(self, seconds):
        self.now += seconds

def read(monkeypatch, channel):
    clock = Clock()
    monkeypatch.setattr(agent.time, 'monotonic', clock.tick)
    monkeypatch.setattr(agent.time, 'sleep', clock.sleep)
    raw = []
    out, complete = agent.read_until_prompt(channel, re.compile(r'(?:^|[\r\n])SYNTH#[ \t]*$'), 1, quiet=.1, raw=raw)
    return out, complete, ''.join(raw)

def test_multiple_pages_split_markers_and_utf8(monkeypatch):
    ch = Channel([b'show version\r\n', b'\xe5\x90', b'\x88\xe6\x88\x90\r\n--Mo', b're--'], [[b'page two\r\n--More--'], [b'end\r\nSYNTH#']])
    out, complete, raw = read(monkeypatch, ch)
    assert complete and out == 'show version\r\n合成\r\npage two\r\nend\r\nSYNTH#'
    assert ch.sent == [' ', ' ']
    assert raw.count('--More--') == 2

def test_literal_marker_and_hash_are_not_protocol(monkeypatch):
    ch = Channel([b'literal --More-- in output\r\n#\r\nSYNTH#'])
    out, complete, raw = read(monkeypatch, ch)
    assert complete and ch.sent == [] and out == raw

def test_missing_prompt_stays_incomplete(monkeypatch):
    out, complete, raw = read(monkeypatch, Channel([b'partial']))
    assert not complete and out == raw == 'partial'

def test_probe_never_enters_configuration_mode(monkeypatch):
    import sys
    import types
    ch = Channel([b'SYNTH>'])
    original_send = ch.send
    def send(value):
        original_send(value)
        ch.chunks.extend([b'first\r\n--More--'] if value == 'show version\n' else [b'SYNTH#'])
    ch.send = send
    calls = []
    client = types.SimpleNamespace(set_missing_host_key_policy=lambda p: None,
        connect=lambda **kw: calls.append('login'), invoke_shell=lambda: ch, close=lambda: None)
    monkeypatch.setitem(sys.modules, 'paramiko', types.SimpleNamespace(SSHClient=lambda: client, AutoAddPolicy=object))
    clock = Clock()
    monkeypatch.setattr(agent.time, 'monotonic', clock.tick)
    monkeypatch.setattr(agent.time, 'sleep', clock.sleep)
    out = agent.op_probe({'ip':'192.0.2.70','user':'synthetic','passwd':'synthetic','command':'show version'})
    assert calls == ['login']
    assert not any(s.strip() in ('config terminal','no page','exit') for s in ch.sent)
    assert 'raw_output' in out and '--More--' in out['raw_output']
    assert '--More--' not in out['output']
