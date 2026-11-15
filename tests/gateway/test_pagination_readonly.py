"""Synthetic terminal protocol checks; no SSH client or real device is used."""
import re
import pytest
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

def test_probe_never_enters_configuration_mode_and_sends_no_page_at_the_enable_prompt(monkeypatch):
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
    assert ch.sent == ['enable\n', 'no page\n', 'show version\n', ' ']
    assert not any(s.strip() in ('config terminal', 'exit', 'terminal length 0') for s in ch.sent)
    assert 'raw_output' in out and '--More--' in out['raw_output']
    assert '--More--' not in out['output']
    assert 'note' not in out and 'truncated' not in out

def test_ansi_prompt_and_pager_keep_wire_bytes(monkeypatch):
    clock = Clock()
    monkeypatch.setattr(agent.time, 'monotonic', clock.tick)
    monkeypatch.setattr(agent.time, 'sleep', clock.sleep)
    chunks = [b'colored\r\n\x1b[7m--More--\x1b[0m']
    page = [b'next\r\n\x1b[32mSYNTH#\x1b[0m']
    channel = Channel(chunks, [page])
    raw_bytes = []
    out, complete = agent.read_until_prompt(channel, re.compile(r'(?:^|[\r\n])SYNTH#[ \t]*$'), 1, quiet=.1, raw_bytes=raw_bytes)
    assert complete and out == 'colored\r\nnext\r\nSYNTH#'
    assert b''.join(raw_bytes) == b''.join(chunks + page)
    assert channel.sent == [' ']


def test_split_pager_erase_is_control_not_next_page_text(monkeypatch):
    erase = b'\b' * 8 + b' ' * 8 + b'\b' * 8
    channel = Channel([b'first\r\n--More--'], [[erase[:11], erase[11:] + b'  indented\r\nSYNTH#']])
    out, complete, raw = read(monkeypatch, channel)
    assert complete and out == 'first\r\n  indented\r\nSYNTH#'
    assert erase.decode() in raw


def test_eof_after_prompt_proves_end_without_quiet_delay(monkeypatch):
    channel = Channel([b'complete\r\nSYNTH#', b''])
    out, complete, raw = read(monkeypatch, channel)
    assert complete and out == raw == 'complete\r\nSYNTH#'


def test_incomplete_utf8_after_prompt_is_not_complete(monkeypatch):
    channel = Channel([b'not finished\r\nSYNTH#', b'\xe5'])
    out, complete, raw = read(monkeypatch, channel)
    assert not complete and out.endswith('\ufffd') and raw.endswith('\ufffd')

def test_split_ansi_marker_and_repeated_backspace_erase(monkeypatch):
    erase = b'\b \b' * 8
    channel = Channel([b'first\r\n\x1b[7', b'm--More--\x1b[0m'], [[erase[:4], erase[4:] + b'next\r\nSYNTH#']])
    out, complete, raw = read(monkeypatch, channel)
    assert complete and out == 'first\r\nnext\r\nSYNTH#'
    assert '\x1b[7m--More--\x1b[0m' in raw
    assert channel.sent == [' ']


def test_unanswered_pager_is_incomplete_even_after_an_earlier_prompt(monkeypatch):
    channel = Channel([b'SYNTH#\r\n--More--', b''])
    out, complete, raw = read(monkeypatch, channel)
    assert not complete and channel.sent == [' ']
    assert out == 'SYNTH#\r\n' and raw.endswith('--More--')


def test_deadline_before_quiet_does_not_claim_complete(monkeypatch):
    clock = Clock()
    monkeypatch.setattr(agent.time, 'monotonic', clock.tick)
    monkeypatch.setattr(agent.time, 'sleep', clock.sleep)
    channel = Channel([b'SYNTH#'])
    out, complete = agent.read_until_prompt(channel, re.compile(r'(?:^|[\r\n])SYNTH#[ \t]*$'), .05, quiet=.1)
    assert out == 'SYNTH#' and not complete


def test_a_literal_marker_at_a_payload_tail_is_not_a_pager(monkeypatch):
    channel = Channel([b'documentation --More--', b'\r\nSYNTH#'])
    out, complete, raw = read(monkeypatch, channel)
    assert complete and channel.sent == [] and out == raw


def test_probe_raw_bytes_are_exact_and_decoded_view_is_labeled(monkeypatch):
    import base64
    import sys
    import types
    command_wire = b'payload\xff\r\nSYNTH#'
    channel = Channel([b'SYNTH>'])
    original_send = channel.send
    def send(value):
        original_send(value)
        channel.chunks.append(command_wire if value == 'show version\n' else b'SYNTH#')
    channel.send = send
    client = types.SimpleNamespace(set_missing_host_key_policy=lambda p: None,
        connect=lambda **kw: None, invoke_shell=lambda: channel, close=lambda: None)
    monkeypatch.setitem(sys.modules, 'paramiko', types.SimpleNamespace(SSHClient=lambda: client, AutoAddPolicy=object))
    clock = Clock()
    monkeypatch.setattr(agent.time, 'monotonic', clock.tick)
    monkeypatch.setattr(agent.time, 'sleep', clock.sleep)
    reply = agent.op_probe({'ip':'192.0.2.70','user':'synthetic','passwd':'synthetic','command':'show version'})
    assert base64.b64decode(reply['raw_output_base64']) == command_wire
    assert reply['raw_output_encoding'] == 'utf-8-replace'
    assert '\ufffd' in reply['raw_output']


def test_public_probe_boundary_excludes_raw_bytes_text_and_unreviewed_metadata(tmp_path):
    """Compile the actual boundary function without importing the missing vendor.

    This is a component test of its field selection and scrub invocation, not a
    substitute for collecting the complete gateway integration suite.
    """
    import ast
    import base64
    import types
    from pathlib import Path
    source = Path(__file__).resolve().parents[2] / 'gateway' / 'framework.py'
    tree = ast.parse(source.read_text(encoding='utf-8'))
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'probe')
    future = ast.ImportFrom(module='__future__', names=[ast.alias(name='annotations')], level=0)
    isolated = ast.fix_missing_locations(ast.Module(body=[future, function], type_ignores=[]))
    secret = 'password=synthetic-private-secret'
    scrubbed = []
    def scrub(text):
        scrubbed.append(text)
        return text.replace(secret, 'password=***')
    raw = {'command':'show version','output':secret,'raw_output':secret,
           'raw_output_base64':base64.b64encode(secret.encode()).decode(),
           'raw_output_encoding':'utf-8-replace','raw_output_sha256':'private-hash',
           'raw_reference':'private-reference','reached_device':True}
    scope = {'read_conf':lambda cfg: None,'device_ips':lambda parser: ['192.0.2.70'],
             'device_credentials':lambda parser, build: {'user':'synthetic','passwd':'synthetic'},
             'agent_call':lambda *args, **kw: raw,'scrub_text':scrub,'FrameworkError':RuntimeError}
    exec(compile(isolated, str(source), 'exec'), scope)
    reply = scope['probe'](types.SimpleNamespace(state_dir=tmp_path), 'show version', 'synthetic', 0)
    assert reply == {'command':'show version','output':'password=***','reached_device':True}
    assert scrubbed == ['show version', secret]
    assert raw['output'] == secret


def test_probe_keeps_received_prefix_on_transport_error(monkeypatch):
    import base64
    import sys
    import types
    prefix = b'partial\xe5'
    channel = Channel([b'SYNTH>'])
    original_send = channel.send
    original_recv = channel.recv
    in_command = [False]
    def send(value):
        original_send(value)
        in_command[0] = value == 'show version\n'
        channel.chunks.append(prefix if in_command[0] else b'SYNTH#')
    def recv(size):
        data = original_recv(size)
        if data == prefix:
            channel.chunks.append(None)
        elif data is None:
            raise OSError('synthetic receive failure')
        return data
    channel.send = send
    channel.recv = recv
    client = types.SimpleNamespace(set_missing_host_key_policy=lambda p: None,
        connect=lambda **kw: None, invoke_shell=lambda: channel, close=lambda: None)
    monkeypatch.setitem(sys.modules, 'paramiko', types.SimpleNamespace(SSHClient=lambda: client, AutoAddPolicy=object))
    clock = Clock()
    monkeypatch.setattr(agent.time, 'monotonic', clock.tick)
    monkeypatch.setattr(agent.time, 'sleep', clock.sleep)
    reply = agent.op_probe({'ip':'192.0.2.70','user':'synthetic','passwd':'synthetic','command':'show version'})
    assert 'error' in reply and reply['reached_device'] is True
    assert base64.b64decode(reply['raw_output_base64']) == prefix
    assert reply['raw_output'] == 'partial\ufffd'


def test_failed_login_is_not_retried(monkeypatch):
    import sys
    import types
    calls = []
    def connect(**kwargs):
        calls.append('login')
        raise RuntimeError('password=synthetic-private-secret')
    client = types.SimpleNamespace(set_missing_host_key_policy=lambda p: None,
        connect=connect, invoke_shell=lambda: calls.append('shell'), close=lambda: calls.append('close'))
    monkeypatch.setitem(sys.modules, 'paramiko', types.SimpleNamespace(SSHClient=lambda: client, AutoAddPolicy=object))
    reply = agent.op_probe({'ip':'192.0.2.70','user':'synthetic','passwd':'synthetic','command':'show version'})
    assert calls == ['login', 'close']
    assert reply['reached_device'] is False and 'error' in reply
    assert 'password=synthetic-private-secret' in reply['error']
    assert reply['raw_output_base64'] == ''


def test_pager_requires_page_data_not_only_an_ansi_reset(monkeypatch):
    channel = Channel([b'SYNTH#\n--More--'], [[b'\x1b[0m', b'']])
    out, complete, raw = read(monkeypatch, channel)
    assert not complete and channel.sent == [' ']


def test_probe_does_not_issue_command_after_incomplete_terminal_setup(monkeypatch):
    import sys
    import types
    for missing in ('banner', 'enable', 'no page'):
        channel = Channel([b'incomplete' if missing == 'banner' else b'SYNTH>'])
        original_send = channel.send
        def send(value):
            original_send(value)
            channel.chunks.append(b'incomplete' if value.strip() == missing else b'SYNTH#')
        channel.send = send
        client = types.SimpleNamespace(set_missing_host_key_policy=lambda p: None,
            connect=lambda **kw: None, invoke_shell=lambda: channel, close=lambda: None)
        monkeypatch.setitem(sys.modules, 'paramiko', types.SimpleNamespace(SSHClient=lambda: client, AutoAddPolicy=object))
        clock = Clock()
        monkeypatch.setattr(agent.time, 'monotonic', clock.tick)
        monkeypatch.setattr(agent.time, 'sleep', clock.sleep)
        monkeypatch.setattr(agent, 'PROMPT_WAIT_S', .2)
        monkeypatch.setattr(agent, 'QUIET_S', .05)
        reply = agent.op_probe({'ip':'192.0.2.70','user':'synthetic','passwd':'synthetic','command':'show version'})
        assert 'error' in reply, missing
        assert 'show version\n' not in channel.sent, missing
        assert reply['reached_device'] is True



def test_public_probe_scrubs_secret_exception_and_all_text_fields(tmp_path):
    import ast
    import types
    from pathlib import Path
    source = Path(__file__).resolve().parents[2] / 'gateway' / 'framework.py'
    tree = ast.parse(source.read_text(encoding='utf-8'))
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'probe')
    future = ast.ImportFrom(module='__future__', names=[ast.alias(name='annotations')], level=0)
    isolated = ast.fix_missing_locations(ast.Module(body=[future, function], type_ignores=[]))
    secret = 'password=synthetic-private-secret'
    reply = {'command':'show version','output':secret,'error':'RuntimeError: ' + secret,
             'note':secret,'stderr':secret,'raw_output':secret,'raw_output_base64':'opaque-private',
             'raw_output_sha256':'private-hash','raw_reference':'private-ref','reached_device':True}
    seen = []
    def scrub(text):
        seen.append(text)
        return text.replace(secret, 'password=***')
    scope = {'read_conf':lambda cfg: None,'device_ips':lambda parser: ['192.0.2.70'],
             'device_credentials':lambda parser, build: {'user':'synthetic','passwd':'synthetic'},
             'agent_call':lambda *args, **kw: reply,'scrub_text':scrub,'FrameworkError':RuntimeError}
    exec(compile(isolated, str(source), 'exec'), scope)
    public = scope['probe'](types.SimpleNamespace(state_dir=tmp_path), 'show version', 'synthetic', 0)
    assert public['error'] == 'RuntimeError: password=***'
    assert public['note'] == public['output'] == public['stderr'] == 'password=***'
    assert set(public) == {'command','output','error','note','stderr','reached_device'}
    assert seen == ['show version', secret, secret, 'RuntimeError: ' + secret, secret]
    # A malformed flag must not disclose its string or be coerced into a confirmed login.
    reply['reached_device'] = secret
    invalid = scope['probe'](types.SimpleNamespace(state_dir=tmp_path), 'show version', 'synthetic', 0)
    assert invalid == {'error':'agent returned malformed probe fields','reached_device':False}
    reply.clear()
    reply['raw_output_base64'] = 'opaque-private'
    assert scope['probe'](types.SimpleNamespace(state_dir=tmp_path), 'show version', 'synthetic', 0) == invalid


# The pager prompt as the gateway recorded the device drawing it: newline, blank, --More--, blank.
# The device wipes what it drew before the next page: the width it drew, or the bare marker's 8.
PAGER_FORMS = [(marker, width, spelling)
               for marker in (b' --More-- ', b'--More-- ', b' --More--', b'--More--')
               for width in sorted({8, len(marker)})
               for spelling in ('backspace-blank-backspace', 'backspace-blank-repeated')]


def erase_for(width, spelling):
    if spelling == 'backspace-blank-backspace':
        return b'\b' * width + b' ' * width + b'\b' * width
    return b'\b \b' * width


@pytest.mark.parametrize('marker,width,spelling', PAGER_FORMS)
def test_pager_line_with_blanks_is_paged_and_its_erase_is_not_page_text(monkeypatch, marker, width, spelling):
    channel = Channel([b'show version\r\nline one\r\n' + marker], [[erase_for(width, spelling) + b'line two\r\nSYNTH#']])
    out, complete, raw = read(monkeypatch, channel)
    assert complete and channel.sent == [' ']
    assert out == 'show version\r\nline one\r\nline two\r\nSYNTH#'


def test_recorded_pager_shape_over_two_pages_with_split_chunks(monkeypatch):
    erase = b'\b' * 10 + b' ' * 10 + b'\b' * 10
    channel = Channel([b'show version\r\nline one\r\n --Mo', b're-- '],
                      [[erase[:7], erase[7:] + b'line two\r\n --More-- '], [erase + b'line three\r\nSYNTH#']])
    out, complete, raw = read(monkeypatch, channel)
    assert complete and channel.sent == [' ', ' ']
    assert out == 'show version\r\nline one\r\nline two\r\nline three\r\nSYNTH#'


def test_an_indented_marker_inside_a_line_is_not_a_pager(monkeypatch):
    channel = Channel([b'  --More-- is printed when paging is on\r\nSYNTH#'])
    out, complete, raw = read(monkeypatch, channel)
    assert complete and channel.sent == [] and out == raw


def test_probe_pages_the_recorded_pager_shape_without_waiting_for_the_timeout(monkeypatch):
    import sys
    import types
    erase = b'\b' * 10 + b' ' * 10 + b'\b' * 10
    answers = {'show version\n': [b'show version\r\nline one\r\n --More-- '],
               ' ': [erase + b'line two\r\nSYNTH#']}
    channel = Channel([b'SYNTH>'])
    original_send = channel.send
    def send(value):
        original_send(value)
        channel.chunks.extend(answers.get(value, [b'SYNTH#']))
    channel.send = send
    client = types.SimpleNamespace(set_missing_host_key_policy=lambda p: None,
        connect=lambda **kw: None, invoke_shell=lambda: channel, close=lambda: None)
    monkeypatch.setitem(sys.modules, 'paramiko', types.SimpleNamespace(SSHClient=lambda: client, AutoAddPolicy=object))
    clock = Clock()
    monkeypatch.setattr(agent.time, 'monotonic', clock.tick)
    monkeypatch.setattr(agent.time, 'sleep', clock.sleep)
    reply = agent.op_probe({'ip':'192.0.2.70','user':'synthetic','passwd':'synthetic','command':'show version'})
    assert channel.sent == ['enable\n', 'no page\n', 'show version\n', ' ']
    assert reply['output'] == 'line one\nline two\nSYNTH#'
    assert 'truncated' not in reply and 'note' not in reply and clock.now < agent.COMMAND_WAIT_S


class Scripted(Channel):
    """Answers each line sent from a table: line (stripped; ' ' for a page key) -> replies in order, one chunk each."""
    def __init__(self, replies):
        Channel.__init__(self, [b'SYNTH>'])
        self.replies = {key: list(value) for key, value in replies.items()}
    def send(self, value):
        self.sent.append(value)
        queue = self.replies.get(value if value == ' ' else value.strip())
        self.chunks.append(queue.pop(0) if queue else b'SYNTH#')


def run_probe(monkeypatch, replies, command='show version'):
    import sys
    import types
    channel = Scripted(replies)
    client = types.SimpleNamespace(set_missing_host_key_policy=lambda p: None,
        connect=lambda **kw: None, invoke_shell=lambda: channel, close=lambda: None)
    monkeypatch.setitem(sys.modules, 'paramiko', types.SimpleNamespace(SSHClient=lambda: client, AutoAddPolicy=object))
    clock = Clock()
    monkeypatch.setattr(agent.time, 'monotonic', clock.tick)
    monkeypatch.setattr(agent.time, 'sleep', clock.sleep)
    monkeypatch.setattr(agent, 'COMMAND_WAIT_S', 1)
    reply = agent.op_probe({'ip':'192.0.2.70','user':'synthetic','passwd':'synthetic','command':command})
    return reply, channel


@pytest.mark.parametrize('answer', [b'no page\r\nSYNTH#', b'no page\r\n\r\nSYNTH#', b'SYNTH#'])
def test_an_accepted_no_page_is_silent_and_pages_are_not_walked(monkeypatch, answer):
    reply, channel = run_probe(monkeypatch, {'no page': [answer], 'show version': [b'show version\r\nbuild line\r\nSYNTH#']})
    assert channel.sent == ['enable\n', 'no page\n', 'show version\n']
    assert reply['output'] == 'build line\nSYNTH#'
    assert 'note' not in reply and 'truncated' not in reply and 'error' not in reply


@pytest.mark.parametrize('answer', [b'no page\r\n    ^\r\n% Invalid input\r\nSYNTH#', b'no page\r\n^\r\nSYNTH#', b'no page\r\nsome text\r\nSYNTH#'])
def test_a_rejected_no_page_is_noted_and_pages_are_still_walked(monkeypatch, answer):
    erase = b'\b' * 10 + b' ' * 10 + b'\b' * 10
    reply, channel = run_probe(monkeypatch, {'no page': [answer],
        'show version': [b'show version\r\nline one\r\n --More-- '], ' ': [erase + b'line two\r\nSYNTH#']})
    assert channel.sent == ['enable\n', 'no page\n', 'show version\n', ' ']
    assert reply['output'] == 'line one\nline two\nSYNTH#'
    assert 'paging not switched off' in reply['note'] and 'no device prompt' not in reply['note']
    assert 'truncated' not in reply and 'error' not in reply and reply['reached_device'] is True


def test_no_page_answered_at_a_user_prompt_is_noted(monkeypatch):
    reply, channel = run_probe(monkeypatch, {'enable': [b'enable\r\nSYNTH>'], '': [b'\r\nSYNTH>'],
        'no page': [b'no page\r\nSYNTH>'], 'show version': [b'show version\r\nbuild line\r\nSYNTH>']})
    assert channel.sent == ['enable\n', '\n', 'no page\n', 'show version\n']
    assert 'paging not switched off' in reply['note'] and reply['output'] == 'build line\nSYNTH>'


def test_a_rejected_no_page_and_a_missing_prompt_keep_both_notes(monkeypatch):
    reply, channel = run_probe(monkeypatch, {'no page': [b'no page\r\n^\r\nSYNTH#'], 'show version': [b'show version\r\nline one\r\n']})
    assert reply['truncated'] is True
    assert 'paging not switched off' in reply['note'] and 'no device prompt' in reply['note']
    assert 'config terminal\n' not in channel.sent and 'exit\n' not in channel.sent


def test_a_rejected_no_page_and_a_syntax_error_in_the_command_keep_the_note(monkeypatch):
    reply, channel = run_probe(monkeypatch, {'no page': [b'no page\r\n^\r\nSYNTH#'], 'show nothing': [b'show nothing\r\n   ^\r\nSYNTH#']},
                               command='show nothing')
    assert reply['syntax_error'] is True and 'paging not switched off' in reply['note']
