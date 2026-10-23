"""
minimal fake Emby server for the black-box tests, serving the endpoints main.py uses
"""
import copy
import json
import re
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


def emby_date(daysAgo=0, hoursAgo=0, fraction='0000000'):
    """
    a LastPlayedDate the way Emby formats it, relative to now
    """
    date = datetime.now(timezone.utc) - timedelta(days=daysAgo, hours=hoursAgo)
    return date.strftime('%Y-%m-%dT%H:%M:%S.') + fraction + 'Z'


def user_data(played=False, count=0, pos=0, last=None, fav=False):
    """
    a UserData object
    """
    data = {'Played': played, 'PlayCount': count, 'PlaybackPositionTicks': pos, 'IsFavorite': fav}
    if last is not None:
        data['LastPlayedDate'] = last
    return data


def finished(daysAgo, count=1, fraction='0000000'):
    """
    UserData of an item played to the end daysAgo
    """
    return user_data(True, count, 0, emby_date(daysAgo, fraction=fraction))


def episode(itemId, name, series='ser1', season='sea1'):
    """
    an Episode item
    """
    return {'Id': itemId, 'Name': name, 'Type': 'Episode', 'MediaType': 'Video', 'SeriesId': series,
            'SeasonId': season, 'Path': f"/media/tv/{series}/{season}/{itemId}.mkv"}


def movie(itemId, name, canDelete=True):
    """
    a Movie item
    """
    item = {'Id': itemId, 'Name': name, 'Type': 'Movie', 'MediaType': 'Video', 'Path': f"/media/movies/{itemId}.mkv"}
    if not canDelete:
        item['CanDelete'] = False
    return item


def default_state():
    """
    a library shared by niko and rhea, kid only played the pilot
    """
    return {
        'users': [{'Name': 'niko', 'Id': 'n1'}, {'Name': 'rhea', 'Id': 'r1'}, {'Name': 'kid', 'Id': 'k1'}],
        'containers': {
            'ser1': {'Id': 'ser1', 'Name': 'Alone', 'Type': 'Series', 'Path': '/media/tv/ser1'},
            'sea1': {'Id': 'sea1', 'Name': 'Vancouver Island', 'Type': 'Season', 'SeriesId': 'ser1'},
            'ser2': {'Id': 'ser2', 'Name': 'Fav Show', 'Type': 'Series'},
            'sea2': {'Id': 'sea2', 'Name': 'Season 1', 'Type': 'Season', 'SeriesId': 'ser2'},
        },
        'containerUserData': {('r1', 'ser2'): user_data(fav=True)},
        'items': {
            'e1': (episode('e1', 'Pilot'), {'n1': finished(83), 'r1': finished(83), 'k1': finished(83)}),
            'e2': (episode('e2', 'Of Wolf and Man'), {'n1': finished(62), 'r1': user_data(pos=11753070000)}),
            'e3': (episode('e3', 'The Talons of Fear'), {'n1': finished(62)}),
            'e4': (episode('e4', 'Stalked'), {'n1': finished(62)}),
            'e5': (episode('e5', 'Recent for rhea'),
                   {'n1': finished(83), 'r1': user_data(True, 1, 0, emby_date(0, 2))}),
            'e6': (episode('e6', 'Rhea fav series', 'ser2', 'sea2'), {'n1': finished(83), 'r1': finished(83)}),
            'e7': (episode('e7', 'Niko rewatching'),
                   {'n1': user_data(True, 2, 5000, emby_date(83)), 'r1': finished(83)}),
            'm1': (movie('m1', 'Both played'), {'n1': finished(83), 'r1': finished(83, fraction='1234567')}),
            'm2': (movie('m2', 'Rhea null date'), {'n1': finished(83), 'r1': user_data(True, 1)}),
            'm4': (movie('m4', 'Rhea only'), {'r1': finished(83)}),
            'm3': (movie('m3', 'No delete perm', canDelete=False), {'n1': finished(83), 'r1': finished(83)}),
        },
    }


class FakeEmby:  # pylint: disable=too-many-instance-attributes
    """
    serves state on a free localhost port in a thread, records DELETE calls in deletes and X-Emby-Tokens in tokens;
    fail_deletes maps item ids and fail_paths request paths to an HTTP status,
    drop_paths are request paths whose connection is closed without a reply
    """

    def __init__(self, state=None):
        self.state = copy.deepcopy(state or default_state())
        self.deletes = []
        self.fail_deletes = {}
        self.fail_paths = {}
        self.drop_paths = set()
        self.tokens = []
        self.auth_requests = []
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), self.handler())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self):
        """base URL of the fake"""
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def start(self):
        """start serving"""
        self.thread.start()
        return self

    def stop(self):
        """stop serving"""
        self.server.shutdown()
        self.server.server_close()

    def handler(self):
        """request handler class bound to this fake"""
        fake = self

        class Handler(BaseHTTPRequestHandler):
            """answers the Emby endpoints main.py uses"""

            def log_message(self, *args):  # pylint: disable=arguments-differ
                pass

            def reply(self, code, body=None):
                """send code and an optional JSON body"""
                self.send_response(code)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                if body is not None:
                    self.wfile.write(json.dumps(body).encode())

            def dropped(self, path):
                """True if path is in drop_paths, the request then gets no reply, only a closed connection"""
                return path in fake.drop_paths

            def note_token(self):
                """record the X-Emby-Token header of an authenticated request"""
                token = self.headers.get('X-Emby-Token')
                if token is not None:
                    fake.tokens.append(token)

            def do_GET(self):  # pylint: disable=invalid-name,too-many-return-statements
                """users, played items, single items"""
                path = urlparse(self.path).path
                if self.dropped(path):
                    return None
                self.note_token()
                if path in fake.fail_paths:
                    return self.reply(fake.fail_paths[path], {})
                state = fake.state
                if path == '/Users/Public':
                    return self.reply(200, state['users'])
                match = re.fullmatch(r'/Users/(\w+)/Items', path)
                if match:
                    played = []
                    for item, perUser in state['items'].values():
                        data = perUser.get(match.group(1), user_data())
                        if data['Played'] and not data['IsFavorite']:
                            played.append({**item, 'UserData': data})
                    return self.reply(200, {'Items': played})
                match = re.fullmatch(r'/Users/(\w+)/Items/(\w+)', path)
                if match:
                    userId, itemId = match.groups()
                    if itemId in state['items']:
                        item, perUser = state['items'][itemId]
                        return self.reply(200, {**item, 'UserData': perUser.get(userId, user_data())})
                    if itemId in state['containers']:
                        data = state['containerUserData'].get((userId, itemId), user_data())
                        return self.reply(200, {**state['containers'][itemId], 'UserData': data})
                return self.reply(404, {})

            def do_POST(self):  # pylint: disable=invalid-name
                """token fetching"""
                path = urlparse(self.path).path
                # read the body first, so the client is not reset while still sending it
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length).decode()
                if self.dropped(path):
                    return None
                if path in fake.fail_paths:
                    return self.reply(fake.fail_paths[path], {})
                if path == '/Users/AuthenticateByName':
                    fake.auth_requests.append(body)
                    return self.reply(200, {'AccessToken': 'fetched-token'})
                return self.reply(404, {})

            def do_DELETE(self):  # pylint: disable=invalid-name
                """item deletion"""
                path = urlparse(self.path).path
                if self.dropped(path):
                    return None
                self.note_token()
                match = re.fullmatch(r'/Items/(\w+)', path)
                if not match:
                    return self.reply(404, {})
                if match.group(1) in fake.fail_deletes:
                    return self.reply(fake.fail_deletes[match.group(1)], {'error': 'nope'})
                fake.deletes.append(match.group(1))
                return self.reply(204)

        return Handler
