"""
black-box tests: run main.py against a fake Emby server and check what it deletes
"""
# test names say what they check
# pylint: disable=missing-function-docstring,too-many-public-methods
import hashlib
import importlib.util
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fake_emby import FakeEmby, episode, finished, movie, user_data

REPO = Path(__file__).resolve().parent.parent
COVERAGE = importlib.util.find_spec('coverage') is not None
ADMIN_LOGIN = 'admin\npassword\n'


def closed_url():
    """
    URL of a localhost port that nothing listens on
    """
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return f"http://127.0.0.1:{sock.getsockname()[1]}"


def run_main(fake, *args, env=None, stdin=None):
    """
    run main.py against fake with --days 1, return the finished process
    """
    command = [sys.executable]
    if COVERAGE:
        command += ['-m', 'coverage', 'run', f"--rcfile={REPO / '.coveragerc'}"]
    command += [str(REPO / 'main.py'), '--days', '1', *args]
    environment = {key: value for key, value in os.environ.items() if not key.startswith('EMBY_')}
    environment.update({'EMBY_URL': fake.url, 'EMBY_TOKEN': 'x'})
    environment.update(env or {})
    # a new session has no controlling terminal, so getpass falls back to stdin
    return subprocess.run(command, cwd=REPO, env=environment, input=stdin, capture_output=True,
                          text=True, timeout=60, check=False, start_new_session=True)


class FakeEmbyTestCase(unittest.TestCase):
    """
    starts a fresh fake Emby per test
    """

    def setUp(self):
        self.fake = FakeEmby().start()
        self.addCleanup(self.fake.stop)

    def assertRun(self, wantExit, wantDeletes, *args, env=None, stdin=None):  # pylint: disable=invalid-name
        """run main.py, check exit code and deleted ids, return the process"""
        process = run_main(self.fake, *args, env=env, stdin=stdin)
        self.assertEqual(wantExit, process.returncode, process.stderr)
        self.assertEqual(sorted(wantDeletes), sorted(self.fake.deletes), process.stderr)
        return process


class PolicyTest(FakeEmbyTestCase):
    """
    --user and --policy
    """

    def test_single_user_deletes_what_that_user_finished(self):
        process = self.assertRun(0, ['e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'm1', 'm2'], '--user', 'niko', '-v')
        self.assertIn("'Alone' 'Vancouver Island' 'Of Wolf and Man' played 62 days ago", process.stderr)
        self.assertIn('CanDelete=false, skipping', process.stderr)
        self.assertIn('Alone: 5', process.stderr)

    def test_policy_user_with_one_name(self):
        self.assertRun(0, ['e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'm1', 'm2'], '--user', 'niko', '--policy', 'user')

    def test_policy_user_rejects_several_names(self):
        process = self.assertRun(2, [], '--user', 'niko,rhea', '--policy', 'user')
        self.assertIn("policy 'user' takes exactly one user", process.stderr)

    def test_all_keeps_what_another_user_still_needs(self):
        self.assertRun(0, ['e1', 'm1'], '--user', 'niko, rhea')

    def test_all_does_not_depend_on_user_order(self):
        self.assertRun(0, ['e1', 'm1'], '--user', 'rhea,niko', '--policy', 'all')

    def test_any_takes_candidates_from_every_user(self):
        self.assertRun(0, ['e1', 'e3', 'e4', 'm1', 'm2', 'm4'], '--user', 'niko,rhea', '--policy', 'any')

    def test_majority_of_two_is_all(self):
        self.assertRun(0, ['e1', 'm1'], '--user', 'niko,rhea', '--policy', 'majority')

    def test_majority_of_three(self):
        self.assertRun(0, ['e1', 'm1'], '--user', 'niko,rhea,kid', '--policy', 'majority')

    def test_all_of_three(self):
        self.assertRun(0, ['e1'], '--user', 'niko,rhea,kid', '--policy', 'all')

    def test_limit_counts_deletes(self):
        process = self.assertRun(0, ['e1', 'e3'], '--user', 'niko,rhea', '--policy', 'any', '--limit', '2', '-v')
        self.assertIn('2 out of 2 items deleted, limit reached', process.stderr)

    def test_policy_from_env_is_validated(self):
        process = self.assertRun(2, [], '--user', 'niko', env={'EMBY_POLICY': 'bogus'})
        self.assertIn("policy 'bogus' is not one of user, all, majority, any", process.stderr)

    def test_policy_from_env(self):
        self.assertRun(0, ['e1', 'e3', 'e4', 'm1', 'm2', 'm4'], env={'EMBY_USER': 'niko,rhea', 'EMBY_POLICY': 'any'})

    def test_unknown_user(self):
        process = self.assertRun(2, [], '--user', 'niko,bob')
        self.assertIn('bob is not a known user', process.stderr)

    def test_dry_run_deletes_nothing(self):
        process = self.assertRun(0, [], '--user', 'niko,rhea', '--dry-run', '-v')
        self.assertIn("'Pilot' played 83 days ago", process.stderr)


class WorkingSetTest(FakeEmbyTestCase):
    """
    --working-set
    """

    def setUp(self):
        super().setUp()
        directory = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.path = self.directory / 'working-set.json'

    def write(self, items, age=timedelta(minutes=10), users=('niko', 'rhea'), **overrides):
        """write a working set file generated age ago"""
        workingSet = {
            'version': 1,
            'generated_at': (datetime.now(timezone.utc) - age).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'users': list(users),
            'items': items,
        }
        workingSet.update(overrides)
        self.path.write_text(json.dumps(workingSet), encoding='utf-8')

    def assertAny(self, wantExit, wantDeletes, *args):  # pylint: disable=invalid-name
        """run with policy any over niko and rhea and the working set"""
        return self.assertRun(wantExit, wantDeletes, '--user', 'niko,rhea', '--policy', 'any',
                              '--working-set', str(self.path), *args)

    def test_items_match_by_id_or_path(self):
        self.write([
            {'id': 'e3', 'path': '/media/tv/ser1/sea1/e3.mkv', 'user': 'rhea', 'reason': 'look-ahead'},
            {'id': None, 'path': '/media/tv/ser1/sea1/e4.mkv', 'user': 'rhea', 'reason': 'look-ahead'},
            {'id': 'zz', 'path': '/media/movies/m2.mkv', 'user': None, 'reason': 'staged'},
        ])
        process = self.assertAny(0, ['e1', 'm1', 'm4'], '-v')
        self.assertIn("Episode 'The Talons of Fear' is in the working set (look-ahead rhea), skipping", process.stderr)
        self.assertIn("Movie 'Rhea null date' is in the working set (staged all users), skipping", process.stderr)

    def test_working_set_from_env(self):
        self.write([{'id': 'e3', 'path': '/media/tv/ser1/sea1/e3.mkv', 'user': 'rhea', 'reason': 'look-ahead'}])
        self.assertRun(0, ['e1', 'e4', 'm1', 'm2', 'm4'], '--user', 'niko,rhea', '--policy', 'any',
                       env={'EMBY_WORKING_SET': str(self.path)})

    def test_series_id_covers_its_episodes(self):
        self.write([{'id': 'ser1', 'path': '/media/tv/ser1', 'user': None, 'reason': 'staged'}])
        self.assertAny(0, ['m1', 'm2', 'm4'])

    def test_series_path_covers_its_episodes(self):
        self.write([{'id': None, 'path': '/media/tv/ser1/', 'user': None, 'reason': 'staged'}])
        self.assertAny(0, ['m1', 'm2', 'm4'])

    def test_season_id_covers_its_episodes(self):
        self.write([{'id': 'sea1', 'path': '/media/tv/ser1/sea1', 'user': 'rhea', 'reason': 'staged'}])
        self.assertAny(0, ['m1', 'm2', 'm4'])

    def test_path_match_is_by_whole_components(self):
        self.write([
            {'id': None, 'path': '/media/tv/ser1/sea1/e3', 'user': 'rhea', 'reason': 'look-ahead'},
            {'id': None, 'path': '/media/tv/ser', 'user': None, 'reason': 'staged'},
        ])
        self.assertAny(0, ['e1', 'e3', 'e4', 'm1', 'm2', 'm4'])

    def test_empty_working_set(self):
        self.write([])
        self.assertAny(0, ['e1', 'e3', 'e4', 'm1', 'm2', 'm4'])

    def test_missing_file(self):
        self.path = self.directory / 'nope.json'
        process = self.assertAny(2, [])
        self.assertIn('is not usable, not deleting anything', process.stderr)

    def test_stale_file(self):
        self.write([], age=timedelta(hours=7))
        process = self.assertAny(2, [])
        self.assertIn('ago, not deleting anything', process.stderr)

    def test_max_age_is_configurable(self):
        self.write([], age=timedelta(hours=7))
        self.assertAny(0, ['e1', 'e3', 'e4', 'm1', 'm2', 'm4'], '--working-set-max-age', '8')

    def test_generated_in_the_future(self):
        self.write([], age=-timedelta(hours=1))
        process = self.assertAny(2, [])
        self.assertIn('in the future, not deleting anything', process.stderr)

    def test_small_clock_skew_is_accepted(self):
        self.write([], age=-timedelta(minutes=2))
        self.assertAny(0, ['e1', 'e3', 'e4', 'm1', 'm2', 'm4'])

    def test_unknown_version(self):
        self.write([], version=2)
        self.assertAny(2, [])

    def test_generated_at_without_timezone(self):
        self.write([], generated_at=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S'))
        self.assertAny(2, [])

    def test_listed_user_missing_from_users(self):
        self.write([], users=['niko'])
        process = self.assertAny(2, [])
        self.assertIn('does not cover rhea, not deleting anything', process.stderr)

    def test_users_field_is_optional(self):
        self.write([])
        workingSet = json.loads(self.path.read_text(encoding='utf-8'))
        del workingSet['users']
        self.path.write_text(json.dumps(workingSet), encoding='utf-8')
        self.assertAny(0, ['e1', 'e3', 'e4', 'm1', 'm2', 'm4'])

    def test_truncated_json(self):
        self.path.write_text('{"version": 1, "generated_at": "2026-10-23T08:00:00Z", "items": [{"id": "e1"',
                             encoding='utf-8')
        self.assertAny(2, [])

    def test_path_is_a_directory(self):
        self.path = self.directory
        self.assertAny(2, [])


class ArgumentTest(FakeEmbyTestCase):
    """
    --url and --user are required
    """

    def test_user_is_required(self):
        process = self.assertRun(2, [])
        self.assertIn("argument '--user' is required", process.stderr)

    def test_url_is_required(self):
        process = self.assertRun(2, [], '--user', 'niko', env={'EMBY_URL': ''})
        self.assertIn("argument '--url' is required", process.stderr)


class ReachabilityTest(FakeEmbyTestCase):
    """
    emby must answer /Users/Public before anything else happens
    """

    def test_nothing_listening_stops_the_run(self):
        process = self.assertRun(2, [], '--user', 'niko', env={'EMBY_URL': closed_url()})
        self.assertIn('emby is not reachable via', process.stderr)

    def test_public_users_error_stops_the_run(self):
        self.fake.fail_paths['/Users/Public'] = 503
        process = self.assertRun(2, [], '--user', 'niko')
        self.assertIn('emby is not reachable via', process.stderr)


class TokenTest(FakeEmbyTestCase):
    """
    no EMBY_TOKEN: the token is fetched with an admin login read from stdin
    """

    def test_admin_login_fetches_token_and_uses_it_for_later_requests(self):
        process = self.assertRun(0, ['e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'm1', 'm2'], '--user', 'niko',
                                 env={'EMBY_TOKEN': ''}, stdin=ADMIN_LOGIN)
        self.assertEqual({'fetched-token'}, set(self.fake.tokens))
        self.assertEqual(1, len(self.fake.auth_requests))
        self.assertIn('Username=admin', self.fake.auth_requests[0])
        self.assertIn('Pw=password', self.fake.auth_requests[0])
        self.assertIn(f"Password={hashlib.sha1(b'password').hexdigest()}", self.fake.auth_requests[0])
        self.assertIn('no access token specified', process.stderr)
        self.assertIn('access token was fetched successfully', process.stderr)
        self.assertIn('fetched-token', process.stderr)

    def test_unreachable_server_while_fetching_token(self):
        self.fake.drop_paths.add('/Users/AuthenticateByName')
        process = self.assertRun(2, [], '--user', 'niko', env={'EMBY_TOKEN': ''}, stdin=ADMIN_LOGIN)
        self.assertIn('got exception when trying to fetch token', process.stderr)

    def test_refused_login_stops_the_run(self):
        self.fake.fail_paths['/Users/AuthenticateByName'] = 401
        process = self.assertRun(2, [], '--user', 'niko', env={'EMBY_TOKEN': ''}, stdin=ADMIN_LOGIN)
        self.assertIn("got error code '401' when trying to fetch token", process.stderr)

    def test_login_answer_without_access_token_stops_the_run(self):
        self.fake.fail_paths['/Users/AuthenticateByName'] = 200
        process = self.assertRun(2, [], '--user', 'niko', env={'EMBY_TOKEN': ''}, stdin=ADMIN_LOGIN)
        self.assertIn('something went wrong getting the access token', process.stderr)


class PlayedItemsErrorTest(FakeEmbyTestCase):
    """
    the played items of the first listed user cannot be fetched
    """

    def test_http_error_stops_the_run(self):
        self.fake.fail_paths['/Users/n1/Items'] = 500
        process = self.assertRun(2, [], '--user', 'niko,rhea')
        self.assertIn("got error code '500' when trying to get played items", process.stderr)

    def test_answer_without_items_key_stops_the_run(self):
        self.fake.fail_paths['/Users/n1/Items'] = 200
        process = self.assertRun(2, [], '--user', 'niko,rhea')
        self.assertIn('something went wrong getting played items', process.stderr)

    def test_connection_error_stops_the_run(self):
        self.fake.drop_paths.add('/Users/n1/Items')
        process = self.assertRun(2, [], '--user', 'niko,rhea')
        self.assertIn('got exception when trying to get played items', process.stderr)

    def test_no_played_items_is_a_successful_noop(self):
        self.fake.state['items'] = {}
        process = self.assertRun(0, [], '--user', 'niko,rhea', '-v')
        self.assertIn('no played items found, nothing to clean up', process.stderr)


class ItemErrorTest(FakeEmbyTestCase):
    """
    a single item cannot be fetched, the run stops rather than guessing
    """

    def test_http_error_stops_the_run(self):
        self.fake.fail_paths['/Users/n1/Items/e1'] = 500
        process = self.assertRun(2, [], '--user', 'niko,rhea')
        self.assertIn("got error code '500' when trying to get item e1", process.stderr)

    def test_connection_error_stops_the_run(self):
        self.fake.drop_paths.add('/Users/n1/Items/e1')
        process = self.assertRun(2, [], '--user', 'niko,rhea')
        self.assertIn('got exception when trying to get item e1', process.stderr)


class DeleteFailureTest(FakeEmbyTestCase):
    """
    a failed delete is logged and skipped, the other items are still deleted
    """

    def test_http_error_skips_item_and_continues(self):
        self.fake.fail_deletes['e1'] = 500
        process = self.assertRun(0, ['e3', 'e4', 'm1', 'm2', 'm4'], '--user', 'niko,rhea', '--policy', 'any')
        self.assertIn('Emby returned HTTP 500 deleting item e1, skipping', process.stderr)

    def test_connection_error_skips_item_and_continues(self):
        self.fake.drop_paths.add('/Items/e1')
        process = self.assertRun(0, ['e3', 'e4', 'm1', 'm2', 'm4'], '--user', 'niko,rhea', '--policy', 'any')
        self.assertIn('connection error deleting item e1, skipping', process.stderr)

    def test_limit_counts_only_successful_deletes(self):
        self.fake.fail_deletes['e1'] = 500
        process = self.assertRun(0, ['e3', 'e4'], '--user', 'niko,rhea', '--policy', 'any', '--limit', '2', '-v')
        self.assertIn('2 out of 2 items deleted, limit reached', process.stderr)


class FavoriteCacheTest(FakeEmbyTestCase):
    """
    a second episode of a series or season already known to be favorite is kept without another lookup
    """

    def test_second_episode_of_favorite_series_is_kept(self):
        # e6 in sea2 already found ser2 favorite for rhea, e8 is in sea3, another season of ser2
        self.fake.state['containers']['sea3'] = {'Id': 'sea3', 'Name': 'Season 3', 'Type': 'Season',
                                                 'SeriesId': 'ser2'}
        self.fake.state['items']['e8'] = (episode('e8', 'Second season', 'ser2', 'sea3'), {'n1': finished(83)})
        process = self.assertRun(0, ['e1', 'm1'], '--user', 'niko,rhea', '-vv')
        self.assertIn('series id ser2 already found in FAVORITES list', process.stderr)

    def test_second_episode_of_favorite_season_is_kept(self):
        # rhea marks season 1 of ser1 favorite, e1 finds it, e3 and e4 then hit the season in FAVORITES
        self.fake.state['containerUserData'][('r1', 'sea1')] = user_data(fav=True)
        process = self.assertRun(0, ['m1', 'm2', 'm4'], '--user', 'niko,rhea', '--policy', 'any', '-vv')
        self.assertIn('season id sea1 already found in FAVORITES list', process.stderr)


class MediaTypeTest(FakeEmbyTestCase):
    """
    only Video items are deleted, anything else stops the run
    """

    def test_non_video_item_stops_the_run(self):
        podcast = {**movie('a1', 'Podcast'), 'MediaType': 'Audio'}
        self.fake.state['items'] = {'a1': (podcast, {'n1': finished(83)})}
        process = self.assertRun(2, [], '--user', 'niko')
        self.assertIn('Movie: Podcast media type is Audio', process.stderr)


if __name__ == '__main__':
    unittest.main()
