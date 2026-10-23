#!/usr/bin/env python3
"""
remove content from emby based on watched status.
"""
import argparse
import getpass
import hashlib
import json
import logging
import os
import posixpath
import pprint
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from functools import cache

import coloredlogs
import requests

LOGGER = logging.getLogger(__name__)
REQUEST_TIMEOUT = 60
PP = pprint.PrettyPrinter(indent=2)

ARGPARSER = argparse.ArgumentParser()
ARGPARSER.add_argument(
    "--url",
    default=os.environ.get('EMBY_URL'),
    help="emby host, can be specified as ENV EMBY_URL (default: %(default)s)")
ARGPARSER.add_argument(
    "--user",
    default=os.environ.get('EMBY_USER'),
    help="emby user or comma separated list of users, see --policy, "
    "can be specified as ENV EMBY_USER (default: %(default)s)")
ARGPARSER.add_argument(
    "--policy",
    default=os.environ.get('EMBY_POLICY', 'all'),
    choices=['user', 'all', 'majority', 'any'],
    help="how many of the listed users have to have played an item before it is deleted, "
    "'user' takes exactly one user, can be specified as ENV EMBY_POLICY (default: %(default)s)")
ARGPARSER.add_argument(
    "--working-set",
    default=os.environ.get('EMBY_WORKING_SET'),
    help="JSON file of items that are never deleted, nothing is deleted if it is missing or stale, "
    "can be specified as ENV EMBY_WORKING_SET (default: %(default)s)")
ARGPARSER.add_argument(
    "--working-set-max-age",
    default=6,
    help="hours after which the working set file is stale (default: %(default)s)",
    type=int)
ARGPARSER.add_argument(
    "--accept-undated",
    default=os.environ.get('EMBY_ACCEPT_UNDATED', '').strip().lower() in ('1', 'true', 'yes'),
    help="count items played without a LastPlayedDate as played before --days, "
    "can be specified as ENV EMBY_ACCEPT_UNDATED=1 (default: %(default)s)",
    action="store_true")
ARGPARSER.add_argument(
    "--auth-token",
    default=os.environ.get('EMBY_TOKEN'),
    help="emby auth key, can be specified as ENV EMBY_TOKEN (default: %(default)s)")
ARGPARSER.add_argument(
    "--days", "-d",
    default=7,
    help="delete items this amount of days after they have been played (default: %(default)s)",
    type=int)
ARGPARSER.add_argument(
    "--limit", "-l",
    default=50,
    help="maximum number of items to delete (default: %(default)s)",
    type=int)
ARGPARSER.add_argument(
    "--verbose", "-v",
    action='count',
    default=0)
ARGPARSER.add_argument(
    "--dry-run",
    help="dry run, do not actually remove torrents",
    action="store_true")
ARGS = ARGPARSER.parse_args()

LEVELS = [logging.WARNING, logging.INFO, logging.DEBUG]
LEVEL = LEVELS[min(len(LEVELS)-1, ARGS.verbose)]
coloredlogs.install(level=LEVEL)

LOGGER.debug("running with DEBUG log level")


def cleanup_and_die(msg):
    """Cleanup and messages, then exit."""
    LOGGER.critical(msg)
    sys.exit(2)


for var in ['url', 'user']:
    if vars(ARGS).get(var):
        LOGGER.debug("%s set to %s", var, vars(ARGS).get(var))
    else:
        ARGPARSER.print_help(sys.stderr)
        cleanup_and_die(f"argument '--{var}' is required, specify through ENV or CLI")

# argparse does not check choices for defaults taken from ENV
POLICIES = {
    'user': lambda played, users: played == users,
    'all': lambda played, users: played == users,
    'majority': lambda played, users: played * 2 > users,
    'any': lambda played, users: played > 0,
}
if ARGS.policy not in POLICIES:
    cleanup_and_die(f"policy '{ARGS.policy}' is not one of {', '.join(POLICIES)}")


def get_auth_token(username, password):
    """Try to get emby authentication auth_token."""
    passwordSha = hashlib.sha1(password.encode()).hexdigest()
    path = '/Users/AuthenticateByName'
    headers = {'X-Emby-Authorization': 'Emby UserId="' + username +
               '", Client="emby-cleaner", Device="emby-cleaner", DeviceId="emby-cleaner", Version="0.1", Token=""'}  # pylint: disable=C0301
    data = {
        'Username': username,
        'Password': passwordSha,
        'Pw':       password,
    }
    try:
        authenticationToken = requests.post(
            f"{ARGS.url}{path}", headers=headers, data=data, timeout=REQUEST_TIMEOUT)
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        cleanup_and_die("got exception when trying to fetch token")

    if authenticationToken.status_code != requests.codes.ok:  # pylint: disable=E1101
        LOGGER.debug(authenticationToken.text)
        cleanup_and_die(f"got error code '{authenticationToken.status_code}' when trying to fetch token")

    if 'AccessToken' not in authenticationToken.json():
        cleanup_and_die("something went wrong getting the access token")

    return authenticationToken.json()['AccessToken']


def get_played_items(itemUserId):
    """
    get played media ITEMS
    """
    # path = '/Items?Recursive=true&IsPlayed=true'
    path = (f"/Users/{itemUserId}/Items?IncludeItemTypes=Episode,Movie&Recursive=true&IsPlayed=true"
            "&IsFavorite=false&Items=UserDataPlayCount,UserDataLastPlayedDate,UserDataIsFavorite")
    try:
        items = requests.get(f"{ARGS.url}{path}", headers={
                             'X-Emby-Token': EMBY_TOKEN}, timeout=REQUEST_TIMEOUT)
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        cleanup_and_die("got exception when trying to get played items")

    if items.status_code != requests.codes.ok:  # pylint: disable=E1101
        LOGGER.debug(items.text)
        cleanup_and_die(f"got error code '{items.status_code}' when trying to get played items")

    if 'Items' not in items.json():
        cleanup_and_die("something went wrong getting played items")

    return items.json()['Items']


@cache
def get_item(itemUserId, itemId):
    """
    get media ITEMS
    """
    cached = get_item.cache_info()
    if cached.hits > 0:
        LOGGER.debug("Cache hit for %s %s", itemUserId, itemId)
    # path = '/Items?Recursive=true&IsPlayed=true'
    path = f"/Users/{itemUserId}/Items/{itemId}"
    try:
        items = requests.get(f"{ARGS.url}{path}", headers={
                             'X-Emby-Token': EMBY_TOKEN}, timeout=REQUEST_TIMEOUT)
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        cleanup_and_die(f"got exception when trying to get item {itemId}")

    if items.status_code != requests.codes.ok:  # pylint: disable=E1101
        LOGGER.debug(items.text)
        cleanup_and_die(f"got error code '{items.status_code}' when trying to get item {itemId}")

    return items.json()


def delete_item(itemId):
    """
    delete item by id. Returns True on success, False on a per-item failure
    (so the loop can skip and continue rather than aborting the run).
    """
    if vars(ARGS).get('dry_run'):
        LOGGER.debug("[dry-run] _NOT_ removing item by id '%s'", itemId)
        return True

    LOGGER.debug("deleting item by id '%s'", itemId)
    path = f"/Items/{itemId}"
    try:
        deleteItem = requests.delete(f"{ARGS.url}{path}", headers={
                                     'X-Emby-Token': EMBY_TOKEN}, timeout=REQUEST_TIMEOUT)
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
        LOGGER.warning(
            "connection error deleting item %s, skipping: %s", itemId, exc)
        return False

    if deleteItem.status_code not in (requests.codes.ok, 204):  # pylint: disable=E1101
        LOGGER.warning(
            "Emby returned HTTP %s deleting item %s, skipping: %s",
            deleteItem.status_code, itemId, deleteItem.text[:200] if deleteItem.text else '')
        return False

    return True


def recursive_fav(itemUserId, item):
    """
    recursively check if item or parent is IsFavorite
    """
    LOGGER.debug('checking %s "%s"', item['Type'], item['Name'])
    if item['UserData']['IsFavorite']:
        LOGGER.debug('%s "%s" IsFavorite', item['Type'], item['Name'])
        return True

    if item['Type'] == 'Episode':
        if (itemUserId, item['SeriesId']) in FAVORITES:
            LOGGER.debug('%s: "%s" series id %s already found in FAVORITES list',
                         item['Type'], item['Name'], item['SeriesId'])
            return True
        if (itemUserId, item['SeasonId']) in FAVORITES:
            LOGGER.debug('%s: "%s" season id %s already found in FAVORITES list',
                         item['Type'], item['Name'], item['SeasonId'])
            return True
        if recursive_fav(itemUserId, get_item(itemUserId, item['SeasonId'])):
            FAVORITES.add((itemUserId, item['SeasonId']))
            LOGGER.debug('%s "%s" IsFavorite', item['Type'], item['Name'])
            return True

    if item['Type'] == 'Season':
        if recursive_fav(itemUserId, get_item(itemUserId, item['SeriesId'])):
            FAVORITES.add((itemUserId, item['SeriesId']))
            LOGGER.debug('%s "%s" IsFavorite', item['Type'], item['Name'])
            return True

    return False


def parse_date(value):
    """
    an Emby date as an aware datetime, naive dates taken as UTC, None if value is not a date
    """
    try:
        date = datetime.fromisoformat(value)
    except ValueError:
        return None
    return date if date.tzinfo else date.replace(tzinfo=timezone.utc)


def played_state(itemUserName, itemUserId, itemId):
    """
    return (keep, finished, datePlayed): keep if the user needs the item (in progress, played after CUTOFF,
    favorite), finished if the user played it before CUTOFF, datePlayed is None for an accepted undated play
    """
    item = get_item(itemUserId, itemId)
    userData = item['UserData']
    if userData.get('PlaybackPositionTicks', 0) > 0 or recursive_fav(itemUserId, item):
        LOGGER.debug('%s "%s" in progress or favorite for %s', item['Type'], item['Name'], itemUserName)
        return True, False, None
    if not userData.get('Played'):
        LOGGER.debug('%s "%s" not played by %s', item['Type'], item['Name'], itemUserName)
        return False, False, None
    lastPlayed = userData.get('LastPlayedDate') or ''
    # .NET's empty DateTime is no date either
    if lastPlayed.startswith('0001-01-01'):
        lastPlayed = ''
    if not lastPlayed and ARGS.accept_undated:
        LOGGER.debug('%s "%s" played by %s at an unknown date', item['Type'], item['Name'], itemUserName)
        return False, True, None
    datePlayed = parse_date(lastPlayed)
    if datePlayed is None:
        LOGGER.info('%s "%s" played by %s has no usable LastPlayedDate (%s), not counting that play',
                    item['Type'], item['Name'], itemUserName, userData.get('LastPlayedDate'))
        return False, False, None
    if datePlayed > CUTOFF:
        LOGGER.debug('%s "%s" played too recently by %s', item['Type'], item['Name'], itemUserName)
        return True, False, None
    LOGGER.debug("%s: '%s' User: %s Playcount: %s", item['Type'], item['Name'], itemUserName, userData.get('PlayCount'))
    return False, True, datePlayed


def load_working_set(path):
    """
    return the working set entries by item id and by path, die if the file is missing, unreadable,
    of another version, without timezone, stale, from the future or lacking a listed user
    """
    try:
        with open(path, encoding='utf-8') as workingSetFile:
            workingSet = json.load(workingSetFile)
        if workingSet['version'] != 1:
            raise ValueError(f"unsupported version {workingSet['version']}")
        age = datetime.now(timezone.utc) - datetime.fromisoformat(workingSet['generated_at'])
        # id is null while this server does not hold the item yet, path is set then
        byId = {entry['id']: entry for entry in workingSet['items'] if entry.get('id')}
        byPath = {entry['path'].rstrip('/'): entry for entry in workingSet['items'] if entry.get('path')}
        uncovered = [name for name, _ in USERS if name not in workingSet.get('users', [name])]
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        cleanup_and_die(f"working set {path} is not usable, not deleting anything: {exc!r}")
    if age > timedelta(hours=ARGS.working_set_max_age):
        cleanup_and_die(f"working set {path} was generated {age} ago, not deleting anything")
    # a generated_at in the future would never become stale
    if age < -timedelta(minutes=5):
        cleanup_and_die(f"working set {path} was generated {-age} in the future, not deleting anything")
    if uncovered:
        cleanup_and_die(f"working set {path} does not cover {', '.join(uncovered)}, not deleting anything")
    LOGGER.debug("working set has %s items, generated %s ago", len(byId), age)
    return byId, byPath


def working_set_entry(item):
    """
    return the working set entry that covers the item, its season or series
    (by id, or by a path the item lies under), None if there is none
    """
    for coveringId in (item['Id'], item.get('SeasonId'), item.get('SeriesId')):
        if coveringId in WORKING_SET_IDS:
            return WORKING_SET_IDS[coveringId]
    path = item.get('Path') or ''
    while path not in WORKING_SET_PATHS and path not in ('', '/'):
        path = posixpath.dirname(path)
    return WORKING_SET_PATHS.get(path)


try:
    CHECK_EMBY_SERVER = requests.get(f"{ARGS.url}/Users/Public", timeout=REQUEST_TIMEOUT)
except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
    cleanup_and_die(f"emby is not reachable via {ARGS.url}")

if CHECK_EMBY_SERVER.status_code != requests.codes.ok:  # pylint: disable=E1101
    cleanup_and_die(f"emby is not reachable via {ARGS.url}")
else:
    PUBLIC_USERS = CHECK_EMBY_SERVER.json()

USER_IDS = {user['Name']: user['Id'] for user in PUBLIC_USERS}

USERS = []
for userName in [name.strip() for name in ARGS.user.split(',') if name.strip()]:
    if userName not in USER_IDS:
        LOGGER.debug(PUBLIC_USERS)
        cleanup_and_die(f"{userName} is not a known user")
    USERS.append((userName, USER_IDS[userName]))
if ARGS.policy == 'user' and len(USERS) != 1:
    cleanup_and_die(f"policy 'user' takes exactly one user, got {ARGS.user}")

if not vars(ARGS).get('auth_token'):
    LOGGER.warning(
        'no access token specified, in order to fetch the token an admin user is required')
    EMBY_ADMIN = getpass.getpass(prompt="Please enter admin username\n")
    EMBY_PASS = getpass.getpass(prompt="Please enter admin password\n")
    EMBY_TOKEN = get_auth_token(EMBY_ADMIN, EMBY_PASS)
    LOGGER.warning(
        'access token was fetched successfully, please save for future use:\n%s', EMBY_TOKEN)
else:
    EMBY_TOKEN = ARGS.auth_token

WORKING_SET_IDS, WORKING_SET_PATHS = load_working_set(ARGS.working_set) if ARGS.working_set else ({}, {})

# with 'all' the first user's played items already hold every candidate
ITEMS = {}
for _, listUserId in (USERS[:1] if ARGS.policy == 'all' else USERS):
    for playedItem in get_played_items(listUserId):
        ITEMS.setdefault(playedItem['Id'], (listUserId, playedItem))
if len(ITEMS) == 0:
    LOGGER.info("no played items found, nothing to clean up")
    sys.exit(0)
LOGGER.debug("got %s played items", len(ITEMS))
CUTOFF = datetime.now(timezone.utc) - timedelta(ARGS.days)
FAVORITES = set()
deletedItems = 0
DELETED_ITEMS_STATS = defaultdict(int)
for listUserId, playedItem in ITEMS.values():
    keep = False
    finishedUsers = 0
    playedDates = []
    for checkUserName, checkUserId in USERS:
        keep, userFinished, userPlayed = played_state(checkUserName, checkUserId, playedItem['Id'])
        if keep:
            break
        finishedUsers += userFinished
        if userPlayed:
            playedDates.append(userPlayed)
    if keep or not POLICIES[ARGS.policy](finishedUsers, len(USERS)):
        continue
    playedWhen = f"{(datetime.now(timezone.utc) - max(playedDates)).days} days ago" if playedDates \
        else "at an unknown date"
    userItem = get_item(listUserId, playedItem['Id'])

    if playedItem['MediaType'] != 'Video':
        cleanup_and_die(f"{playedItem['Type']}: {playedItem['Name']} media type is {playedItem['MediaType']}")
    LOGGER.debug(playedItem)
    if playedItem['Type'] == 'Episode':
        season = get_item(listUserId, playedItem['SeasonId'])['Name']
        series = get_item(listUserId, playedItem['SeriesId'])['Name']
        LOGGER.info("%s: '%s' '%s' '%s' played %s", playedItem['Type'], series, season, playedItem['Name'], playedWhen)
    else:
        LOGGER.info("%s: '%s' played %s", playedItem['Type'], playedItem['Name'], playedWhen)

    workingSetEntry = working_set_entry(userItem)
    if workingSetEntry:
        LOGGER.info("%s '%s' is in the working set (%s %s), skipping", playedItem['Type'], playedItem['Name'],
                    workingSetEntry.get('reason'), workingSetEntry.get('user') or 'all users')
        continue

    if not userItem.get('CanDelete', True):
        LOGGER.warning("%s '%s' (id=%s) reports CanDelete=false, skipping",
                       playedItem['Type'], playedItem['Name'], playedItem['Id'])
        continue

    if not delete_item(playedItem['Id']):
        continue

    if playedItem['Type'] == 'Episode':
        DELETED_ITEMS_STATS[series] += 1
    deletedItems += 1
    if deletedItems >= ARGS.limit:
        LOGGER.info("%s out of %s items deleted, limit reached", deletedItems, ARGS.limit)
        break

for series, count in sorted(DELETED_ITEMS_STATS.items(), key=lambda item: item[1], reverse=True):
    LOGGER.info("%s: %s", series, count)
