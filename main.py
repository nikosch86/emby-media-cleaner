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
import pprint
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from functools import cache

import coloredlogs
import requests

LOGGER = logging.getLogger(__name__)
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
        cleanup_and_die(
            "argument '--{}' is required, specify through ENV or CLI".format(var))

# argparse does not check choices for defaults taken from ENV
POLICIES = {
    'user': lambda played, users: played == users,
    'all': lambda played, users: played == users,
    'majority': lambda played, users: played * 2 > users,
    'any': lambda played, users: played > 0,
}
if ARGS.policy not in POLICIES:
    cleanup_and_die("policy '%s' is not one of %s" % (ARGS.policy, ', '.join(POLICIES)))


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
            "%s%s" % (ARGS.url, path), headers=headers, data=data)
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        cleanup_and_die("got exception when trying to fetch token")

    if authenticationToken.status_code != requests.codes.ok:  # pylint: disable=E1101
        LOGGER.debug(authenticationToken.text)
        cleanup_and_die("got error code '%s' when trying to fetch token" % (
            authenticationToken.status_code))

    if 'AccessToken' not in authenticationToken.json():
        cleanup_and_die("something went wrong getting the access token")

    return authenticationToken.json()['AccessToken']


def get_played_items(itemUserId):
    """
    get played media ITEMS
    """
    # path = '/Items?Recursive=true&IsPlayed=true'
    path = "/Users/%s/Items?IncludeItemTypes=Episode,Movie&Recursive=true&IsPlayed=true&IsFavorite=false&Items=UserDataPlayCount,UserDataLastPlayedDate,UserDataIsFavorite" % (itemUserId)
    try:
        items = requests.get("%s%s" % (ARGS.url, path), headers={
                             'X-Emby-Token': EMBY_TOKEN})
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        cleanup_and_die("got exception when trying to get played items")

    if items.status_code != requests.codes.ok:  # pylint: disable=E1101
        LOGGER.debug(items.text)
        cleanup_and_die(
            "got error code '%s' when trying to get played items" % (items.status_code))

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
        LOGGER.debug(f"Cache hit for {itemUserId} {itemId}")
    # path = '/Items?Recursive=true&IsPlayed=true'
    path = "/Users/%s/Items/%s" % (itemUserId, itemId)
    try:
        items = requests.get("%s%s" % (ARGS.url, path), headers={
                             'X-Emby-Token': EMBY_TOKEN})
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        cleanup_and_die("got exception when trying to get item %s" % (itemId))

    if items.status_code != requests.codes.ok:  # pylint: disable=E1101
        LOGGER.debug(items.text)
        cleanup_and_die("got error code '%s' when trying to get item %s" % (
            items.status_code, itemId))

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
    path = "/Items/%s" % (itemId)
    try:
        deleteItem = requests.delete("%s%s" % (ARGS.url, path), headers={
                                     'X-Emby-Token': EMBY_TOKEN})
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
        LOGGER.warning(
            "connection error deleting item %s, skipping: %s", itemId, exc)
        return False

    if deleteItem.status_code != requests.codes.ok and deleteItem.status_code != 204:  # pylint: disable=E1101
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


def played_state(itemUserName, itemUserId, itemId):
    """
    return (keep, datePlayed): keep is True if the user still needs the item,
    because it is in progress, played after CUTOFF or favorite. datePlayed is
    when the user finished the item before CUTOFF, None if the user has not.
    """
    item = get_item(itemUserId, itemId)
    userData = item['UserData']
    if userData.get('PlaybackPositionTicks', 0) > 0:
        LOGGER.debug('%s "%s" in progress for %s', item['Type'], item['Name'], itemUserName)
        return True, None
    if recursive_fav(itemUserId, item):
        LOGGER.debug('%s "%s" is favorite for %s', item['Type'], item['Name'], itemUserName)
        return True, None
    if not userData.get('Played') or userData.get('PlayCount', 0) == 0 or not userData.get('LastPlayedDate'):
        LOGGER.debug('%s "%s" not played by %s', item['Type'], item['Name'], itemUserName)
        return False, None
    datePlayed = datetime.strptime(
        userData['LastPlayedDate'], '%Y-%m-%dT%H:%M:%S.0000000Z').replace(tzinfo=timezone.utc)
    if datePlayed > CUTOFF:
        LOGGER.debug('%s "%s" played too recently by %s', item['Type'], item['Name'], itemUserName)
        return True, None
    LOGGER.debug(
        f"{item['Type']}: '{item['Name']}' User: {itemUserName} Playcount: {userData['PlayCount']}")
    return False, datePlayed


def load_working_set(path):
    """
    return the working set entries by item id and by path, die if the file is
    missing, unreadable, older than --working-set-max-age or lacks a listed user
    """
    try:
        with open(path, encoding='utf-8') as workingSetFile:
            workingSet = json.load(workingSetFile)
        if workingSet['version'] != 1:
            raise ValueError("unsupported version %s" % (workingSet['version']))
        age = datetime.now(timezone.utc) - datetime.fromisoformat(workingSet['generated_at'])
        # id is null while the Target does not hold the item yet, path is set then
        byId = {entry['id']: entry for entry in workingSet['items'] if entry.get('id')}
        byPath = {entry['path']: entry for entry in workingSet['items'] if entry.get('path')}
        uncovered = [name for name, _ in USERS if name not in workingSet.get('users', [name])]
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        cleanup_and_die("working set %s is not usable, not deleting anything: %r" % (path, exc))
    if age > timedelta(hours=ARGS.working_set_max_age):
        cleanup_and_die("working set %s was generated %s ago, not deleting anything" % (path, age))
    if uncovered:
        cleanup_and_die("working set %s does not cover %s, not deleting anything" % (path, ', '.join(uncovered)))
    LOGGER.debug("working set has %s items, generated %s ago", len(byId), age)
    return byId, byPath


try:
    CHECK_EMBY_SERVER = requests.get("%s%s" % (ARGS.url, '/Users/Public'))
except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
    cleanup_and_die("emby is not reachable via %s" % (ARGS.url))

if CHECK_EMBY_SERVER.status_code != requests.codes.ok:  # pylint: disable=E1101
    cleanup_and_die("emby is not reachable via %s" % (ARGS.url))
else:
    PUBLIC_USERS = CHECK_EMBY_SERVER.json()

USER_IDS = {user['Name']: user['Id'] for user in PUBLIC_USERS}

USERS = list()
for userName in [name.strip() for name in ARGS.user.split(',') if name.strip()]:
    if userName not in USER_IDS:
        LOGGER.debug(PUBLIC_USERS)
        cleanup_and_die("%s is not a known user" % (userName))
    USERS.append((userName, USER_IDS[userName]))
if ARGS.policy == 'user' and len(USERS) != 1:
    cleanup_and_die("policy 'user' takes exactly one user, got %s" % (ARGS.user))

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
LOGGER.debug(f"got {len(ITEMS)} played items")
CUTOFF = datetime.now(timezone.utc) - timedelta(ARGS.days)
FAVORITES = set()
DELETED_ITEMS = 0
DELETED_ITEMS_STATS = defaultdict(int)
for listUserId, playedItem in ITEMS.values():
    keep = False
    playedDates = list()
    for checkUserName, checkUserId in USERS:
        keep, userPlayed = played_state(checkUserName, checkUserId, playedItem['Id'])
        if keep:
            break
        if userPlayed:
            playedDates.append(userPlayed)
    if keep or not POLICIES[ARGS.policy](len(playedDates), len(USERS)):
        continue
    daysSincePlayed = datetime.now(timezone.utc) - max(playedDates)
    userItem = get_item(listUserId, playedItem['Id'])

    if playedItem['MediaType'] != 'Video':
        cleanup_and_die("%s: %s media type is %s" % (
            playedItem['Type'], playedItem['Name'], playedItem['MediaType']))
    LOGGER.debug(playedItem)
    if playedItem['Type'] == 'Episode':
        season = get_item(listUserId, playedItem['SeasonId'])['Name']
        series = get_item(listUserId, playedItem['SeriesId'])['Name']
        LOGGER.info(
            f"{playedItem['Type']}: '{series}' '{season}' '{playedItem['Name']}' played {daysSincePlayed.days} days ago")
    elif playedItem['Type'] == 'Season':
        series = get_item(listUserId, playedItem['SeriesId'])['Name']
        LOGGER.info(
            f"{playedItem['Type']}: '{series}' '{season}' played {daysSincePlayed.days} days ago")
    else:
        LOGGER.info(
            f"{playedItem['Type']}: '{playedItem['Name']}' played {daysSincePlayed.days} days ago")

    workingSetEntry = WORKING_SET_IDS.get(playedItem['Id']) or WORKING_SET_PATHS.get(userItem.get('Path'))
    if workingSetEntry:
        LOGGER.info(
            f"{playedItem['Type']} '{playedItem['Name']}' is in the working set "
            f"({workingSetEntry.get('reason')} {workingSetEntry.get('user') or 'all users'}), skipping")
        continue

    if not userItem.get('CanDelete', True):
        LOGGER.warning(
            f"{playedItem['Type']} '{playedItem['Name']}' (id={playedItem['Id']}) reports CanDelete=false, skipping")
        continue

    if not delete_item(playedItem['Id']):
        continue

    if playedItem['Type'] == 'Episode':
        DELETED_ITEMS_STATS[series] += 1
    DELETED_ITEMS += 1
    if DELETED_ITEMS >= ARGS.limit:
        LOGGER.info(
            f"{DELETED_ITEMS} out of {ARGS.limit} items deleted, limit reached")
        break

for series, count in sorted(DELETED_ITEMS_STATS.items(), key=lambda item: item[1], reverse=True):
    LOGGER.info(f"{series}: {count}")
