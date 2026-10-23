#!/usr/bin/env python3
"""
remove content from emby based on watched status.
"""
import argparse
import getpass
import hashlib
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
    help="emby user, or a comma separated list of users that all have to have played an item "
    "before it is deleted, can be specified as ENV EMBY_USER (default: %(default)s)")
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

    if len(items.json()['Items']) == 0:
        LOGGER.info("no played items found, nothing to clean up")
        sys.exit(0)

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


def played_before_cutoff(itemUserName, itemUserId, itemId):
    """
    return when the user finished the item, or None if the item has to be kept
    for that user: not played, in progress, played after CUTOFF or favorite
    """
    item = get_item(itemUserId, itemId)
    userData = item['UserData']
    if not userData.get('Played') or userData.get('PlayCount', 0) == 0:
        LOGGER.debug('%s "%s" not played by %s', item['Type'], item['Name'], itemUserName)
        return None
    if userData.get('PlaybackPositionTicks', 0) > 0:
        LOGGER.debug('%s "%s" in progress for %s', item['Type'], item['Name'], itemUserName)
        return None
    if not userData.get('LastPlayedDate'):
        LOGGER.debug('%s "%s" has no LastPlayedDate for %s', item['Type'], item['Name'], itemUserName)
        return None
    datePlayed = datetime.strptime(
        userData['LastPlayedDate'], '%Y-%m-%dT%H:%M:%S.0000000Z').replace(tzinfo=timezone.utc)
    if datePlayed > CUTOFF:
        return None
    LOGGER.debug(
        f"{item['Type']}: '{item['Name']}' User: {itemUserName} Playcount: {userData['PlayCount']}")
    if recursive_fav(itemUserId, item):
        LOGGER.debug("item is favorite for %s, skip", itemUserName)
        return None
    return datePlayed


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
# played items of the first user are the candidates, every user has to have played them
userId = USERS[0][1]

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

ITEMS = get_played_items(userId)
LOGGER.debug(f"got {len(ITEMS)} played items")
CUTOFF = datetime.now(timezone.utc) - timedelta(ARGS.days)
FAVORITES = set()
DELETED_ITEMS = 0
DELETED_ITEMS_STATS = defaultdict(int)
for playedItem in ITEMS:
    lastPlayedDates = list()
    for checkUserName, checkUserId in USERS:
        lastPlayed = played_before_cutoff(checkUserName, checkUserId, playedItem['Id'])
        if lastPlayed is None:
            break
        lastPlayedDates.append(lastPlayed)
    if len(lastPlayedDates) < len(USERS):
        continue
    daysSincePlayed = datetime.now(timezone.utc) - max(lastPlayedDates)
    userItem = get_item(userId, playedItem['Id'])

    if playedItem['MediaType'] != 'Video':
        cleanup_and_die("%s: %s media type is %s" % (
            playedItem['Type'], playedItem['Name'], playedItem['MediaType']))
    LOGGER.debug(playedItem)
    if playedItem['Type'] == 'Episode':
        season = get_item(userId, playedItem['SeasonId'])['Name']
        series = get_item(userId, playedItem['SeriesId'])['Name']
        LOGGER.info(
            f"{playedItem['Type']}: '{series}' '{season}' '{playedItem['Name']}' played {daysSincePlayed.days} days ago")
    elif playedItem['Type'] == 'Season':
        series = get_item(userId, playedItem['SeriesId'])['Name']
        LOGGER.info(
            f"{playedItem['Type']}: '{series}' '{season}' played {daysSincePlayed.days} days ago")
    else:
        LOGGER.info(
            f"{playedItem['Type']}: '{playedItem['Name']}' played {daysSincePlayed.days} days ago")

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
