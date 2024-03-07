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
from datetime import datetime, timedelta
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
    help="emby user, can be specified as ENV EMBY_USER (default: %(default)s)")
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
        cleanup_and_die("no items found")

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
    delete item by id
    """
    if vars(ARGS).get('dry_run'):
        LOGGER.debug("[dry-run] _NOT_ removing item by id '%s'", itemId)
        return

    LOGGER.debug("deleting item by id '%s'", itemId)
    path = "/Items/%s" % (itemId)
    try:
        deleteItem = requests.delete("%s%s" % (ARGS.url, path), headers={
                                     'X-Emby-Token': EMBY_TOKEN})
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        cleanup_and_die(
            "got exception when trying to delete item %s" % (itemId))

    if deleteItem.status_code != requests.codes.ok and deleteItem.status_code != 204:  # pylint: disable=E1101
        LOGGER.debug(deleteItem.text)
        cleanup_and_die("got error code '%s' when trying to delete item %s" % (
            deleteItem.status_code, itemId))


def recursive_fav(itemUserId, item):
    """
    recursively check if item or parent is IsFavorite
    """
    LOGGER.debug('checking %s "%s"', item['Type'], item['Name'])
    if item['UserData']['IsFavorite']:
        LOGGER.debug('%s "%s" IsFavorite', item['Type'], item['Name'])
        return True

    if item['Type'] == 'Episode':
        if item['SeriesId'] in FAVORITES:
            LOGGER.debug('%s: "%s" series id %s already found in FAVORITES list',
                         item['Type'], item['Name'], item['SeriesId'])
            return True
        if item['SeasonId'] in FAVORITES:
            LOGGER.debug('%s: "%s" season id %s already found in FAVORITES list',
                         item['Type'], item['Name'], item['SeasonId'])
            return True
        if recursive_fav(itemUserId, get_item(userId, item['SeasonId'])):
            FAVORITES.append(item['SeasonId'])
            LOGGER.debug('%s "%s" IsFavorite', item['Type'], item['Name'])
            return True

    if item['Type'] == 'Season':
        if recursive_fav(itemUserId, get_item(userId, item['SeriesId'])):
            FAVORITES.append(item['SeriesId'])
            LOGGER.debug('%s "%s" IsFavorite', item['Type'], item['Name'])
            return True

    return False


try:
    CHECK_EMBY_SERVER = requests.get("%s%s" % (ARGS.url, '/Users/Public'))
except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
    cleanup_and_die("emby is not reachable via %s" % (ARGS.url))

if CHECK_EMBY_SERVER.status_code != requests.codes.ok:  # pylint: disable=E1101
    cleanup_and_die("emby is not reachable via %s" % (ARGS.url))
else:
    PUBLIC_USERS = CHECK_EMBY_SERVER.json()

USER_LIST = list()
for user in PUBLIC_USERS:
    USER_LIST.append(user['Name'])

if ARGS.user not in USER_LIST:
    LOGGER.debug(PUBLIC_USERS)
    cleanup_and_die("%s is not a known user" % (ARGS.user))
else:
    for user in PUBLIC_USERS:
        if ARGS.user == user['Name']:
            userId = user['Id']

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
CUTOFF = datetime.utcnow() - timedelta(ARGS.days)
FAVORITES = list()
DELETED_ITEMS = 0
DELETED_ITEMS_STATS = defaultdict(int)
for playedItem in ITEMS:
    if 'Played' in playedItem['UserData']:
        if playedItem['UserData']['Played'] and playedItem['UserData']['PlayCount'] > 0:
            lastPlayed = datetime.strptime(
                playedItem['UserData']['LastPlayedDate'], '%Y-%m-%dT%H:%M:%S.0000000Z')
            daysSincePlayed = datetime.utcnow() - lastPlayed
            if lastPlayed > CUTOFF:
                continue
            LOGGER.debug(
                f"{playedItem['Type']}: '{playedItem['Name']}' Fav: {playedItem['UserData']['IsFavorite']} Playcount: {playedItem['UserData']['PlayCount']}")
            if recursive_fav(userId, playedItem):
                LOGGER.debug("item is favorite, skip")
                continue

            if playedItem['MediaType'] != 'Video':
                cleanup_and_die("%s: %s media type is %s" % (
                    playedItem['Type'], playedItem['Name'], playedItem['MediaType']))
            LOGGER.debug(playedItem)
            if playedItem['Type'] == 'Episode':
                season = get_item(userId, playedItem['SeasonId'])['Name']
                series = get_item(userId, playedItem['SeriesId'])['Name']
                LOGGER.info(
                    f"{playedItem['Type']}: '{series}' '{season}' '{playedItem['Name']}' played {daysSincePlayed.days} days ago")
                DELETED_ITEMS_STATS[series] += 1
            elif playedItem['Type'] == 'Season':
                series = get_item(userId, playedItem['SeriesId'])['Name']
                LOGGER.info(
                    f"{playedItem['Type']}: '{series}' '{season}' played {daysSincePlayed.days} days ago")
            else:
                LOGGER.info(
                    f"{playedItem['Type']}: '{playedItem['Name']}' played {daysSincePlayed.days} days ago")
            delete_item(playedItem['Id'])
            DELETED_ITEMS += 1
            if DELETED_ITEMS >= ARGS.limit:
                LOGGER.info(
                    f"{DELETED_ITEMS} out of {ARGS.limit} items deleted, limit reached")
                break

for series, count in sorted(DELETED_ITEMS_STATS.items(), key=lambda item: item[1], reverse=True):
    LOGGER.info(f"{series}: {count}")
