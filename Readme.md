# Emby Media Remover based on time after played last

This script uses the emby API to get a list of played items.  
Items that have been played longer than the configured amount of days  
ago and are not marked as favorites will be removed.
It is taking into consideration that Seasons or Series can be marked as favorites.

This is useful in a scenario where an automated system is used to handle media and storage space should be reused.  

```
usage: main.py [-h] [--url URL] [--user USER] [--policy {user,all,majority,any}]
               [--working-set WORKING_SET] [--working-set-max-age WORKING_SET_MAX_AGE]
               [--auth-token AUTH_TOKEN] [--days DAYS] [--limit LIMIT] [--verbose] [--dry-run]

options:
  -h, --help            show this help message and exit
  --url URL             emby host, can be specified as ENV EMBY_URL (default: None)
  --user USER           emby user or comma separated list of users, see --policy, can be specified
                        as ENV EMBY_USER (default: None)
  --policy {user,all,majority,any}
                        how many of the listed users have to have played an item before it is
                        deleted, 'user' takes exactly one user, can be specified as ENV
                        EMBY_POLICY (default: all)
  --working-set WORKING_SET
                        JSON file of items that are never deleted, nothing is deleted if it is
                        missing or stale, can be specified as ENV EMBY_WORKING_SET (default: None)
  --working-set-max-age WORKING_SET_MAX_AGE
                        hours after which the working set file is stale (default: 6)
  --auth-token AUTH_TOKEN
                        emby auth key, can be specified as ENV EMBY_TOKEN (default: None)
  --days DAYS, -d DAYS  delete items this amount of days after they have been played (default: 7)
  --limit LIMIT, -l LIMIT
                        maximum number of items to delete (default: 50)
  --verbose, -v
  --dry-run             dry run, do not actually remove torrents
```

## Several users

When several users share a server, list all of them, e.g. `EMBY_USER=alice,bob`.  
A user has finished an item when they played it (play count above 0) longer than `--days` ago.  
`--policy` decides how many of the listed users have to have finished an item before it is removed:

- `user`: exactly one user is listed, and that user finished it
- `all` (default): every listed user finished it
- `majority`: more than half of the listed users finished it
- `any`: at least one listed user finished it

Whatever the policy, an item stays as long as any listed user has it in progress,
played it within `--days`, or marked it (or its Season or Series) as favorite.  
With `all`, an item only some of the users watch is never removed.

## Working set

`--working-set` points to a JSON file of items that must never be removed, e.g. what a sync tool still needs on this server.  
If the file is missing, unreadable, older than `--working-set-max-age` hours, dated more than 5 minutes in the future,
or does not cover one of the listed users,
the script exits with code 2 without removing anything.

```json
{
  "version": 1,
  "generated_at": "2026-10-23T20:18:04Z",
  "users": ["alice", "bob"],
  "items": [
    {"id": "<emby item id>", "path": "<item path as emby reports it>", "user": "bob", "reason": "in-progress"},
    {"id": null, "path": "<path the item will have>", "user": null, "reason": "staged"}
  ]
}
```

An item is kept if its id, its Season's or its Series' id matches an entry, or its path is an entry's path or lies under it;
a null id matches on the path only.
`generated_at` needs a timezone, `users` is optional, `user` and `reason` only show up in the log.

the connection details and credentials can be provided from the environment.  
a Dockerfile is provided and can be used as follows:  
`docker build . -t remover && docker run -it remover`

Environment variables can be used with the Dockerfile as shown:  
`docker build . -t remover && docker run -it -e EMBY_URL -e EMBY_USER -e EMBY_TOKEN remover`

With several users and a working set, mount the directory that holds the file (Docker would create a missing file as a directory):  
`docker run -it -e EMBY_URL -e EMBY_TOKEN -e EMBY_USER=alice,bob -e EMBY_POLICY=any -v /path/to/state:/working-set:ro -e EMBY_WORKING_SET=/working-set/working-set.json remover`

## Development

`pip install -r requirements-dev.txt`, then:

- `make test` runs `main.py` against a fake Emby server (`tests/fake_emby.py`) and fails below 90% line coverage
- `make check` runs pylint with `.pylintrc`
