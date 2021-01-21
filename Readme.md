# Emby Media Remover based on time after played last

This script uses the emby API to get a list of played items.  
Items that have been played longer than the configured amount of days  
ago and are not marked as favorites will be removed.
It is taking into consideration that Seasons or Series can be marked as favorites.

This is useful in a scenario where an automated system is used to handle media and storage space should be reused.  

```
usage: main.py [-h] [--url URL] [--user USER] [--auth-token AUTH_TOKEN] [--days DAYS] [--verbose] [--dry-run]

optional arguments:
  -h, --help            show this help message and exit
  --url URL             emby host, can be specified as ENV EMBY_URL (default: None)
  --user USER           emby user, can be specified as ENV EMBY_USER (default: None)
  --auth-token AUTH_TOKEN
                        emby auth key, can be specified as ENV EMBY_TOKEN (default: None)
  --days DAYS, -d DAYS  delete items this amount of days after they have been played (default: 7)
  --verbose, -v
  --dry-run             dry run, do not actually remove torrents
  ```

the connection details and credentials can be provided from the environment.  
a Dockerfile is provided and can be used as follows:  
`docker build . -t remover && docker run -it remover`

Environment variables can be used with the Dockerfile as shown:  
`docker build . -t remover && docker run -it -e EMBY_URL -e EMBY_USER -e EMBY_TOKEN remover`
