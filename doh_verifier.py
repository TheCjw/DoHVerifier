#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import concurrent.futures
import base64
import io
from struct import unpack
import re

import requests
from requests import ConnectTimeout
from requests import ReadTimeout
from tabulate import tabulate
import maxminddb

from libs.log import logger

reader = maxminddb.open_database("GeoLite2-Country.mmdb")


def parse_resolvers(content):
    result = re.findall(r"^##.+?(?P<resolver>.+$)(?P<description>(\n|.)+?)(?P<stamp>^sdns.+)",
                        content, re.M)
    if result is None:
        return None

    resolvers = []
    for r in result:
        # Skip sdns://
        stamp = r[3][7:]

        # FIX Padding.
        stamp += "=" * ((4 - len(stamp) % 4) % 4)
        decoded_stamp = base64.urlsafe_b64decode(stamp)

        stream = io.BytesIO(decoded_stamp)
        # https://github.com/jedisct1/dnscrypt-proxy/wiki/stamps

        flag = unpack("B", stream.read(1))[0]

        # Parse DNS-over-HTTPS only.
        if flag != 0x02:
            continue

        resolver = {}

        resolver["name"] = r[0]
        resolver["ip_address"] = ""

        props = unpack("Q", stream.read(8))[0]

        _len = unpack("B", stream.read(1))[0]
        if _len != 0:
            # can be empty.
            ip_address = stream.read(_len)
            resolver["ip_address"] = ip_address.decode()

        # https://github.com/jedisct1/dnscrypt-proxy/blob/master/vendor/github.com/jedisct1/go-dnsstamps/dnsstamps.go#L159
        while True:
            vlen = unpack("B", stream.read(1))[0]
            _len = vlen & (~0x80)
            if _len > 0:
                hashes = stream.read(_len)

            if (vlen & 0x80) != 0x80:
                break

        _len = unpack("B", stream.read(1))[0]
        host = None
        if _len != 0:
            host = stream.read(_len)

        _len = unpack("B", stream.read(1))[0]
        path = None
        if _len != 0:
            path = stream.read(_len)

        resolver["url"] = f"https://{host.decode()}{path.decode()}"
        resolvers.append(resolver)

    return resolvers


def test_resolver(resolver):
    logger.debug(f"Querying {resolver['name']}")
    try:
        params = {
            "name": "dl.google.com"
        }
        r = requests.get(resolver["url"], params=params, timeout=2)
        resolver["latency(ms)"] = int(r.elapsed.total_seconds() * 1000)

        for answer in r.json()["Answer"]:
            if answer["type"] == 1:
                ip = answer["data"]
                country = reader.get(ip)
                resolver["google"] = f"{ip}({country['country']['iso_code']})"
                break
    except (ConnectTimeout, ReadTimeout):
        resolver["latency(ms)"] = "timeout"
    return resolver


def main():
    content = open("public-resolvers.md", encoding="utf-8").read()
    resolvers = parse_resolvers(content)

    ipv4_resolvers = []
    for resolver in resolvers:
        ip_address = resolver["ip_address"]
        if len(ip_address):
            # Ignore ipv6
            if ip_address[0] == "[":
                continue
        ipv4_resolvers.append(resolver)

    result = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_list = {executor.submit(
            test_resolver, resolver): resolver for resolver in ipv4_resolvers}
        for future in concurrent.futures.as_completed(future_list):
            try:
                if future.result():
                    result.append(future.result())
            except:
                pass

    print(tabulate(result, headers="keys", tablefmt="github"))


if __name__ == "__main__":
    main()
