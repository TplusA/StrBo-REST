#! /usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (C) 2021  T+A elektroakustik GmbH & Co. KG
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import argparse
import json
import requests
import websocket


def _register_connection(wsock, client_id):
    if client_id is None or client_id <= 0:
        return

    print('Registering on WebSocket')
    wsock.send(json.dumps({'op': 'register', 'client_id': client_id}))
    wsock.send(b'\0')


def _process_command_line():
    parser = argparse.ArgumentParser(description='StrBo REST event monitor')
    parser.add_argument(
        '--address', '-a', metavar='ADDR', type=str, required=True,
        help='address of the device to connect to'
    )
    parser.add_argument(
        '--port', '-p', metavar='PORT', type=int, default=8467,
        help='port to connect to'
    )
    parser.add_argument(
        '--client-id', '-i', metavar='ID', type=int,
        help='register with client ID assigned by StrBo API call'
    )
    args = parser.parse_args()
    return vars(args)


def _main():
    options = _process_command_line()

    addr = options['address'] + ':' + str(options['port'])
    requests.get('http://' + addr + '/v1/')

    ws_uri = 'ws://' + addr + '/events'
    print('Connect to {}'.format(ws_uri))
    wsock = websocket.create_connection(ws_uri)

    _register_connection(wsock, options['client_id'])

    print('Waiting for messages')

    while True:
        try:
            buffer = wsock.recv()
        except Exception as e:
            print('Failed reading from WebSocket: {}'.format(e))
            buffer = None
            break
        except KeyboardInterrupt:
            print('Terminating')
            buffer = None
            break

        if len(buffer) == 1 and buffer[0] == '\0':
            continue

        for buffer in buffer.split('\0'):
            if buffer:
                result = json.loads(buffer)
                print('Event: {}'.format(result))


if __name__ == '__main__':
    _main()
