#!/usr/bin/env python3
import h11

# Simulate a simple GET request
request_data = b'GET /health HTTP/1.1\r\nHost: localhost\r\nUser-Agent: curl/8.14.1\r\nAccept: */*\r\n\r\n'

print(f"Testing h11 parsing with data: {request_data[:100]}...")

conn = h11.Connection(h11.SERVER)
conn.receive_data(request_data)

hostname = None
while True:
    event = conn.next_event()
    print(f'Event: {type(event).__name__} - {event}')
    
    if event is h11.NEED_DATA:
        print('Need more data')
        break
    elif isinstance(event, h11.Request):
        print(f'Request: {event.method} {event.target}')
        # Headers are in event.headers
        print(f'Headers in Request event: {event.headers}')
        for name, value in event.headers:
            print(f'  {name}={value}')
            if name.lower() == b'host':
                hostname = value.decode('utf-8')
    elif isinstance(event, (h11.EndOfMessage, h11.Data)):
        print(f'End of message/data')
        break

print(f'\nExtracted hostname: {hostname}')