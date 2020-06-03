"""
A test URL writing program, going t
"""
from mitmproxy import http


def request(flow: http.HTTPFlow) -> None:
    # pretty_url takes the "Host" header of the request into account, which
    # is useful in transparent mode where we usually only have the IP otherwise.

    with open("C:/Users/Orang/PycharmProjects/Ipass/Src/textfile.txt","a")as test:
        url = flow.request.pretty_url + "\n"
        test.write(url)


    if flow.request.pretty_url == "http://example.com/path":
        flow.response = http.HTTPResponse.make(
            200,  # (optional) status code
            b"Hello World",  # (optional) content
            {"Content-Type": "text/html"}  # (optional) headers
        )