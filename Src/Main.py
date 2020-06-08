"""
A test URL writing program, going t
"""
from mitmproxy import http
from mitmproxy.net.http.http1.assemble import assemble_request
from bs4 import BeautifulSoup
from mitmproxy import ctx, http

from mitmproxy.net.http.http1.assemble import _assemble_response_headers, assemble_response


def request(flow: http.HTTPFlow) -> None:
    # alles wat in de persoon zijn requist zit kan je hier vragen.

    with open("C:/Users/Orang/PycharmProjects/Ipass/Src/textfile.txt", "a")as test:
        url = flow.request.pretty_url + "\n"
        test.write(url)

    if flow.request.pretty_url == "http://example.com/path":
        flow.response = http.HTTPResponse.make(
            200,  # (optional) status code
            b"Hello World",  # (optional) content
            {"Content-Type": "text/html"}  # (optional) headers
        )


def response(flow: http.HTTPFlow):
    # alles wat in de response zit kan je hier vragen.
    with open("C:/Users/Orang/PycharmProjects/Ipass/Src/test2html.txt", "a+")as test:
        data = assemble_request(flow.request).decode('utf-8')
        httpdata = BeautifulSoup(flow.response.content, "html.parser")
        httptext = httpdata.get_text()
        test.write(httptext)
