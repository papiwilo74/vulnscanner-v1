from unittest.mock import patch

import responses

from scanner.crawler import crawl_site, detect_spa_signature
from scanner.headless_crawler import HeadlessCrawler


def test_detect_spa_signature():
    assert detect_spa_signature('<div id="root"></div>') is True
    assert detect_spa_signature('<html><body><div id="app"></div></body></html>') is True
    assert detect_spa_signature('<app-root>Loading...</app-root>') is True
    assert detect_spa_signature('<script id="__NEXT_DATA__" type="application/json">{}</script>') is True
    assert detect_spa_signature('<div ng-version="16.2.0">Angular App</div>') is True
    assert detect_spa_signature('<div data-v-12345678>Vue Scoped</div>') is True

    # Plain static HTML
    assert detect_spa_signature('<html><body><h1>Hello World</h1><p>Simple static page</p></body></html>') is False
    assert detect_spa_signature('') is False


@responses.activate
def test_crawl_site_spa_trigger():
    start_url = "https://spa-example.test/"
    responses.add(
        responses.GET,
        start_url,
        body='<html><div id="root"></div><script src="/bundle.js"></script></html>',
        status=200,
        headers={"Content-Type": "text/html"}
    )
    responses.add(
        responses.GET,
        "https://spa-example.test/sitemap.xml",
        status=404
    )
    responses.add(
        responses.GET,
        "https://spa-example.test/sitemap_index.xml",
        status=404
    )
    responses.add(
        responses.GET,
        "https://spa-example.test/robots.txt",
        status=404
    )

    with (
        patch("scanner.crawler.is_playwright_available", return_value=True),
        patch("scanner.headless_crawler.crawl_site_dynamic", return_value=(["https://spa-example.test/dashboard"], {"https://spa-example.test/api/user"})),
    ):
        pages = crawl_site(start_url, max_pages=5)
        assert "https://spa-example.test/dashboard" in pages
        assert "https://spa-example.test/api/user" in pages


def test_headless_crawler_unavailable():
    with patch("scanner.headless_crawler.is_playwright_available", return_value=False):
        crawler = HeadlessCrawler()
        links, apis, html = crawler.crawl_dynamic_page("https://example.com")
        assert links == []
        assert apis == set()
        assert html == ""
