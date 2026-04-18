"""Crawler module — intelligent web crawling and endpoint discovery."""

from sentinal_fuzz.crawler.base import BaseCrawler, CrawlState
from sentinal_fuzz.crawler.crawler_factory import get_crawler
from sentinal_fuzz.crawler.http_crawler import HttpCrawler
from sentinal_fuzz.crawler.js_crawler import JsCrawler, merge_endpoints

__all__ = [
    "BaseCrawler",
    "CrawlState",
    "HttpCrawler",
    "JsCrawler",
    "get_crawler",
    "merge_endpoints",
]
