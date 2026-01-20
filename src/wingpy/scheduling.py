# SPDX-License-Identifier: GPL-3.0-or-later
#
# Copyright (C) 2025 Wingmen Solutions ApS
# This file is part of wingpy, distributed under the terms of the GNU GPLv3.
# See the LICENSE, NOTICE, and AUTHORS files for more information.
"""
Most API interaction can be optimized by utilizing conrurency while also
adapting to rate limits. This module provides a set of classes to handle
asynchronous tasks and request throttling and in way makes sure that the
API is not overloaded with requests while also reaching maximum performance.
"""

import asyncio
import math
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from time import sleep
from typing import Any, ParamSpec, TypeVar

import arrow
import httpx

from wingpy.logger import logger


@dataclass
class RequestLogEntry:
    """
    Log entry for a sent request.
    """

    status_code: int
    """The HTTP status code of the response."""

    timestamp: arrow.Arrow
    """The timestamp of when the request was sent."""

    url: str | None
    """The URL of the request."""


P = ParamSpec("P")
R = TypeVar("R")


class TaskRunner:
    """
    Manage and execute asynchronous tasks using a thread pool executor with a specified number of worker threads.
    """

    def __init__(self, max_workers: int) -> None:
        self.max_workers: int = max_workers
        """The maximum number of worker threads to use in the thread pool."""

        self.loop: asyncio.AbstractEventLoop = asyncio.new_event_loop()
        """The event loop used to manage asynchronous tasks."""

        self.tasks: set[asyncio.Task[Any]] = set()
        """A set of scheduled asyncio tasks."""

        self._lock: threading.Lock = threading.Lock()
        """
        A threading lock to ensure concurrent requests are synchronized in terms of throttling and logging.
        """

        asyncio.set_event_loop(self.loop)
        self.loop.set_default_executor(ThreadPoolExecutor(max_workers=self.max_workers))

    def schedule(
        self,
        func: Callable[P, R],
        *args: P.args,
        _task_name: str | None = None,  # type: ignore
        **kwargs: P.kwargs,
    ) -> None:
        """
        Schedule a function to be run asynchronously.

        Parameters
        ----------
        func
            The function to be executed.
        _task_name
            Optional name for the task. If not provided, a name will be
            generated, similar to `task-xxxxxxxxxx`.
        *args
            Positional arguments to pass to the function.
        **kwargs
            Keyword arguments to pass to the function.
        """
        logger.trace(
            f"Scheduling task: {func.__name__} with args: {args} and kwargs: {kwargs}"
        )
        task = asyncio.Task(asyncio.to_thread(func, *args, **kwargs), loop=self.loop)
        task.set_name(_task_name or f"task-{id(task)}")
        self.tasks.add(task)

    def run(self) -> dict[str, Any]:
        """
        Run all scheduled tasks and return their results.

        Returns
        -------
        dict[str, Any]
            A dictionary where each key is the name of a task and the value is
            the result of that task.
        """
        results = {}

        if len(self.tasks) > 0:
            self.loop.run_until_complete(
                asyncio.gather(*self.tasks, return_exceptions=True)
            )
            results = {task.get_name(): task.result() for task in self.tasks}
            self.tasks.clear()

        return results


class RequestThrottler:
    """
    Handle request throttling for API calls through exponential backoff and
    adjusting to rate limiting.
    """

    def __init__(
        self,
        *,
        backoff_initial: float = 1.0,
        backoff_multiplier: float = 2.0,
        rate_limit_period: float = 0.0,
        rate_limit_max_requests: int = 0,
    ) -> None:
        self.backoff_initial: float = backoff_initial
        """The initial delay for exponential backoff."""

        self.backoff_multiplier: float = backoff_multiplier
        """The multiplier for exponential backoff."""

        self.rate_limit_period: float = rate_limit_period
        """The period for rate limiting in seconds."""

        self.rate_limit_max_requests: int = rate_limit_max_requests
        """The maximum number of requests allowed in the rate limit period."""

        self._backoff_delay: float = 0.0
        """The current backoff delay."""

        self._start_time: arrow.Arrow | None = None
        """The start time of the latest backoff."""

        self._end_time: arrow.Arrow | None = None
        """The end time of the latest backoff."""

    def wait_for_backoff(self, *, start_time: arrow.Arrow) -> None:
        """
        Returns after waiting for the exponential backoff timer.

        Usefull when the API does not provide a Retry-After header and the rate
        limit period of the API is not known.

        Parameters
        ----------
        start_time
            Due to multiple threads, the start time is passed as a parameter to
            ensure that the delay is calculated from the point in time where
            the the request was sent.

        """
        total_delay = self.calculate_delay_from_backoff() + 1
        self.ensure_delay(start_time=start_time, delay=total_delay)

    def wait_for_rate_limit(
        self,
        *,
        start_time: arrow.Arrow,
        response: httpx.Response,
        request_log: list[RequestLogEntry],
    ) -> None:
        """
        Returns after waiting for the rate limit timer.

        Usefull when the API provides a Retry-After header or when the rate
        limit period is known.

        Parameters
        ----------
        start_time
            Due to multiple threads, the start time is passed as a parameter to
            ensure that the delay is calculated from the point in time where
            the the request was sent.
        response
            Response object from the API call with HTTP status code 429 (Too
            Many Requests).
        request_log
            A list of request log entries leading up to the rate limit response.
        """

        if self._end_time is None or start_time > self._end_time:
            total_delay = self.calculate_delay_from_rate_limit(
                start_time=start_time,
                response=response,
                request_log=request_log,
            )
            self.ensure_delay(start_time=start_time, delay=total_delay)

    def ensure_delay(self, *, start_time: arrow.Arrow, delay: float | int) -> None:
        """
        Sleeps until the time has passed.

        Parameters
        ----------
        start_time
            Start timestamp of the delay period.
        delay
            The delay in seconds to sleep before continuing.
        """

        self._end_time = start_time.shift(seconds=delay)

        # Due to multiple threads we need to account for the time it took may lead to a negative delay
        retry_delay = math.ceil(
            max((self._end_time - arrow.utcnow()).total_seconds(), 0)
        )

        # Reset the backoff delay if it exceeds the rate limit period
        if self.rate_limit_period and self._backoff_delay > self.rate_limit_period:
            self.reset_backoff()
            retry_delay = self._backoff_delay

        logger.info(f"Delaying for {retry_delay} seconds")
        logger.trace(f"Continuing {round(delay, 1)} seconds after {start_time})")
        sleep(retry_delay)

    def calculate_delay_from_rate_limit(
        self,
        *,
        start_time: arrow.Arrow,
        response: httpx.Response,
        request_log: list[RequestLogEntry],
    ) -> float:
        """
        Calculate a delay based on server rate limiting.

        This method checks for the Retry-After header in the response and
        calculates the delay accordingly. If the header is not present, it
        uses the platform-specific rate limit values to determine the delay.
        If neither is available, it falls back to exponential backoff.

        Parameters
        ----------
        start_time
            Due to multiple threads, the start time is passed as a parameter to
            ensure that the delay is calculated from the point in time where
            the the request was sent.
        response
            The HTTP response object from the API call. Used to check for the
            Retry-After header.
        request_log
            A list of request log entries leading up to the rate limit
            response. Used to calculate the run rate and oldest request timestamp
            in case the Retry-After header is not present.

        Returns
        -------
        float
            The calculated delay in seconds.
        """
        # Look for Retry-After header and use it to determine delay
        retry_after = response.headers.get("Retry-After")

        if retry_after:
            delay = self.calculate_delay_from_header(
                start_time=start_time, retry_after=retry_after
            )

        # If no Retry-After header is received, use platform specific rate limit values
        elif self.rate_limit_period:
            delay = self.calculate_delay_from_period(request_log=request_log)

        # Exponential backoff is last resort
        else:
            logger.debug("No Retry-After header received. Doing exponential backoff")
            delay = self.calculate_delay_from_backoff()

        return max(delay, self.backoff_initial)

    def calculate_delay_from_header(
        self, *, start_time: arrow.Arrow, retry_after: str
    ) -> float:
        """
        Calculate the delay based on the Retry-After header.

        Two different valid formats exists: `Retry-After: <delay-seconds>`
        and `Retry-After: <http-date>`

        Parameters
        ----------
        start_time
            Due to multiple threads, the start time is passed as a parameter to
            ensure that the delay is calculated from the point in time where
            the the request was sent.
        retry_after
            The value of the Retry-After header from an HTTP response.

        Returns
        -------
        float
            The calculated delay in seconds.
        """
        logger.debug(f"Received header Retry-After: {retry_after}")

        if retry_after.isdigit():
            # Numeric value is <delay-seconds>
            delay = int(retry_after)
        else:
            # String value is <http-date>
            target_time = arrow.get(
                retry_after,
                "ddd, D MMM YYYY HH:mm:ss ZZZ",
            )
            delta_seconds = (target_time - start_time).total_seconds()
            delay = math.ceil(delta_seconds)
        return delay

    def calculate_delay_from_period(self, request_log: list[RequestLogEntry]) -> float:
        """
        Based on the current run rate and the platform rate limit parameters, calculate a reasonable delay.
        Usefull when the API does not provide a Retry-After header but the rate limit period is known.
        If just a few requests where made in the rate limit period and we did not cause the rate limiting,
        we can calculate a delay based on the number of successful requests.

        Parameters
        ----------
        request_log
            A list of request log entries leading up to the rate limit response.
            Used to calculate the run rate and oldest request timestamp.

        Returns
        -------
        float
            The calculated delay in seconds.

        """

        run_rate, oldest_request = self.run_rate(request_log=request_log)
        oldest_request = oldest_request or arrow.utcnow()
        # If the oldest request is None, we assume that the rate limit period is not known
        # and we use the current time as the oldest request since we use it for calculating the delay

        logger.trace(
            f"Oldest request considdered in rate limiting period: {oldest_request}"
        )

        since_oldest_request = math.ceil(
            (arrow.utcnow() - oldest_request).total_seconds()
        )

        logger.debug(
            f"Platform rate limit exceeded. Current run rate: {run_rate} requests in {since_oldest_request} seconds. Platform limit: {self.rate_limit_max_requests} requests in {self.rate_limit_period} seconds"
        )

        ramp_up_factor = run_rate / self.rate_limit_max_requests

        logger.trace(
            f"Amount of expected successful requests: {round(ramp_up_factor * 100, 1)}% probability that we caused the rate limiting"
        )

        if run_rate:
            # For how long have been using the API?
            activity_period = (arrow.utcnow() - oldest_request).total_seconds()

            # How long until the rate limit period is over?
            delta_seconds = self.rate_limit_period - activity_period

            # Some platforms have variable rate limits depending on various factors.
            # If we causes the rate limiting, wait for the full remaining period
            # If rate limiting is not caused by us, calculate a delay based on the number of successful requests

            delay = delta_seconds * ramp_up_factor

        else:
            logger.trace(
                "0 requests in rate limit period, so we have no clue about when to try again. Using exponential backoff"
            )
            backoff_delay = self.calculate_delay_from_backoff()

            if (
                self.backoff_multiplier > 1
                and self._backoff_delay > self.backoff_initial
            ):
                retry_count = math.log(
                    backoff_delay / self.backoff_initial,
                    self.backoff_multiplier,
                )

                total_wait = (
                    self.backoff_initial
                    * (1 - self.backoff_multiplier**retry_count)
                    / (1 - self.backoff_multiplier)
                )
                logger.trace(f"Total waited time so far: {total_wait} seconds")
            else:
                total_wait = backoff_delay

            if self.rate_limit_period:
                # If API has a well-known rate limit period, we can subtract the time from that
                delay = self.rate_limit_period - total_wait
            else:
                delay = total_wait
            logger.trace(
                f"Exponential backoff delay: {delay} seconds limitied to {self.rate_limit_period} seconds"
            )

        return delay

    def calculate_delay_from_backoff(self) -> float:
        """
        Calculate a delay based on exponential backoff.
        This method uses the backoff_initial and backoff_multiplier
        attributes to determine the delay.

        Returns
        -------
        float
            The calculated delay in seconds.
        """

        if self._backoff_delay == 0.0:
            self._backoff_delay = self.backoff_initial
        else:
            self._backoff_delay *= self.backoff_multiplier

        # If the API has a well-known rate limit period, we neder need to wait longer than that
        if self.rate_limit_period:
            delay = min(self.rate_limit_period, self._backoff_delay)
        else:
            delay = self._backoff_delay

        logger.trace(f"Calculated backoff delay: {delay} seconds")

        return delay

    def run_rate(
        self, *, request_log: list[RequestLogEntry]
    ) -> tuple[int, arrow.Arrow | None]:
        """
        Calculate the current run rate and oldest request timestamp.
        This is a placeholder implementation and should be replaced with actual logic.

        Parameters
        ----------
        request_log
            A list of request log entries leading up to the rate limit response.
            Used to calculate the run rate and oldest request timestamp.

        Returns
        -------
        tuple[int, arrow.Arrow | None]
            A tuple containing the number of requests in the rate limit period
            and the timestamp of the oldest request in the rate limit period.
        """
        if self.rate_limit_period is None:
            return 0, None

        # We only care about requests in the last rate limit period
        oldest_relevant_timestamp = arrow.utcnow().shift(
            seconds=-self.rate_limit_period
        )

        # Filter out 429 requests and requests older than the rate limit period
        # e.g. if the rate limit is 120 requests in 60 seconds, we only care about the last 60 seconds
        logs_in_rate_limit_period = []
        for log in request_log:
            if log.status_code != 429 and log.timestamp > oldest_relevant_timestamp:
                logs_in_rate_limit_period.append(log)

        # Filter out requests outside of the maximum request number
        # e.g. if the rate limit is 120 requests in 60 seconds, we only care about the last 120 requests
        logs_resulting_in_rate_limiting: list[RequestLogEntry] = (
            logs_in_rate_limit_period[-self.rate_limit_max_requests :]
        )

        # Calculate the number of requests in the rate limit period
        run_rate = len(logs_resulting_in_rate_limiting)

        # Find the oldest request in the rate limit period
        oldest_request = (
            logs_resulting_in_rate_limiting[0].timestamp
            if len(logs_resulting_in_rate_limiting) > 0
            else arrow.utcnow()
        )

        return run_rate, oldest_request

    def reset_backoff(self) -> None:
        """
        Reset the current backoff delay to 0.
        Usefull when the API is not longer rate limiting.
        """
        self._backoff_delay = 0.0
