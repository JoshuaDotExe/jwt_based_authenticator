#!/usr/bin/env python3

import argparse
import json
import statistics
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor


def parse_args():
	parser = argparse.ArgumentParser(
		description="Load test the token endpoint and estimate peak successful RPM."
	)
	parser.add_argument("--url", default="http://localhost:8080/token", help="Token endpoint URL")
	parser.add_argument("--username", required=True, help="Username for the token request")
	parser.add_argument("--password", required=True, help="Password for the token request")
	parser.add_argument("--aud", default="api.local", help="Audience claim to request")
	parser.add_argument(
		"--duration",
		type=float,
		default=10.0,
		help="Test duration per concurrency level in seconds",
	)
	parser.add_argument(
		"--start-concurrency",
		type=int,
		default=1,
		help="Initial number of concurrent workers",
	)
	parser.add_argument(
		"--max-concurrency",
		type=int,
		default=64,
		help="Maximum number of concurrent workers to test",
	)
	parser.add_argument(
		"--concurrency-multiplier",
		type=float,
		default=2.0,
		help="Multiplier applied after each passing stage",
	)
	parser.add_argument(
		"--max-error-rate",
		type=float,
		default=0.01,
		help="Maximum allowed error rate for a stage to count as passing",
	)
	parser.add_argument(
		"--timeout",
		type=float,
		default=5.0,
		help="Per-request timeout in seconds",
	)
	parser.add_argument(
		"--expected-status",
		type=int,
		default=201,
		help="HTTP status treated as a successful token response",
	)
	return parser.parse_args()


def make_request(url, payload_bytes, timeout):
	request = urllib.request.Request(
		url,
		data=payload_bytes,
		headers={"Content-Type": "application/json"},
		method="POST",
	)
	start = time.perf_counter()
	status_code = None
	try:
		with urllib.request.urlopen(request, timeout=timeout) as response:
			response.read()
			status_code = response.status
			return status_code, time.perf_counter() - start, None
	except urllib.error.HTTPError as exc:
		status_code = exc.code
		return status_code, time.perf_counter() - start, str(exc)
	except Exception as exc:  # pylint: disable=broad-except
		return status_code, time.perf_counter() - start, str(exc)


def run_stage(args, concurrency):
	payload_bytes = json.dumps(
		{
			"username": args.username,
			"password": args.password,
			"aud": args.aud,
		}
	).encode("utf-8")
	deadline = time.perf_counter() + args.duration
	lock = threading.Lock()
	results = {
		"requests": 0,
		"successes": 0,
		"failures": 0,
		"latencies": [],
		"status_counts": {},
	}

	def worker():
		while time.perf_counter() < deadline:
			status_code, latency, error = make_request(args.url, payload_bytes, args.timeout)
			with lock:
				results["requests"] += 1
				results["latencies"].append(latency)
				results["status_counts"][status_code] = results["status_counts"].get(status_code, 0) + 1
				if error is None and status_code == args.expected_status:
					results["successes"] += 1
				else:
					results["failures"] += 1

	with ThreadPoolExecutor(max_workers=concurrency) as executor:
		for _ in range(concurrency):
			executor.submit(worker)

	requests = results["requests"]
	error_rate = (results["failures"] / requests) if requests else 1.0
	success_rpm = (results["successes"] / args.duration) * 60.0
	avg_latency_ms = statistics.fmean(results["latencies"]) * 1000 if results["latencies"] else 0.0
	max_latency_ms = max(results["latencies"]) * 1000 if results["latencies"] else 0.0

	return {
		"concurrency": concurrency,
		"requests": requests,
		"successes": results["successes"],
		"failures": results["failures"],
		"error_rate": error_rate,
		"success_rpm": success_rpm,
		"avg_latency_ms": avg_latency_ms,
		"max_latency_ms": max_latency_ms,
		"status_counts": results["status_counts"],
		"passed": requests > 0 and error_rate <= args.max_error_rate,
	}


def next_concurrency(current, multiplier, max_concurrency):
	next_value = int(current * multiplier)
	if next_value <= current:
		next_value = current + 1
	return min(next_value, max_concurrency)


def main():
	args = parse_args()
	concurrency = max(1, args.start_concurrency)
	max_concurrency = max(concurrency, args.max_concurrency)
	stages = []
	best_stage = None

	print("Load test configuration")
	print(f"  url: {args.url}")
	print(f"  duration: {args.duration:.1f}s per stage")
	print(f"  expected_status: {args.expected_status}")
	print(f"  max_error_rate: {args.max_error_rate:.2%}")
	print()

	while True:
		stage = run_stage(args, concurrency)
		stages.append(stage)
		print(
			"concurrency={concurrency:>3} requests={requests:>5} successes={successes:>5} "
			"failures={failures:>4} success_rpm={success_rpm:>8.1f} error_rate={error_rate:>7.2%} "
			"avg_ms={avg_latency_ms:>7.1f} max_ms={max_latency_ms:>7.1f}".format(**stage)
		)

		if stage["passed"]:
			if best_stage is None or stage["success_rpm"] > best_stage["success_rpm"]:
				best_stage = stage
			if concurrency >= max_concurrency:
				break
			next_value = next_concurrency(concurrency, args.concurrency_multiplier, max_concurrency)
			if next_value == concurrency:
				break
			concurrency = next_value
			continue

		break

	print()
	if best_stage is None:
		print("No passing stage observed. Check credentials, endpoint health, or relax --max-error-rate.")
		if stages:
			print(f"Last status counts: {stages[-1]['status_counts']}")
			raise SystemExit(1)

	print("Peak passing stage")
	print(f"  concurrency: {best_stage['concurrency']}")
	print(f"  peak_success_rpm: {best_stage['success_rpm']:.1f}")
	print(f"  requests: {best_stage['requests']}")
	print(f"  successes: {best_stage['successes']}")
	print(f"  failures: {best_stage['failures']}")
	print(f"  error_rate: {best_stage['error_rate']:.2%}")
	print(f"  avg_latency_ms: {best_stage['avg_latency_ms']:.1f}")
	print(f"  max_latency_ms: {best_stage['max_latency_ms']:.1f}")
	print(f"  status_counts: {best_stage['status_counts']}")


if __name__ == "__main__":
	main()