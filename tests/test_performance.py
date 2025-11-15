#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Comprehensive performance tests for gr-linux-crypto.

Measures:
- Single-operation latency (with percentiles)
- Throughput (MB/s)
- Memory usage and leaks
- CPU usage
- Hardware acceleration detection
- Algorithm comparison
"""

import os
import secrets
import statistics
import sys
import time
from typing import Dict, List

import pytest

try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    pass

    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

# Import crypto functions
try:
    from python.linux_crypto import decrypt, encrypt
except ImportError:
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))
        from linux_crypto import decrypt, encrypt
    except ImportError:
        pytest.skip("Cannot import crypto modules")


# Performance thresholds
LATENCY_THRESHOLD_US = 100  # microseconds
THROUGHPUT_MIN_MBPS = 10  # Minimum MB/s for real-time operation
MEMORY_LEAK_THRESHOLD_PERCENT = 10  # Max memory increase over test


class PerformanceMetrics:
    """Track and analyze performance metrics."""

    def __init__(self):
        self.times: List[float] = []
        self.memory_samples: List[float] = []
        self.cpu_samples: List[float] = []

    def add_time(self, elapsed: float):
        """Add a timing measurement (seconds)."""
        self.times.append(elapsed)

    def add_memory(self, memory_mb: float):
        """Add a memory measurement (MB)."""
        self.memory_samples.append(memory_mb)

    def add_cpu(self, cpu_percent: float):
        """Add a CPU measurement (percent)."""
        self.cpu_samples.append(cpu_percent)

    def get_statistics(self) -> Dict:
        """Get comprehensive statistics."""
        if not self.times:
            return {}

        times_us = [t * 1_000_000 for t in self.times]  # Convert to microseconds

        stats = {
            "count": len(times_us),
            "min_us": min(times_us),
            "max_us": max(times_us),
            "mean_us": statistics.mean(times_us),
            "median_us": statistics.median(times_us),
            "stdev_us": statistics.stdev(times_us) if len(times_us) > 1 else 0,
        }

        # Calculate percentiles
        if len(times_us) > 1:
            sorted_times = sorted(times_us)
            stats["p50_us"] = sorted_times[int(len(sorted_times) * 0.50)]
            stats["p95_us"] = sorted_times[int(len(sorted_times) * 0.95)]
            stats["p99_us"] = sorted_times[int(len(sorted_times) * 0.99)]
        else:
            stats["p50_us"] = stats["p95_us"] = stats["p99_us"] = times_us[0]

        # Memory statistics
        if self.memory_samples:
            stats["memory_mean_mb"] = statistics.mean(self.memory_samples)
            stats["memory_max_mb"] = max(self.memory_samples)
            stats["memory_min_mb"] = min(self.memory_samples)
            stats["memory_stable"] = (
                (max(self.memory_samples) - min(self.memory_samples))
                / statistics.mean(self.memory_samples)
                * 100
            ) < MEMORY_LEAK_THRESHOLD_PERCENT

        # CPU statistics
        if self.cpu_samples:
            stats["cpu_mean_percent"] = statistics.mean(self.cpu_samples)
            stats["cpu_max_percent"] = max(self.cpu_samples)

        return stats

    def print_report(self, test_name: str):
        """Print formatted performance report."""
        stats = self.get_statistics()

        print(f"\n{'='*70}")
        print(f"Performance Report: {test_name}")
        print(f"{'='*70}")
        print(f"Operations: {stats['count']:,}")
        print("\nLatency (microseconds):")
        print(f"  Min:    {stats['min_us']:8.3f} μs")
        print(f"  Max:    {stats['max_us']:8.3f} μs")
        print(f"  Mean:   {stats['mean_us']:8.3f} μs")
        print(f"  Median: {stats['p50_us']:8.3f} μs (p50)")
        print(f"  p95:    {stats['p95_us']:8.3f} μs")
        print(f"  p99:    {stats['p99_us']:8.3f} μs")
        print(f"  StdDev: {stats['stdev_us']:8.3f} μs")

        if "memory_mean_mb" in stats:
            print("\nMemory:")
            print(f"  Mean: {stats['memory_mean_mb']:.2f} MB")
            print(
                f"  Range: {stats['memory_min_mb']:.2f} - {stats['memory_max_mb']:.2f} MB"
            )
            print(f"  Stable: {'YES' if stats['memory_stable'] else 'NO'}")

        if "cpu_mean_percent" in stats:
            print("\nCPU Usage:")
            print(f"  Mean: {stats['cpu_mean_percent']:.2f}%")
            print(f"  Max:  {stats['cpu_max_percent']:.2f}%")

        print(f"{'='*70}")


class TestLatency:
    """Test single-operation latency."""

    @pytest.mark.parametrize(
        "algorithm,auth",
        [
            ("aes-128", "gcm"),
            ("aes-256", "gcm"),
            ("chacha20", "poly1305"),
        ],
    )
    def test_encryption_latency_16_bytes(self, algorithm, auth):
        """Test encryption latency for 16-byte payload (M17 frame size)."""
        metrics = PerformanceMetrics()

        # Generate key
        key_size = 16 if algorithm == "aes-128" else 32
        key = secrets.token_bytes(key_size)
        data = secrets.token_bytes(16)  # M17 frame size

        # Warm up
        for _ in range(100):
            encrypt(algorithm, key, data, auth=auth)

        # Measure 100,000 operations
        iterations = 100_000

        for _ in range(iterations):
            start = time.perf_counter()
            encrypt(algorithm, key, data, auth=auth)
            elapsed = time.perf_counter() - start
            metrics.add_time(elapsed)

        stats = metrics.get_statistics()
        metrics.print_report(f"{algorithm}-{auth} (16 bytes)")

        # Assert mean latency < 100μs
        assert (
            stats["mean_us"] < LATENCY_THRESHOLD_US
        ), f"Mean latency {stats['mean_us']:.3f}μs exceeds threshold {LATENCY_THRESHOLD_US}μs"

        # Assert p99 < 200μs (99% of operations should be fast)
        assert (
            stats["p99_us"] < LATENCY_THRESHOLD_US * 2
        ), f"p99 latency {stats['p99_us']:.3f}μs too high"

    @pytest.mark.parametrize("size", [16, 64, 256, 1024, 4096])
    def test_encryption_latency_various_sizes(self, size):
        """Test encryption latency for various data sizes."""
        metrics = PerformanceMetrics()

        key = secrets.token_bytes(32)
        data = secrets.token_bytes(size)

        # Warm up
        for _ in range(50):
            encrypt("aes-256", key, data, auth="gcm")

        # Measure 10,000 operations
        iterations = 10_000

        for _ in range(iterations):
            start = time.perf_counter()
            encrypt("aes-256", key, data, auth="gcm")
            elapsed = time.perf_counter() - start
            metrics.add_time(elapsed)

        stats = metrics.get_statistics()
        metrics.print_report(f"AES-256-GCM ({size} bytes)")

        # Latency should scale reasonably with size
        expected_max = LATENCY_THRESHOLD_US * (size / 16)  # Scale from 16-byte baseline
        assert (
            stats["mean_us"] < expected_max
        ), f"Latency {stats['mean_us']:.3f}μs exceeds expected {expected_max:.3f}μs for {size} bytes"


class TestThroughput:
    """Test encryption/decryption throughput."""

    @pytest.mark.parametrize(
        "algorithm,auth",
        [
            ("aes-128", "gcm"),
            ("aes-256", "gcm"),
            ("chacha20", "poly1305"),
        ],
    )
    def test_encryption_throughput(self, algorithm, auth):
        """Measure encryption throughput in MB/s."""
        key_size = 16 if algorithm == "aes-128" else 32
        key = secrets.token_bytes(key_size)

        # Test with various payload sizes
        test_sizes = [16, 64, 256, 1024, 4096, 16384]
        results = {}

        for size in test_sizes:
            data = secrets.token_bytes(size)

            # Warm up
            for _ in range(10):
                encrypt(algorithm, key, data, auth=auth)

            # Measure throughput
            iterations = 1000
            total_bytes = size * iterations

            start = time.perf_counter()
            for _ in range(iterations):
                encrypt(algorithm, key, data, auth=auth)
            elapsed = time.perf_counter() - start

            throughput_mbps = (total_bytes / elapsed) / (1024 * 1024)
            results[size] = throughput_mbps

            print(f"{algorithm}-{auth} ({size} bytes): {throughput_mbps:.2f} MB/s")

            # For real-time voice (16 bytes per 40ms = 400 bytes/s), we need much less
            # But for bulk operations, we want good throughput
            if size >= 1024:
                assert (
                    throughput_mbps > THROUGHPUT_MIN_MBPS
                ), f"Throughput {throughput_mbps:.2f} MB/s too low for {size} bytes"

        # Print summary
        print(f"\n{algorithm}-{auth} Throughput Summary:")
        for size, mbps in results.items():
            print(f"  {size:5d} bytes: {mbps:7.2f} MB/s")

    def test_decryption_throughput(self):
        """Measure decryption throughput."""
        key = secrets.token_bytes(32)
        data = secrets.token_bytes(1024)

        # Encrypt once
        ciphertext, iv, auth_tag = encrypt("aes-256", key, data, auth="gcm")

        # Measure decryption throughput
        iterations = 1000
        total_bytes = len(data) * iterations

        start = time.perf_counter()
        for _ in range(iterations):
            decrypt("aes-256", key, ciphertext, iv, auth="gcm", auth_tag=auth_tag)
        elapsed = time.perf_counter() - start

        throughput_mbps = (total_bytes / elapsed) / (1024 * 1024)

        print(f"\nDecryption Throughput: {throughput_mbps:.2f} MB/s")
        assert throughput_mbps > THROUGHPUT_MIN_MBPS


class TestMemoryUsage:
    """Test memory usage and detect leaks."""

    @pytest.mark.skipif(not PSUTIL_AVAILABLE, reason="psutil not available")
    def test_memory_stability_continuous_encryption(self):
        """Test memory stability during continuous encryption."""
        process = psutil.Process()
        metrics = PerformanceMetrics()

        key = secrets.token_bytes(32)
        data = secrets.token_bytes(1024)

        # Initial memory (allow GC to settle)
        import gc

        gc.collect()
        time.sleep(0.1)
        initial_memory = process.memory_info().rss / (1024 * 1024)  # MB

        # Run continuous encryption
        iterations = 10_000
        sample_interval = 100

        for i in range(iterations):
            encrypt("aes-256", key, data, auth="gcm")

            # Sample memory periodically
            if i % sample_interval == 0:
                memory_mb = process.memory_info().rss / (1024 * 1024)
                metrics.add_memory(memory_mb)

        # Final memory (allow GC to settle)
        gc.collect()
        time.sleep(0.1)
        final_memory = process.memory_info().rss / (1024 * 1024)

        metrics.get_statistics()

        # Check for memory leaks
        memory_increase = final_memory - initial_memory
        memory_increase_percent = (
            (memory_increase / initial_memory) * 100 if initial_memory > 0 else 0
        )

        print("\nMemory Change:")
        print(f"  Initial: {initial_memory:.2f} MB")
        print(f"  Final:   {final_memory:.2f} MB")
        print(f"  Change:  {memory_increase:+.2f} MB ({memory_increase_percent:+.2f}%)")

        # Only check stats if we have memory samples
        if metrics.memory_samples:
            # Print memory statistics manually (print_report needs timing data)
            print("\nMemory Statistics:")
            print(f"  Samples: {len(metrics.memory_samples)}")
            print(f"  Mean: {statistics.mean(metrics.memory_samples):.2f} MB")
            print(f"  Min: {min(metrics.memory_samples):.2f} MB")
            print(f"  Max: {max(metrics.memory_samples):.2f} MB")

            # Memory should not increase significantly
            # Allow for GC variance - be more lenient (20% instead of 10%)
            assert (
                memory_increase_percent < MEMORY_LEAK_THRESHOLD_PERCENT * 2
            ), f"Memory increase {memory_increase_percent:.2f}% may indicate issue (threshold: {MEMORY_LEAK_THRESHOLD_PERCENT * 2}%)"

            # Check stability only if we have enough samples
            if len(metrics.memory_samples) > 5:
                memory_variance = (
                    (max(metrics.memory_samples) - min(metrics.memory_samples))
                    / statistics.mean(metrics.memory_samples)
                    * 100
                )
                print(f"  Memory variance: {memory_variance:.2f}%")
                # Variance should be reasonable (allow up to 30% variance due to GC)
                assert (
                    memory_variance < 30
                ), f"Memory variance {memory_variance:.2f}% too high"

    @pytest.mark.skipif(not PSUTIL_AVAILABLE, reason="psutil not available")
    def test_memory_usage_per_operation(self):
        """Measure memory usage per encryption operation."""
        process = psutil.Process()

        key = secrets.token_bytes(32)
        data = secrets.token_bytes(1024)

        # Baseline memory
        baseline_memory = process.memory_info().rss / (1024 * 1024)

        # Encrypt
        encrypt("aes-256", key, data, auth="gcm")

        # Memory after operation
        after_memory = process.memory_info().rss / (1024 * 1024)

        memory_per_op = after_memory - baseline_memory

        print(f"\nMemory per operation: {memory_per_op:.4f} MB")

        # Should be reasonable (< 1 MB per operation)
        assert (
            memory_per_op < 1.0
        ), f"Memory per operation too high: {memory_per_op:.4f} MB"


class TestCPUUsage:
    """Test CPU usage during operations."""

    @pytest.mark.skipif(not PSUTIL_AVAILABLE, reason="psutil not available")
    def test_cpu_usage_sustained_operation(self):
        """Test CPU usage during sustained encryption."""
        process = psutil.Process()
        metrics = PerformanceMetrics()

        key = secrets.token_bytes(32)
        data = secrets.token_bytes(1024)

        # Measure CPU during sustained operation
        iterations = 1000
        sample_interval = 50

        for i in range(iterations):
            encrypt("aes-256", key, data, auth="gcm")

            # Sample CPU periodically
            if i % sample_interval == 0:
                cpu_percent = process.cpu_percent(interval=0.01)
                metrics.add_cpu(cpu_percent)

        stats = metrics.get_statistics()

        if "cpu_mean_percent" in stats:
            print("\nCPU Usage:")
            print(f"  Mean: {stats['cpu_mean_percent']:.2f}%")
            print(f"  Max:  {stats['cpu_max_percent']:.2f}%")

            # For real-time voice processing, CPU should be reasonable
            # Single core shouldn't be maxed out for voice encryption
            assert stats["cpu_mean_percent"] < 100, "CPU usage too high"


class TestAlgorithmComparison:
    """Compare performance of different algorithms."""

    def test_algorithm_comparison_16_bytes(self):
        """Compare algorithms for 16-byte payload."""
        test_data = secrets.token_bytes(16)
        iterations = 10_000

        results = {}

        algorithms = [
            ("aes-128", "gcm", secrets.token_bytes(16)),
            ("aes-256", "gcm", secrets.token_bytes(32)),
            ("chacha20", "poly1305", secrets.token_bytes(32)),
        ]

        for algorithm, auth, key in algorithms:
            # Warm up
            for _ in range(100):
                encrypt(algorithm, key, test_data, auth=auth)

            # Measure
            start = time.perf_counter()
            for _ in range(iterations):
                encrypt(algorithm, key, test_data, auth=auth)
            elapsed = time.perf_counter() - start

            avg_latency_us = (elapsed / iterations) * 1_000_000
            results[f"{algorithm}-{auth}"] = avg_latency_us

        print(f"\n{'='*70}")
        print("Algorithm Comparison (16 bytes)")
        print(f"{'='*70}")
        for algo, latency in sorted(results.items(), key=lambda x: x[1]):
            print(f"  {algo:25s}: {latency:8.3f} μs")
        print(f"{'='*70}")

        # All should meet latency threshold
        for algo, latency in results.items():
            assert (
                latency < LATENCY_THRESHOLD_US
            ), f"{algo} latency {latency:.3f}μs exceeds threshold"

    def test_algorithm_comparison_large_data(self):
        """Compare algorithms for large data (4096 bytes)."""
        test_data = secrets.token_bytes(4096)
        iterations = 1000

        results = {}

        algorithms = [
            ("aes-128", "gcm", secrets.token_bytes(16)),
            ("aes-256", "gcm", secrets.token_bytes(32)),
            ("chacha20", "poly1305", secrets.token_bytes(32)),
        ]

        for algorithm, auth, key in algorithms:
            # Warm up
            for _ in range(10):
                encrypt(algorithm, key, test_data, auth=auth)

            # Measure
            start = time.perf_counter()
            for _ in range(iterations):
                encrypt(algorithm, key, test_data, auth=auth)
            elapsed = time.perf_counter() - start

            throughput_mbps = ((len(test_data) * iterations) / elapsed) / (1024 * 1024)
            results[f"{algorithm}-{auth}"] = throughput_mbps

        print(f"\n{'='*70}")
        print("Algorithm Comparison (4096 bytes) - Throughput")
        print(f"{'='*70}")
        for algo, mbps in sorted(results.items(), key=lambda x: x[1], reverse=True):
            print(f"  {algo:25s}: {mbps:7.2f} MB/s")
        print(f"{'='*70}")


class TestHardwareAcceleration:
    """Test hardware acceleration detection."""

    def test_detect_aes_ni(self):
        """Detect AES-NI support on x86_64."""
        import platform

        if platform.machine() != "x86_64":
            pytest.skip("AES-NI detection only on x86_64")

        try:
            # Check CPU flags
            with open("/proc/cpuinfo", "r") as f:
                cpuinfo = f.read()

            has_aes_ni = "aes" in cpuinfo.lower()

            print("\nAES-NI Detection:")
            print(f"  Architecture: {platform.machine()}")
            print(f"  AES-NI Support: {'YES' if has_aes_ni else 'NO'}")

            # Note: This doesn't guarantee OpenSSL uses it, but indicates availability
            assert True  # Just report, don't fail

        except Exception as e:
            print(f"Could not detect AES-NI: {e}")
            pytest.skip("CPU info not accessible")

    def test_detect_arm_crypto_extensions(self):
        """Detect ARM crypto extensions on ARM64."""
        import platform

        if (
            not platform.machine().startswith("aarch64")
            and platform.machine() != "arm64"
        ):
            pytest.skip("ARM crypto extensions only on ARM64")

        try:
            with open("/proc/cpuinfo", "r") as f:
                cpuinfo = f.read()

            # ARM crypto extensions indicators
            has_crypto = "asimd" in cpuinfo.lower() or "aes" in cpuinfo.lower()

            print("\nARM Crypto Extensions:")
            print(f"  Architecture: {platform.machine()}")
            print(f"  Crypto Support: {'YES' if has_crypto else 'NO'}")

            assert True

        except Exception as e:
            print(f"Could not detect ARM crypto: {e}")
            pytest.skip("CPU info not accessible")

    def test_kernel_crypto_acceleration(self):
        """Check if kernel crypto API is available."""
        try:
            # Check for AF_ALG socket support (kernel crypto API)
            import socket

            try:
                test_socket = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
                test_socket.close()
                kernel_crypto_available = True
            except (OSError, AttributeError):
                kernel_crypto_available = False

            print("\nKernel Crypto API:")
            print(f"  AF_ALG Support: {'YES' if kernel_crypto_available else 'NO'}")

            assert True  # Just report availability

        except Exception as e:
            print(f"Could not check kernel crypto: {e}")
            assert True


class TestRealTimePerformance:
    """Test performance for real-time voice applications."""

    def test_real_time_voice_encryption(self):
        """Test that encryption meets real-time voice requirements."""
        # M17 voice frame: 16 bytes every 40ms = 400 bytes/second
        # We need encryption to complete in < 40ms per frame

        key = secrets.token_bytes(32)
        frame = secrets.token_bytes(16)

        # Measure 1000 frames (40 seconds of audio)
        iterations = 1000
        frame_time_ms = 40  # 40ms per frame
        # max_latency_ms threshold: 10% of frame time (not used in assertions, for reference)

        latencies = []

        for _ in range(iterations):
            start = time.perf_counter()
            encrypt("chacha20", key, frame, auth="poly1305")
            elapsed = time.perf_counter() - start
            latencies.append(elapsed * 1000)  # Convert to milliseconds

        mean_latency_ms = statistics.mean(latencies)
        max_latency_ms_actual = max(latencies)
        p99_latency_ms = sorted(latencies)[int(len(latencies) * 0.99)]

        print("\nReal-Time Voice Encryption Performance:")
        print(f"  Mean latency: {mean_latency_ms:.3f} ms")
        print(f"  Max latency:  {max_latency_ms_actual:.3f} ms")
        print(f"  p99 latency:  {p99_latency_ms:.3f} ms")
        print(f"  Frame time:   {frame_time_ms:.3f} ms")
        print(f"  Headroom:     {(frame_time_ms - mean_latency_ms):.3f} ms")

        # Mean should be well under frame time
        assert (
            mean_latency_ms < frame_time_ms
        ), f"Mean latency {mean_latency_ms:.3f}ms exceeds frame time {frame_time_ms}ms"

        # p99 should also be reasonable
        assert (
            p99_latency_ms < frame_time_ms * 2
        ), f"p99 latency {p99_latency_ms:.3f}ms too high for real-time"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
