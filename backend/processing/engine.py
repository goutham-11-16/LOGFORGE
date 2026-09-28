"""Core Log Processing Engine for LOGFORGE ULPF.
Executes the full pipeline: Ingestion -> Detection -> Parsing -> Normalization -> Validation -> Storage.
Enhanced with per-line exception isolation, detailed error context,
severity breakdown tracking, and threat detection statistics.
"""
import time
import logging
from typing import List, Tuple, Dict, Any, Optional
from backend.parsers.registry import registry
from backend.normalization.normalizer import normalizer
from backend.validation.validator import validator
from backend.storage.db import store
from backend.schema.models import UniversalEvent, FailedEvent, BatchProcessSummary

logger = logging.getLogger("logforge.engine")


class ProcessingEngine:
    """High-throughput, streaming-capable log pre-processing engine."""

    def process_line(
        self,
        raw_line: str,
        forced_parser: Optional[str] = None
    ) -> Tuple[Optional[UniversalEvent], Optional[FailedEvent]]:
        """Process a single log line through the complete pipeline."""
        line = raw_line.strip()
        if not line:
            return None, None

        t0 = time.perf_counter()

        # Step 1: Parser & Format Selection
        parser = None
        confidence = 1.0
        if forced_parser:
            parser = registry.get_parser(forced_parser)
            if not parser:
                return None, FailedEvent(
                    raw_event=line,
                    reason=f"Specified parser '{forced_parser}' not found in registry",
                    detected_format="unknown"
                )
        else:
            parser, confidence = registry.detect_format(line)

        if not parser or confidence < 0.2:
            return None, FailedEvent(
                raw_event=line,
                reason=f"No suitable parser detected (confidence={confidence:.2f}; line_prefix='{line[:60]}')",
                detected_format="unknown"
            )

        # Step 2: Extraction / Parsing
        try:
            extracted = parser.parse(line)
        except Exception as e:
            return None, FailedEvent(
                raw_event=line,
                reason=f"Parser '{parser.name}' extraction error: {type(e).__name__}: {str(e)[:200]}",
                detected_format=parser.format_name,
                parser_attempted=parser.name
            )

        # Guard: parser must return a dict
        if not isinstance(extracted, dict):
            return None, FailedEvent(
                raw_event=line,
                reason=f"Parser '{parser.name}' returned non-dict type: {type(extracted).__name__}",
                detected_format=parser.format_name,
                parser_attempted=parser.name
            )

        # Skip header rows (CSV auto-detection)
        if extracted.get("_is_header"):
            return None, None

        # Step 3: Field Normalization
        duration_ms = (time.perf_counter() - t0) * 1000.0
        try:
            norm_event = normalizer.normalize(
                extracted=extracted,
                raw_line=line,
                parser_name=parser.name,
                source_format=parser.format_name,
                confidence=confidence,
                duration_ms=duration_ms
            )
        except Exception as e:
            return None, FailedEvent(
                raw_event=line,
                reason=f"Normalization error ({parser.name}): {type(e).__name__}: {str(e)[:200]}",
                detected_format=parser.format_name,
                parser_attempted=parser.name
            )

        # Step 4: Schema Validation
        is_valid, error_msg = validator.validate(norm_event)
        if not is_valid:
            return None, FailedEvent(
                raw_event=line,
                reason=f"Validation failed: {error_msg}",
                detected_format=parser.format_name,
                parser_attempted=parser.name
            )

        return norm_event, None

    def process_batch(
        self,
        lines: Any,
        forced_parser: Optional[str] = None,
        chunk_size: int = 5000
    ) -> BatchProcessSummary:
        """
        Process a collection or generator of log lines with bounded O(1) memory
        by flushing to SQLite in chunks.
        """
        start_time = time.perf_counter()
        normalized_chunk: List[UniversalEvent] = []
        failed_chunk: List[FailedEvent] = []

        total_normalized = 0
        total_failed = 0
        total_skipped = 0

        sources_breakdown: Dict[str, int] = {}
        formats_breakdown: Dict[str, int] = {}
        actions_breakdown: Dict[str, int] = {}
        severity_breakdown: Dict[str, int] = {}
        threat_count = 0

        for line in lines:
            if not line:
                total_skipped += 1
                continue
            clean = line.strip() if isinstance(line, str) else str(line).strip()
            if not clean:
                total_skipped += 1
                continue

            # Per-line exception isolation: never let one bad line crash the batch
            try:
                event, failed = self.process_line(clean, forced_parser=forced_parser)
            except Exception as e:
                logger.warning("Unhandled error processing line: %s — %s", clean[:80], str(e))
                failed = FailedEvent(
                    raw_event=clean,
                    reason=f"Unhandled pipeline error: {type(e).__name__}: {str(e)[:200]}",
                    detected_format="unknown"
                )
                event = None

            if event:
                normalized_chunk.append(event)
                total_normalized += 1
                dev = event.source.device_type or "unknown"
                fmt = event.metadata.source_format or "unknown"
                act = event.event.action or "unknown"
                sev = event.event.severity or "informational"
                sources_breakdown[dev] = sources_breakdown.get(dev, 0) + 1
                formats_breakdown[fmt] = formats_breakdown.get(fmt, 0) + 1
                actions_breakdown[act] = actions_breakdown.get(act, 0) + 1
                severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1
                if event.threat_intel.threat_detected:
                    threat_count += 1
            elif failed:
                failed_chunk.append(failed)
                total_failed += 1

            # Flush chunks to storage periodically to preserve O(1) memory footprint
            if len(normalized_chunk) >= chunk_size:
                store.insert_batch(normalized_chunk)
                normalized_chunk.clear()

            if len(failed_chunk) >= chunk_size:
                store.insert_failed_batch(failed_chunk)
                failed_chunk.clear()

        # Flush remaining buffers
        if normalized_chunk:
            store.insert_batch(normalized_chunk)
            normalized_chunk.clear()
        if failed_chunk:
            store.insert_failed_batch(failed_chunk)
            failed_chunk.clear()

        total_elapsed = time.perf_counter() - start_time
        total_count = total_normalized + total_failed
        eps = round(total_count / total_elapsed, 2) if total_elapsed > 0 else 0.0

        summary = BatchProcessSummary(
            total_events=total_count,
            normalized_count=total_normalized,
            failed_count=total_failed,
            processing_time_seconds=round(total_elapsed, 4),
            events_per_second=eps,
            sources_breakdown=sources_breakdown,
            formats_breakdown=formats_breakdown,
            actions_breakdown=actions_breakdown
        )

        store.record_batch_job(summary)
        return summary


engine = ProcessingEngine()
