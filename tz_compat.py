from __future__ import annotations

from datetime import timedelta, timezone as dt_timezone

try:
    import pytz as _pytz  # type: ignore[import-not-found]
except ModuleNotFoundError:
    _pytz = None

try:
    from zoneinfo import ZoneInfo
except ModuleNotFoundError:  # pragma: no cover
    ZoneInfo = None  # type: ignore[assignment]


class _PytzCompat:
    @staticmethod
    def FixedOffset(minutes: int):
        return dt_timezone(timedelta(minutes=int(minutes)))

    @staticmethod
    def timezone(name: str):
        zone_name = (name or "").strip()
        if not zone_name:
            return dt_timezone.utc

        if ZoneInfo is not None:
            try:
                return ZoneInfo(zone_name)
            except Exception:  # pragma: no cover
                pass

        return dt_timezone.utc


pytz = _pytz if _pytz is not None else _PytzCompat()

