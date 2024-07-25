import datetime
from pycdlib.dates import VolumeDescriptorDate, DirectoryRecordDate
from pycdlib.udf import UDFTimestamp


def datetime_from_iso_date(iso_date):
    year = None
    tz = None
    if isinstance(iso_date, VolumeDescriptorDate):
        year = iso_date.year
        day = iso_date.dayofmonth
    elif isinstance(iso_date, DirectoryRecordDate):
        year = 1900 + iso_date.years_since_1900
        day = iso_date.day_of_month
    elif isinstance(iso_date, UDFTimestamp):
        year = iso_date.year
        day = iso_date.day
        if tz:
            tz = datetime.timezone(datetime.timedelta(minutes=iso_date.tz))
        else:
            tz = datetime.timezone.utc
    else:
        return None

    if not tz:
        try:
            tz = datetime.timezone(datetime.timedelta(minutes=15 * iso_date.gmtoffset))
        except ValueError:
            tz = datetime.timezone.utc

    if not year:
        return None

    if year < 1970:
        year += 100

    month = iso_date.month
    if iso_date.month == 0:
        month = 1

    try:
        dt = datetime.datetime(
            year,
            month,
            day,
            iso_date.hour,
            iso_date.minute,
            iso_date.second,
            tzinfo=tz
        )
    except ValueError:
        dt = datetime.datetime.min
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def datetime_from_hfs_date(seconds):
    return datetime.datetime(1904,1,1, tzinfo=datetime.timezone.utc) + datetime.timedelta(seconds=seconds)
