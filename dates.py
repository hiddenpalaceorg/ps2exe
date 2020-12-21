import datetime
from pycdlib.dates import VolumeDescriptorDate, DirectoryRecordDate


def datetime_from_iso_date(iso_date):
    year = None
    if isinstance(iso_date, VolumeDescriptorDate):
        year = iso_date.year
        day = iso_date.dayofmonth
    elif isinstance(iso_date, DirectoryRecordDate):
        year = 1900 + iso_date.years_since_1900
        day = iso_date.day_of_month
    else:
        return None

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
            tzinfo=datetime.timezone(datetime.timedelta(minutes=15 * iso_date.gmtoffset))
        )
    except ValueError:
        dt = datetime.datetime.min
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt
