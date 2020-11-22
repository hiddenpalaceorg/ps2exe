from dates import datetime_from_iso_date

def get_pvd_info(iso):
    pvd = iso.pvd

    info = {}

    for field in ("system_identifier", "volume_identifier", "volume_set_identifier"):
        info[field] = getattr(pvd, field).strip().decode(errors='replace').encode("cp1252", errors="replace").decode()

    for field in (
        "volume_creation_date",
        "volume_modification_date",
        "volume_expiration_date",
        "volume_effective_date",
    ):
        info[field] = datetime_from_iso_date(getattr(pvd, field))

    return info