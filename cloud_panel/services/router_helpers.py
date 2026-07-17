"""Small RouterOS helper functions used by router services."""


def routeros_bool(value) -> str:
    """Convert a Python truth value to RouterOS yes/no syntax."""
    return "yes" if bool(value) else "no"


def api_find_by_comment(api, menu: str, comment: str):
    """Find the first RouterOS item matching a comment."""
    rows = api.talk(
        str(menu) + "/print"
    )

    for row in rows:
        if row.get("comment", "") == comment:
            return row

    return None


def api_find_by_name(api, menu: str, name: str):
    """Find the first RouterOS item matching a name."""
    rows = api.talk(
        str(menu) + "/print"
    )

    for row in rows:
        if row.get("name", "") == name:
            return row

    return None


def ros_quote(value) -> str:
    """Escape a value before inserting it into RouterOS script text."""
    return (
        str(value or "")
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("$", "\\$")
    )
