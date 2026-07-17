"""System update page and status API routes."""

from typing import Callable

from flask import flash, jsonify, redirect, render_template, request, url_for

from cloud_panel.config import CLOUD_GUARD_VERSION
from cloud_panel.services.settings import get_settings


def register_update_routes(
    app,
    login_required: Callable,
    start_update_job: Callable,
    read_update_status: Callable,
    audit_event: Callable,
) -> None:
    """Register update routes with stable legacy endpoints."""

    @login_required
    def system_updates_page():
        if request.method == "POST":
            upload = request.files.get("update_file")
            if not upload or not upload.filename.lower().endswith(".zip"):
                flash("اختر ملف تحديث ZIP", "danger")
                return redirect(url_for("system_updates_page"))
            try:
                job_id = start_update_job(upload)
                audit_event("system_update_queued", upload.filename, job_id)
                return render_template(
                    "system_updates.html",
                    update_status=read_update_status(job_id),
                    active_job_id=job_id,
                    update_started=True,
                    current_version=CLOUD_GUARD_VERSION,
                    settings=get_settings(),
                )
            except Exception as exc:
                audit_event("system_update_failed", upload.filename, str(exc))
                flash("تعذر بدء التحديث: %s" % exc, "danger")
                return redirect(url_for("system_updates_page"))

        return render_template(
            "system_updates.html",
            update_status=read_update_status(),
            active_job_id=None,
            update_started=False,
            current_version=CLOUD_GUARD_VERSION,
            settings=get_settings(),
        )

    @login_required
    def system_update_status_api():
        job_id = request.args.get("job", "").strip() or None
        payload = read_update_status(job_id) or {
            "status": "idle",
            "message": "لا يوجد تحديث قيد التنفيذ",
        }
        payload["current_version"] = CLOUD_GUARD_VERSION
        return jsonify(payload)

    app.add_url_rule(
        "/system/updates",
        endpoint="system_updates_page",
        view_func=system_updates_page,
        methods=["GET", "POST"],
    )
    app.add_url_rule(
        "/api/system/update-status",
        endpoint="system_update_status_api",
        view_func=system_update_status_api,
        methods=["GET"],
    )
