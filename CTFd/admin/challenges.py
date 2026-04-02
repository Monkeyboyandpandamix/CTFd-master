from flask import abort, render_template, request, url_for
from sqlalchemy import func

from CTFd.admin import admin
from CTFd.models import Challenges, Flags, Solves, db
from CTFd.plugins.challenges import CHALLENGE_CLASSES, get_chal_class
from CTFd.schemas.tags import TagSchema
from CTFd.utils.decorators import admins_only
from CTFd.utils.security.signing import serialize
from CTFd.utils.user import get_current_team, get_current_user


def _challenge_display_id_map():
    challenge_ids = [
        challenge_id
        for (challenge_id,) in Challenges.query.with_entities(Challenges.id)
        .order_by(Challenges.id.asc())
        .all()
    ]
    return {challenge_id: index for index, challenge_id in enumerate(challenge_ids, start=1)}


def _difficulty_clause(level):
    if level == "warmup":
        return Challenges.value <= 100
    if level == "easy":
        return (Challenges.value > 100) & (Challenges.value <= 250)
    if level == "medium":
        return (Challenges.value > 250) & (Challenges.value <= 500)
    if level == "hard":
        return (Challenges.value > 500) & (Challenges.value <= 1000)
    if level == "expert":
        return Challenges.value > 1000
    return None


@admin.route("/admin/challenges")
@admins_only
def challenges_listing():
    q = request.args.get("q")
    field = request.args.get("field")
    category = request.args.get("category")
    difficulty = request.args.get("difficulty")
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    if per_page not in (20, 50):
        per_page = 20
    filters = []

    if q:
        # The field exists as an exposed column
        if Challenges.__mapper__.has_property(field):
            filters.append(getattr(Challenges, field).like("%{}%".format(q)))

    if category:
        filters.append(Challenges.category == category)

    difficulty_clause = _difficulty_clause(difficulty)
    if difficulty_clause is not None:
        filters.append(difficulty_clause)

    query = Challenges.query.filter(*filters).order_by(Challenges.id.asc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    challenges = pagination.items
    total = pagination.total
    categories = [
        category_name
        for (category_name,) in db.session.query(Challenges.category)
        .filter(Challenges.category.isnot(None))
        .group_by(Challenges.category)
        .order_by(func.lower(Challenges.category))
        .all()
        if category_name
    ]
    display_ids = _challenge_display_id_map()

    return render_template(
        "admin/challenges/challenges.html",
        challenges=challenges,
        display_ids=display_ids,
        total=total,
        q=q,
        field=field,
        categories=categories,
        selected_category=category,
        selected_difficulty=difficulty,
        page=page,
        per_page=per_page,
        pagination=pagination,
    )


@admin.route("/admin/challenges/<int:challenge_id>")
@admins_only
def challenges_detail(challenge_id):
    challenges = dict(
        Challenges.query.with_entities(Challenges.id, Challenges.name).all()
    )
    challenge = Challenges.query.filter_by(id=challenge_id).first_or_404()
    display_id = _challenge_display_id_map().get(challenge.id, challenge.id)
    solves = (
        Solves.query.filter_by(challenge_id=challenge.id)
        .order_by(Solves.date.asc())
        .all()
    )
    flags = Flags.query.filter_by(challenge_id=challenge.id).all()

    try:
        challenge_class = get_chal_class(challenge.type)
    except KeyError:
        abort(
            500,
            f"The underlying challenge type ({challenge.type}) is not installed. This challenge can not be loaded.",
        )

    update_j2 = render_template(
        challenge_class.templates["update"].lstrip("/"), challenge=challenge
    )

    update_script = url_for(
        "views.static_html", route=challenge_class.scripts["update"].lstrip("/")
    )
    return render_template(
        "admin/challenges/challenge.html",
        update_template=update_j2,
        update_script=update_script,
        challenge=challenge,
        display_id=display_id,
        challenges=challenges,
        solves=solves,
        flags=flags,
    )


@admin.route("/admin/challenges/preview/<int:challenge_id>")
@admins_only
def challenges_preview(challenge_id):
    challenge = Challenges.query.filter_by(id=challenge_id).first_or_404()
    chal_class = get_chal_class(challenge.type)
    user = get_current_user()
    team = get_current_team()

    files = []
    for f in challenge.files:
        token = {
            "user_id": user.id,
            "team_id": team.id if team else None,
            "file_id": f.id,
        }
        files.append(url_for("views.files", path=f.location, token=serialize(token)))

    tags = [
        tag["value"] for tag in TagSchema("user", many=True).dump(challenge.tags).data
    ]

    content = render_template(
        chal_class.templates["view"].lstrip("/"),
        solves=None,
        solved_by_me=False,
        files=files,
        tags=tags,
        hints=challenge.hints,
        max_attempts=challenge.max_attempts,
        attempts=0,
        challenge=challenge,
        rating=None,
        ratings=None,
    )
    return render_template(
        "admin/challenges/preview.html", content=content, challenge=challenge
    )


@admin.route("/admin/challenges/new")
@admins_only
def challenges_new():
    types = CHALLENGE_CLASSES.keys()
    return render_template("admin/challenges/new.html", types=types)
