from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, HttpResponseRedirect
from django.views.decorators.csrf import csrf_exempt
from django.db import connection
from django.contrib.auth.hashers import make_password, check_password  # used only in FIX

from .models import AppUser, Note


# ---------------------------------------------------------------------------
# AUTH (registration / login) — session is just AppUser.id stored in cookie
# for simplicity; not the focus of the flaws below except where noted.
# ---------------------------------------------------------------------------

def register(request):
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]

        # ------------------------------------------------------------------
        # FLAW 3 (A02:2021 - Cryptographic Failures)
        # Password is stored in plaintext. Anyone with DB access (an insider,
        # a leaked backup, an SQL-injection read via FLAW 2) gets every
        # user's real password directly, not just a hash.
        AppUser.objects.create(username=username, password=make_password(password))

        # ------------------------------------------------------------------
        # FIX  hash the password before storing it, using
        # Django's PBKDF2-based hasher (salted + slow by design).
        # 

        return redirect("login")
    return render(request, "notes/register.html")


def login_view(request):
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]
        try:
            user = AppUser.objects.get(username=username)
        except AppUser.DoesNotExist:
            return HttpResponse("Invalid credentials", status=401)

        # ------------------------------------------------------------------
        # FLAW 3 continued: plaintext comparison instead of a verified hash.
        if user.password == password:
            response = redirect("note_list")
            response.set_cookie("uid", user.id)
            return response

        # ------------------------------------------------------------------
        # FIX
        if check_password(password, user.password):
             response = redirect("note_list")
             response.set_cookie("uid", user.id)
             return response

        return HttpResponse("Invalid credentials", status=401)
    return render(request, "notes/login.html")


def _current_user(request):
    uid = request.COOKIES.get("uid")
    if not uid:
        return None
    return AppUser.objects.filter(id=uid).first()


# ---------------------------------------------------------------------------
# NOTES
# ---------------------------------------------------------------------------

def note_list(request):
    user = _current_user(request)
    if not user:
        return redirect("login")
    notes = Note.objects.filter(owner=user)
    return render(request, "notes/list.html", {"notes": notes})


def note_create(request):
    user = _current_user(request)
    if not user:
        return redirect("login")
    if request.method == "POST":
        title = request.POST.get("title", "")
        body = request.POST.get("body", "")
        Note.objects.create(owner=user, title=title, body=body)
        return redirect("note_list")
    return render(request, "notes/create.html")


def note_detail(request, note_id):
    user = _current_user(request)
    if not user:
        return redirect("login")

    # -----------------------------------------------------------------------
    # FLAW 1 (A01:2021 - Broken Access Control / IDOR)
    # Any logged-in user can view ANY note by guessing/incrementing note_id
    # in the URL — there is no check that note.owner == user.
    note = get_object_or_404(Note, id=note_id, owner=user)

    # -------------------------------------------------------------------
    # FIX: scope the lookup to the current user so a
    # request for someone else's note ID returns 404 instead of the data.
    

    return render(request, "notes/detail.html", {"note": note})


def note_search(request):
    user = _current_user(request)
    if not user:
        return redirect("login")

    query = request.GET.get("q", "")

    # -------------------------------------------------------------------
    # FLAW 2 (A03:2021 - Injection)
    # Raw SQL built via string formatting. A query like:
    #   ' UNION SELECT id, username, password, id FROM notes_appuser -- 
    # lets an attacker read arbitrary tables, including AppUser.password.
    with connection.cursor() as cursor:
        sql = "SELECT id, title, body, owner_id FROM notes_note WHERE owner_id = %s AND title LIKE '%%%s%%'" % (
            user.id, query,
        )
        cursor.execute(sql)
        rows = cursor.fetchall()

    # -------------------------------------------------------------------
    # FIX: use parameterized queries (or better, the ORM)
    # so user input is never concatenated into the SQL string.
    notes = Note.objects.filter(owner=user, title__icontains=query)
    rows = [(n.id, n.title, n.body, n.owner_id) for n in notes]

    return render(request, "notes/search.html", {"rows": rows, "query": query})



def note_delete(request, note_id):
    # -------------------------------------------------------------------
    # FLAW 5 (CSRF)
    # This state-changing POST endpoint is explicitly exempted from CSRF
    # protection. A malicious external page can auto-submit a hidden form
    # to this URL; the victim's browser will include their session cookie,
    # and the note gets deleted without the victim's real intent.
    if request.method == "POST":
        user = _current_user(request)
        note = get_object_or_404(Note, id=note_id, owner=user)
        note.delete()
        return redirect("note_list")
    return HttpResponse(status=405)

    # -------------------------------------------------------------------
    # FIX remove @csrf_exempt entirely (Django's CSRF
    # middleware protects POST views by default as long as the template
    # includes {% csrf_token %} in the delete form and the decorator above
   
