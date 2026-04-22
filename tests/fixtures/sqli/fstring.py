# Flask search endpoint — SQLi via Python f-string.

@app.route("/search")
def search():
    q = request.args.get("q", "")
    sort = request.args.get("sort", "created_at")

    # Injection via f-string.
    sql = f"SELECT id, title FROM posts WHERE title LIKE '%{q}%' ORDER BY {sort} LIMIT 50"
    rows = db.session.execute(sql).fetchall()
    return jsonify([dict(r) for r in rows])
