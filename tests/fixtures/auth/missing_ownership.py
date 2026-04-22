# Flask order-edit endpoint — authenticated but no ownership check.
# Any logged-in user can modify any order by guessing the order id.

@app.route("/orders/<int:order_id>", methods=["PATCH"])
@login_required
def update_order(order_id):
    order = db.session.query(Order).filter_by(id=order_id).first()
    if not order:
        abort(404)

    # Missing: no check that current_user.id == order.customer_id.
    order.shipping_address = request.json["shipping_address"]
    order.notes = request.json.get("notes", order.notes)
    db.session.commit()
    return jsonify(order.to_dict())
