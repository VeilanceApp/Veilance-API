import stripe

import lib.settings as settings
import lib.connectors.sql as sql


conf = settings.load_conf()
stripe.api_key = conf['stripe']['api_key']


def format_price(price):
    if price.unit_amount is None:
        return "Custom or tiered pricing"
    amount = price.unit_amount / 100
    currency = price.currency.upper()
    if price.type == "recurring" and price.recurring:
        interval = price.recurring.interval
        interval_count = price.recurring.interval_count
        if interval_count == 1:
            return f"{currency} {amount:,.2f}/{interval}"
        return f"{currency} {amount:,.2f} every {interval_count} {interval}s"
    return f"{currency} {amount:,.2f} one time"


def get_product():
    product_id = settings.load_conf()['stripe']['products']["premium"]
    product = stripe.Product.retrieve(product_id)
    prices = stripe.Price.list(product=product.id, active=True, limit=30)["data"][0]
    return {
        "price": format_price(prices),
        "currency": prices.currency,
        "type": prices.type,
        "display_name": product.name,
        "product_id": product.id,
    }


def get_stripe_customer(user_email, user_id):
    stripe_id = sql.find_stripe_id_by_user_id(user_id)
    if stripe_id is None:
        results = stripe.Customer.list(email=user_email)
        if len(results.data) == 0:
            stripe.Customer.create(email=user_email)
            customer = stripe.Customer.list(email=user_email)['data'][0]['id']
            sql.update_user_stripe_id(customer, user_id)
        else:
            customer = results['data'][0]['id']
    else:
        customer = stripe_id
    return customer


def get_product_data(product_id):
    return stripe.Product.retrieve(product_id)


def get_price_data(price_id):
    return stripe.Price.retrieve(price_id)


def get_customer_invoices(customer_id, limit=20):
    invoices = []
    data = stripe.Invoice.list(customer=customer_id, limit=limit)
    for item in data:
        invoices.append({
            "invoice_id": item['id'],
            "invoice_pdf": item["invoice_pdf"],
            "invoice_due_date_epoch": settings.timestamp_to_iso(item['due_date']),
            "invoice_item_description": item['lines']['data'][0]['description'],
            "current_invoice_status": item['status']
        })
    return invoices
