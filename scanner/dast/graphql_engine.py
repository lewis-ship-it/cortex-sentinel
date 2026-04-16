# scanner/dast/graphql_engine.py
# FIX: Removed broken Unicode character (衔) from query string.

from urllib.parse import urljoin

# FIX: Clean introspection query — no broken Unicode
GRAPHQL_INTROSPECTION_QUERY = {
    "query": """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args { name type { name kind ofType { name kind } } defaultValue }
        type { name kind ofType { name kind } }
        isDeprecated
        deprecationReason
      }
      inputFields { name type { name kind ofType { name kind } } defaultValue }
      interfaces { name kind }
      enumValues(includeDeprecated: true) { name description isDeprecated }
      possibleTypes { name kind }
    }
    directives {
      name
      description
      locations
      args { name type { name kind ofType { name kind } } defaultValue }
    }
  }
}
"""
}

GRAPHQL_PATHS = ["/graphql", "/graphiql", "/v1/graphql", "/api/graphql", "/query"]


async def check_graphql_introspection(client, base_url: str) -> dict | None:
    """
    Checks each known GraphQL path for introspection.
    Returns a finding dict if found, else None.
    """
    for path in GRAPHQL_PATHS:
        target = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        try:
            res = await client.post(
                target,
                json=GRAPHQL_INTROSPECTION_QUERY,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            if res.status_code != 200:
                continue
            try:
                data = res.json()
            except Exception:
                continue

            if "data" in data and "__schema" in str(data.get("data", {})):
                return {
                    "url":         target,
                    "type":        "GraphQL Introspection Enabled",
                    "severity":    "High",
                    "description": (
                        "The GraphQL endpoint allows full schema introspection. "
                        "Attackers can enumerate all queries, mutations, and field names "
                        "without authentication, dramatically reducing the effort needed "
                        "to exploit the API."
                    ),
                }
        except Exception:
            continue
    return None
