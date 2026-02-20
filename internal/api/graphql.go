package api

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
)

// GraphQLHandler handles GraphQL requests at /graphql.
type GraphQLHandler struct{}

// NewGraphQLHandler creates a new GraphQLHandler.
func NewGraphQLHandler() *GraphQLHandler {
	return &GraphQLHandler{}
}

// graphqlRequest represents an incoming GraphQL request body.
type graphqlRequest struct {
	Query         string                 `json:"query"`
	Variables     map[string]interface{} `json:"variables"`
	OperationName string                `json:"operationName"`
}

// graphqlError represents a GraphQL-spec error.
type graphqlError struct {
	Message    string                   `json:"message"`
	Locations  []map[string]interface{} `json:"locations,omitempty"`
	Path       []interface{}            `json:"path,omitempty"`
	Extensions map[string]interface{}   `json:"extensions,omitempty"`
}

// ServeHTTP handles GraphQL requests, supporting GET and POST.
func (g *GraphQLHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) int {
	if r.Method == http.MethodOptions {
		return handleOptions(w)
	}

	var req graphqlRequest

	switch r.Method {
	case http.MethodGet:
		req.Query = r.URL.Query().Get("query")
		req.OperationName = r.URL.Query().Get("operationName")
		if vars := r.URL.Query().Get("variables"); vars != "" {
			_ = json.Unmarshal([]byte(vars), &req.Variables)
		}

	case http.MethodPost:
		ct := r.Header.Get("Content-Type")
		if strings.Contains(ct, "application/graphql") {
			body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err != nil {
				return g.writeErrors(w, http.StatusBadRequest, graphqlError{
					Message: "Failed to read request body",
				})
			}
			req.Query = string(body)
		} else {
			// Default: application/json
			if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
				return g.writeErrors(w, http.StatusBadRequest, graphqlError{
					Message: fmt.Sprintf("JSON parse error: %s", err.Error()),
					Locations: []map[string]interface{}{
						{"line": 1, "column": 1},
					},
				})
			}
		}

	default:
		w.Header().Set("Allow", "GET, POST, OPTIONS")
		return g.writeErrors(w, http.StatusMethodNotAllowed, graphqlError{
			Message: "GraphQL only supports GET and POST requests",
		})
	}

	query := strings.TrimSpace(req.Query)
	if query == "" {
		return g.writeErrors(w, http.StatusBadRequest, graphqlError{
			Message: "Must provide query string",
			Locations: []map[string]interface{}{
				{"line": 1, "column": 1},
			},
		})
	}

	// Check for introspection queries.
	if strings.Contains(query, "__schema") || strings.Contains(query, "__type") {
		return g.handleIntrospection(w, query)
	}

	// Check for mutation
	if strings.HasPrefix(query, "mutation") {
		return g.handleMutation(w, query, req.Variables)
	}

	// Execute query
	return g.handleQuery(w, query, req.Variables)
}

// writeErrors writes a GraphQL error response.
func (g *GraphQLHandler) writeErrors(w http.ResponseWriter, status int, errs ...graphqlError) int {
	resp := map[string]interface{}{
		"errors": errs,
	}
	writeJSON(w, status, resp)
	return status
}

// handleIntrospection returns a realistic introspection response.
func (g *GraphQLHandler) handleIntrospection(w http.ResponseWriter, query string) int {
	// If querying a specific type
	if strings.Contains(query, "__type") && !strings.Contains(query, "__schema") {
		return g.handleTypeIntrospection(w, query)
	}

	schema := g.buildIntrospectionSchema()

	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"__schema": schema,
		},
	}
	writeJSON(w, http.StatusOK, resp)
	return http.StatusOK
}

// handleTypeIntrospection handles __type queries for specific types.
func (g *GraphQLHandler) handleTypeIntrospection(w http.ResponseWriter, query string) int {
	allTypes := g.buildAllTypes()

	// Try to extract the type name from the query
	typeName := ""
	for _, t := range allTypes {
		name := t["name"].(string)
		if strings.Contains(query, fmt.Sprintf(`"%s"`, name)) || strings.Contains(query, fmt.Sprintf(`'%s'`, name)) {
			typeName = name
			break
		}
	}

	if typeName == "" {
		// Default to Query type
		typeName = "Query"
	}

	for _, t := range allTypes {
		if t["name"].(string) == typeName {
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"data": map[string]interface{}{
					"__type": t,
				},
			})
			return http.StatusOK
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data": map[string]interface{}{
			"__type": nil,
		},
	})
	return http.StatusOK
}

// buildIntrospectionSchema builds the full introspection schema.
func (g *GraphQLHandler) buildIntrospectionSchema() map[string]interface{} {
	allTypes := g.buildAllTypes()

	directives := []map[string]interface{}{
		{
			"name":        "include",
			"description": "Directs the executor to include this field or fragment only when the `if` argument is true.",
			"locations":   []string{"FIELD", "FRAGMENT_SPREAD", "INLINE_FRAGMENT"},
			"args": []map[string]interface{}{
				{
					"name":         "if",
					"description":  "Included when true.",
					"type":         typeRef("NON_NULL", scalarRef("Boolean")),
					"defaultValue": nil,
				},
			},
		},
		{
			"name":        "skip",
			"description": "Directs the executor to skip this field or fragment when the `if` argument is true.",
			"locations":   []string{"FIELD", "FRAGMENT_SPREAD", "INLINE_FRAGMENT"},
			"args": []map[string]interface{}{
				{
					"name":         "if",
					"description":  "Skipped when true.",
					"type":         typeRef("NON_NULL", scalarRef("Boolean")),
					"defaultValue": nil,
				},
			},
		},
		{
			"name":        "deprecated",
			"description": "Marks an element of a GraphQL schema as no longer supported.",
			"locations":   []string{"FIELD_DEFINITION", "ENUM_VALUE"},
			"args": []map[string]interface{}{
				{
					"name":         "reason",
					"description":  "Explains why this element was deprecated.",
					"type":         scalarRef("String"),
					"defaultValue": `"No longer supported"`,
				},
			},
		},
	}

	return map[string]interface{}{
		"queryType":        map[string]interface{}{"name": "Query"},
		"mutationType":     map[string]interface{}{"name": "Mutation"},
		"subscriptionType": nil,
		"types":            allTypes,
		"directives":       directives,
	}
}

// buildAllTypes returns all types for the introspection schema.
func (g *GraphQLHandler) buildAllTypes() []map[string]interface{} {
	types := []map[string]interface{}{
		g.buildQueryType(),
		g.buildMutationType(),
		g.buildUserType(),
		g.buildProductType(),
		g.buildOrderType(),
		g.buildOrderItemType(),
		g.buildPostType(),
		g.buildServerType(),
		g.buildCommentType(),
		g.buildCategoryType(),
		g.buildTagType(),
		g.buildPageInfoType(),
		g.buildAddressType(),
		g.buildUserPreferencesType(),
		g.buildServerMetricsType(),
		g.buildMediaType(),
		g.buildUserConnectionType(),
		g.buildUserEdgeType(),
		g.buildPostConnectionType(),
		g.buildPostEdgeType(),
		g.buildCreateUserInputType(),
		g.buildUpdateUserInputType(),
		g.buildCreatePostInputType(),
		g.buildCreateOrderInputType(),
		g.buildOrderItemInputType(),
		g.buildCreateUserPayloadType(),
		g.buildUpdateUserPayloadType(),
		g.buildDeleteUserPayloadType(),
		g.buildCreatePostPayloadType(),
		g.buildCreateOrderPayloadType(),
		// Scalar types
		scalarType("ID", "The `ID` scalar type represents a unique identifier."),
		scalarType("String", "The `String` scalar type represents textual data."),
		scalarType("Int", "The `Int` scalar type represents non-fractional signed whole numeric values."),
		scalarType("Float", "The `Float` scalar type represents signed double-precision fractional values."),
		scalarType("Boolean", "The `Boolean` scalar type represents `true` or `false`."),
		scalarType("DateTime", "An ISO-8601 encoded UTC date string."),
		scalarType("JSON", "Arbitrary JSON value."),
		scalarType("URL", "A valid URL string."),
		// Enum types
		g.buildUserRoleEnum(),
		g.buildUserStatusEnum(),
		g.buildPostStatusEnum(),
		g.buildOrderStatusEnum(),
		g.buildServerStatusEnum(),
		g.buildSortDirectionEnum(),
	}
	return types
}

// --- Query type ---

func (g *GraphQLHandler) buildQueryType() map[string]interface{} {
	return map[string]interface{}{
		"kind":        "OBJECT",
		"name":        "Query",
		"description": "The root query type.",
		"fields": []map[string]interface{}{
			{
				"name":              "users",
				"description":       "List all users with optional filtering and pagination.",
				"type":              namedRef("UserConnection"),
				"isDeprecated":      false,
				"deprecationReason": nil,
				"args": []map[string]interface{}{
					argDef("first", scalarRef("Int"), "Returns the first N items.", `"20"`),
					argDef("after", scalarRef("String"), "Cursor for forward pagination.", nil),
					argDef("role", namedRef("UserRole"), "Filter by user role.", nil),
					argDef("status", namedRef("UserStatus"), "Filter by user status.", nil),
					argDef("search", scalarRef("String"), "Search users by name or email.", nil),
					argDef("sortBy", scalarRef("String"), "Field to sort by.", `"created_at"`),
					argDef("sortDirection", namedRef("SortDirection"), "Sort direction.", `"DESC"`),
				},
			},
			{
				"name":              "user",
				"description":       "Fetch a single user by ID.",
				"type":              namedRef("User"),
				"isDeprecated":      false,
				"deprecationReason": nil,
				"args": []map[string]interface{}{
					argDef("id", typeRef("NON_NULL", scalarRef("ID")), "The user's unique identifier.", nil),
				},
			},
			{
				"name":              "products",
				"description":       "List all products with optional filtering.",
				"type":              listRef(namedRef("Product")),
				"isDeprecated":      false,
				"deprecationReason": nil,
				"args": []map[string]interface{}{
					argDef("limit", scalarRef("Int"), "Maximum number of products to return.", `"25"`),
					argDef("offset", scalarRef("Int"), "Number of products to skip.", `"0"`),
					argDef("category", scalarRef("String"), "Filter by category slug.", nil),
					argDef("minPrice", scalarRef("Float"), "Minimum price filter.", nil),
					argDef("maxPrice", scalarRef("Float"), "Maximum price filter.", nil),
					argDef("inStock", scalarRef("Boolean"), "Filter by stock availability.", nil),
				},
			},
			{
				"name":              "product",
				"description":       "Fetch a single product by ID.",
				"type":              namedRef("Product"),
				"isDeprecated":      false,
				"deprecationReason": nil,
				"args": []map[string]interface{}{
					argDef("id", typeRef("NON_NULL", scalarRef("ID")), "The product's unique identifier.", nil),
				},
			},
			{
				"name":              "orders",
				"description":       "List orders for the authenticated user.",
				"type":              listRef(namedRef("Order")),
				"isDeprecated":      false,
				"deprecationReason": nil,
				"args": []map[string]interface{}{
					argDef("limit", scalarRef("Int"), "Maximum number of orders to return.", `"20"`),
					argDef("offset", scalarRef("Int"), "Number of orders to skip.", `"0"`),
					argDef("status", namedRef("OrderStatus"), "Filter by order status.", nil),
					argDef("userId", scalarRef("ID"), "Filter by user ID (admin only).", nil),
				},
			},
			{
				"name":              "posts",
				"description":       "List all posts with optional filtering and pagination.",
				"type":              namedRef("PostConnection"),
				"isDeprecated":      false,
				"deprecationReason": nil,
				"args": []map[string]interface{}{
					argDef("first", scalarRef("Int"), "Returns the first N items.", `"20"`),
					argDef("after", scalarRef("String"), "Cursor for forward pagination.", nil),
					argDef("status", namedRef("PostStatus"), "Filter by post status.", nil),
					argDef("authorId", scalarRef("ID"), "Filter by author ID.", nil),
					argDef("tag", scalarRef("String"), "Filter by tag slug.", nil),
					argDef("search", scalarRef("String"), "Full-text search in title and body.", nil),
				},
			},
			{
				"name":              "post",
				"description":       "Fetch a single post by ID or slug.",
				"type":              namedRef("Post"),
				"isDeprecated":      false,
				"deprecationReason": nil,
				"args": []map[string]interface{}{
					argDef("id", scalarRef("ID"), "The post's unique identifier.", nil),
					argDef("slug", scalarRef("String"), "The post's URL slug.", nil),
				},
			},
			{
				"name":              "servers",
				"description":       "List all servers in the infrastructure.",
				"type":              listRef(namedRef("Server")),
				"isDeprecated":      false,
				"deprecationReason": nil,
				"args": []map[string]interface{}{
					argDef("limit", scalarRef("Int"), "Maximum number of servers to return.", `"50"`),
					argDef("offset", scalarRef("Int"), "Number of servers to skip.", `"0"`),
					argDef("status", namedRef("ServerStatus"), "Filter by server status.", nil),
					argDef("region", scalarRef("String"), "Filter by region.", nil),
				},
			},
			{
				"name":              "server",
				"description":       "Fetch a single server by ID or hostname.",
				"type":              namedRef("Server"),
				"isDeprecated":      false,
				"deprecationReason": nil,
				"args": []map[string]interface{}{
					argDef("id", typeRef("NON_NULL", scalarRef("ID")), "The server's unique identifier.", nil),
				},
			},
			{
				"name":              "categories",
				"description":       "List all product categories.",
				"type":              listRef(namedRef("Category")),
				"isDeprecated":      false,
				"deprecationReason": nil,
				"args":              []map[string]interface{}{},
			},
			{
				"name":              "tags",
				"description":       "List all content tags.",
				"type":              listRef(namedRef("Tag")),
				"isDeprecated":      false,
				"deprecationReason": nil,
				"args": []map[string]interface{}{
					argDef("limit", scalarRef("Int"), "Maximum number of tags to return.", `"100"`),
				},
			},
			{
				"name":              "node",
				"description":       "Fetches an object given its global ID.",
				"type":              namedRef("Node"),
				"isDeprecated":      false,
				"deprecationReason": nil,
				"args": []map[string]interface{}{
					argDef("id", typeRef("NON_NULL", scalarRef("ID")), "The global ID of the object.", nil),
				},
			},
		},
		"interfaces":    []interface{}{},
		"enumValues":    nil,
		"inputFields":   nil,
		"possibleTypes": nil,
	}
}

// --- Mutation type ---

func (g *GraphQLHandler) buildMutationType() map[string]interface{} {
	return map[string]interface{}{
		"kind":        "OBJECT",
		"name":        "Mutation",
		"description": "The root mutation type.",
		"fields": []map[string]interface{}{
			{
				"name":              "createUser",
				"description":       "Create a new user account.",
				"type":              namedRef("CreateUserPayload"),
				"isDeprecated":      false,
				"deprecationReason": nil,
				"args": []map[string]interface{}{
					argDef("input", typeRef("NON_NULL", namedRef("CreateUserInput")), "The user data for creation.", nil),
				},
			},
			{
				"name":              "updateUser",
				"description":       "Update an existing user.",
				"type":              namedRef("UpdateUserPayload"),
				"isDeprecated":      false,
				"deprecationReason": nil,
				"args": []map[string]interface{}{
					argDef("id", typeRef("NON_NULL", scalarRef("ID")), "The user's unique identifier.", nil),
					argDef("input", typeRef("NON_NULL", namedRef("UpdateUserInput")), "The fields to update.", nil),
				},
			},
			{
				"name":              "deleteUser",
				"description":       "Delete a user account. This action is irreversible.",
				"type":              namedRef("DeleteUserPayload"),
				"isDeprecated":      false,
				"deprecationReason": nil,
				"args": []map[string]interface{}{
					argDef("id", typeRef("NON_NULL", scalarRef("ID")), "The user's unique identifier.", nil),
				},
			},
			{
				"name":              "createPost",
				"description":       "Create a new blog post.",
				"type":              namedRef("CreatePostPayload"),
				"isDeprecated":      false,
				"deprecationReason": nil,
				"args": []map[string]interface{}{
					argDef("input", typeRef("NON_NULL", namedRef("CreatePostInput")), "The post data for creation.", nil),
				},
			},
			{
				"name":              "createOrder",
				"description":       "Create a new order.",
				"type":              namedRef("CreateOrderPayload"),
				"isDeprecated":      false,
				"deprecationReason": nil,
				"args": []map[string]interface{}{
					argDef("input", typeRef("NON_NULL", namedRef("CreateOrderInput")), "The order data for creation.", nil),
				},
			},
		},
		"interfaces":    []interface{}{},
		"enumValues":    nil,
		"inputFields":   nil,
		"possibleTypes": nil,
	}
}

// --- Object types ---

func (g *GraphQLHandler) buildUserType() map[string]interface{} {
	return map[string]interface{}{
		"kind":        "OBJECT",
		"name":        "User",
		"description": "A user account in the system.",
		"fields": []map[string]interface{}{
			fieldDef("id", typeRef("NON_NULL", scalarRef("ID")), "Unique identifier for the user."),
			fieldDef("username", typeRef("NON_NULL", scalarRef("String")), "The user's login name."),
			fieldDef("email", typeRef("NON_NULL", scalarRef("String")), "The user's email address."),
			fieldDef("fullName", scalarRef("String"), "The user's display name."),
			fieldDef("role", namedRef("UserRole"), "The user's assigned role."),
			fieldDef("status", namedRef("UserStatus"), "Current account status."),
			fieldDef("avatarUrl", scalarRef("URL"), "URL to the user's avatar image."),
			fieldDef("phone", scalarRef("String"), "The user's phone number."),
			fieldDef("address", namedRef("Address"), "The user's mailing address."),
			fieldDef("preferences", namedRef("UserPreferences"), "The user's application preferences."),
			fieldDef("loginCount", scalarRef("Int"), "Total number of logins."),
			fieldDef("twoFactorEnabled", scalarRef("Boolean"), "Whether two-factor authentication is enabled."),
			fieldDef("createdAt", scalarRef("DateTime"), "When the account was created."),
			fieldDef("updatedAt", scalarRef("DateTime"), "When the account was last updated."),
			fieldDef("lastLogin", scalarRef("DateTime"), "When the user last logged in."),
			{
				"name":              "posts",
				"description":       "Posts authored by this user.",
				"type":              namedRef("PostConnection"),
				"isDeprecated":      false,
				"deprecationReason": nil,
				"args": []map[string]interface{}{
					argDef("first", scalarRef("Int"), "Returns the first N posts.", `"10"`),
					argDef("after", scalarRef("String"), "Cursor for forward pagination.", nil),
				},
			},
		},
		"interfaces":    []map[string]interface{}{{"name": "Node"}},
		"enumValues":    nil,
		"inputFields":   nil,
		"possibleTypes": nil,
	}
}

func (g *GraphQLHandler) buildProductType() map[string]interface{} {
	return map[string]interface{}{
		"kind":        "OBJECT",
		"name":        "Product",
		"description": "A product available in the store.",
		"fields": []map[string]interface{}{
			fieldDef("id", typeRef("NON_NULL", scalarRef("ID")), "Unique identifier for the product."),
			fieldDef("name", typeRef("NON_NULL", scalarRef("String")), "The product name."),
			fieldDef("slug", typeRef("NON_NULL", scalarRef("String")), "URL-friendly identifier."),
			fieldDef("description", scalarRef("String"), "Detailed product description."),
			fieldDef("price", typeRef("NON_NULL", scalarRef("Float")), "Current price in USD."),
			fieldDef("compareAtPrice", scalarRef("Float"), "Original price before discount."),
			fieldDef("sku", typeRef("NON_NULL", scalarRef("String")), "Stock keeping unit."),
			fieldDef("inStock", typeRef("NON_NULL", scalarRef("Boolean")), "Whether the product is in stock."),
			fieldDef("stockQuantity", scalarRef("Int"), "Available quantity in stock."),
			fieldDef("category", namedRef("Category"), "The product's category."),
			fieldDef("tags", listRef(namedRef("Tag")), "Tags associated with this product."),
			fieldDef("imageUrl", scalarRef("URL"), "Primary product image URL."),
			fieldDef("thumbnailUrl", scalarRef("URL"), "Product thumbnail URL."),
			fieldDef("weight", scalarRef("Float"), "Product weight in kilograms."),
			fieldDef("dimensions", scalarRef("String"), "Product dimensions (LxWxH)."),
			fieldDef("rating", scalarRef("Float"), "Average customer rating (0-5)."),
			fieldDef("reviewCount", scalarRef("Int"), "Number of customer reviews."),
			fieldDef("createdAt", scalarRef("DateTime"), "When the product was added."),
			fieldDef("updatedAt", scalarRef("DateTime"), "When the product was last updated."),
		},
		"interfaces":    []map[string]interface{}{{"name": "Node"}},
		"enumValues":    nil,
		"inputFields":   nil,
		"possibleTypes": nil,
	}
}

func (g *GraphQLHandler) buildOrderType() map[string]interface{} {
	return map[string]interface{}{
		"kind":        "OBJECT",
		"name":        "Order",
		"description": "A customer order.",
		"fields": []map[string]interface{}{
			fieldDef("id", typeRef("NON_NULL", scalarRef("ID")), "Unique identifier for the order."),
			fieldDef("orderNumber", typeRef("NON_NULL", scalarRef("String")), "Human-readable order number."),
			fieldDef("status", namedRef("OrderStatus"), "Current order status."),
			fieldDef("customer", namedRef("User"), "The customer who placed the order."),
			fieldDef("items", typeRef("NON_NULL", listRef(namedRef("OrderItem"))), "Line items in the order."),
			fieldDef("subtotal", typeRef("NON_NULL", scalarRef("Float")), "Order subtotal before tax and shipping."),
			fieldDef("tax", scalarRef("Float"), "Tax amount."),
			fieldDef("shippingCost", scalarRef("Float"), "Shipping cost."),
			fieldDef("total", typeRef("NON_NULL", scalarRef("Float")), "Order total including tax and shipping."),
			fieldDef("currency", typeRef("NON_NULL", scalarRef("String")), "Currency code (e.g. USD)."),
			fieldDef("shippingAddress", namedRef("Address"), "Shipping address."),
			fieldDef("billingAddress", namedRef("Address"), "Billing address."),
			fieldDef("notes", scalarRef("String"), "Customer notes for the order."),
			fieldDef("createdAt", scalarRef("DateTime"), "When the order was placed."),
			fieldDef("updatedAt", scalarRef("DateTime"), "When the order was last updated."),
			fieldDef("shippedAt", scalarRef("DateTime"), "When the order was shipped."),
		},
		"interfaces":    []map[string]interface{}{{"name": "Node"}},
		"enumValues":    nil,
		"inputFields":   nil,
		"possibleTypes": nil,
	}
}

func (g *GraphQLHandler) buildOrderItemType() map[string]interface{} {
	return map[string]interface{}{
		"kind":        "OBJECT",
		"name":        "OrderItem",
		"description": "A single line item in an order.",
		"fields": []map[string]interface{}{
			fieldDef("id", typeRef("NON_NULL", scalarRef("ID")), "Unique identifier for the line item."),
			fieldDef("product", namedRef("Product"), "The product ordered."),
			fieldDef("quantity", typeRef("NON_NULL", scalarRef("Int")), "Quantity ordered."),
			fieldDef("unitPrice", typeRef("NON_NULL", scalarRef("Float")), "Price per unit at time of order."),
			fieldDef("total", typeRef("NON_NULL", scalarRef("Float")), "Line item total."),
		},
		"interfaces":    []interface{}{},
		"enumValues":    nil,
		"inputFields":   nil,
		"possibleTypes": nil,
	}
}

func (g *GraphQLHandler) buildPostType() map[string]interface{} {
	return map[string]interface{}{
		"kind":        "OBJECT",
		"name":        "Post",
		"description": "A blog post or article.",
		"fields": []map[string]interface{}{
			fieldDef("id", typeRef("NON_NULL", scalarRef("ID")), "Unique identifier for the post."),
			fieldDef("title", typeRef("NON_NULL", scalarRef("String")), "The post title."),
			fieldDef("slug", typeRef("NON_NULL", scalarRef("String")), "URL-friendly identifier."),
			fieldDef("body", scalarRef("String"), "The full post content in HTML."),
			fieldDef("excerpt", scalarRef("String"), "Short summary of the post."),
			fieldDef("status", namedRef("PostStatus"), "Publication status."),
			fieldDef("author", namedRef("User"), "The post author."),
			fieldDef("featuredImage", namedRef("Media"), "Featured image for the post."),
			fieldDef("tags", listRef(namedRef("Tag")), "Tags associated with this post."),
			fieldDef("category", namedRef("Category"), "Primary category."),
			fieldDef("wordCount", scalarRef("Int"), "Number of words in the post body."),
			fieldDef("readingTime", scalarRef("Int"), "Estimated reading time in minutes."),
			fieldDef("viewCount", scalarRef("Int"), "Number of views."),
			fieldDef("likeCount", scalarRef("Int"), "Number of likes."),
			{
				"name":              "comments",
				"description":       "Comments on this post.",
				"type":              listRef(namedRef("Comment")),
				"isDeprecated":      false,
				"deprecationReason": nil,
				"args": []map[string]interface{}{
					argDef("first", scalarRef("Int"), "Returns the first N comments.", `"10"`),
					argDef("after", scalarRef("String"), "Cursor for forward pagination.", nil),
				},
			},
			fieldDef("publishedAt", scalarRef("DateTime"), "When the post was published."),
			fieldDef("createdAt", scalarRef("DateTime"), "When the post was created."),
			fieldDef("updatedAt", scalarRef("DateTime"), "When the post was last updated."),
		},
		"interfaces":    []map[string]interface{}{{"name": "Node"}},
		"enumValues":    nil,
		"inputFields":   nil,
		"possibleTypes": nil,
	}
}

func (g *GraphQLHandler) buildServerType() map[string]interface{} {
	return map[string]interface{}{
		"kind":        "OBJECT",
		"name":        "Server",
		"description": "A server in the infrastructure.",
		"fields": []map[string]interface{}{
			fieldDef("id", typeRef("NON_NULL", scalarRef("ID")), "Unique identifier for the server."),
			fieldDef("hostname", typeRef("NON_NULL", scalarRef("String")), "Server hostname."),
			fieldDef("ipAddress", scalarRef("String"), "Server IP address."),
			fieldDef("status", namedRef("ServerStatus"), "Current server status."),
			fieldDef("region", scalarRef("String"), "Data center region."),
			fieldDef("provider", scalarRef("String"), "Cloud provider."),
			fieldDef("instanceType", scalarRef("String"), "Instance type (e.g. t3.medium)."),
			fieldDef("os", scalarRef("String"), "Operating system."),
			fieldDef("cpuCores", scalarRef("Int"), "Number of CPU cores."),
			fieldDef("memoryGb", scalarRef("Float"), "Memory in gigabytes."),
			fieldDef("diskGb", scalarRef("Float"), "Disk capacity in gigabytes."),
			fieldDef("metrics", namedRef("ServerMetrics"), "Current performance metrics."),
			fieldDef("tags", listRef(scalarRef("String")), "Organizational tags."),
			fieldDef("createdAt", scalarRef("DateTime"), "When the server was provisioned."),
			fieldDef("updatedAt", scalarRef("DateTime"), "When the server record was last updated."),
			fieldDef("lastHealthCheck", scalarRef("DateTime"), "When the last health check ran."),
		},
		"interfaces":    []map[string]interface{}{{"name": "Node"}},
		"enumValues":    nil,
		"inputFields":   nil,
		"possibleTypes": nil,
	}
}

func (g *GraphQLHandler) buildCommentType() map[string]interface{} {
	return map[string]interface{}{
		"kind":        "OBJECT",
		"name":        "Comment",
		"description": "A comment on a post.",
		"fields": []map[string]interface{}{
			fieldDef("id", typeRef("NON_NULL", scalarRef("ID")), "Unique identifier for the comment."),
			fieldDef("body", typeRef("NON_NULL", scalarRef("String")), "The comment text."),
			fieldDef("author", namedRef("User"), "The comment author."),
			fieldDef("post", namedRef("Post"), "The post this comment belongs to."),
			fieldDef("parentComment", namedRef("Comment"), "Parent comment for nested replies."),
			fieldDef("likeCount", scalarRef("Int"), "Number of likes."),
			fieldDef("createdAt", scalarRef("DateTime"), "When the comment was posted."),
			fieldDef("updatedAt", scalarRef("DateTime"), "When the comment was last edited."),
		},
		"interfaces":    []map[string]interface{}{{"name": "Node"}},
		"enumValues":    nil,
		"inputFields":   nil,
		"possibleTypes": nil,
	}
}

func (g *GraphQLHandler) buildCategoryType() map[string]interface{} {
	return map[string]interface{}{
		"kind":        "OBJECT",
		"name":        "Category",
		"description": "A product or content category.",
		"fields": []map[string]interface{}{
			fieldDef("id", typeRef("NON_NULL", scalarRef("ID")), "Unique identifier for the category."),
			fieldDef("name", typeRef("NON_NULL", scalarRef("String")), "Category name."),
			fieldDef("slug", typeRef("NON_NULL", scalarRef("String")), "URL-friendly identifier."),
			fieldDef("description", scalarRef("String"), "Category description."),
			fieldDef("parentCategory", namedRef("Category"), "Parent category for nested hierarchy."),
			fieldDef("productCount", scalarRef("Int"), "Number of products in this category."),
			fieldDef("imageUrl", scalarRef("URL"), "Category image URL."),
		},
		"interfaces":    []map[string]interface{}{{"name": "Node"}},
		"enumValues":    nil,
		"inputFields":   nil,
		"possibleTypes": nil,
	}
}

func (g *GraphQLHandler) buildTagType() map[string]interface{} {
	return map[string]interface{}{
		"kind":        "OBJECT",
		"name":        "Tag",
		"description": "A tag for content organization.",
		"fields": []map[string]interface{}{
			fieldDef("id", typeRef("NON_NULL", scalarRef("ID")), "Unique identifier for the tag."),
			fieldDef("name", typeRef("NON_NULL", scalarRef("String")), "Tag name."),
			fieldDef("slug", typeRef("NON_NULL", scalarRef("String")), "URL-friendly identifier."),
			fieldDef("postCount", scalarRef("Int"), "Number of posts with this tag."),
		},
		"interfaces":    []interface{}{},
		"enumValues":    nil,
		"inputFields":   nil,
		"possibleTypes": nil,
	}
}

func (g *GraphQLHandler) buildPageInfoType() map[string]interface{} {
	return map[string]interface{}{
		"kind":        "OBJECT",
		"name":        "PageInfo",
		"description": "Information about pagination in a connection.",
		"fields": []map[string]interface{}{
			fieldDef("hasNextPage", typeRef("NON_NULL", scalarRef("Boolean")), "Whether more items exist after the last item in this page."),
			fieldDef("hasPreviousPage", typeRef("NON_NULL", scalarRef("Boolean")), "Whether more items exist before the first item in this page."),
			fieldDef("startCursor", scalarRef("String"), "Cursor of the first item in this page."),
			fieldDef("endCursor", scalarRef("String"), "Cursor of the last item in this page."),
			fieldDef("totalCount", scalarRef("Int"), "Total number of items in the connection."),
		},
		"interfaces":    []interface{}{},
		"enumValues":    nil,
		"inputFields":   nil,
		"possibleTypes": nil,
	}
}

func (g *GraphQLHandler) buildAddressType() map[string]interface{} {
	return map[string]interface{}{
		"kind":        "OBJECT",
		"name":        "Address",
		"description": "A physical mailing address.",
		"fields": []map[string]interface{}{
			fieldDef("street", scalarRef("String"), "Street address line."),
			fieldDef("city", scalarRef("String"), "City name."),
			fieldDef("state", scalarRef("String"), "State or province."),
			fieldDef("zip", scalarRef("String"), "Postal code."),
			fieldDef("country", scalarRef("String"), "Country code."),
		},
		"interfaces":    []interface{}{},
		"enumValues":    nil,
		"inputFields":   nil,
		"possibleTypes": nil,
	}
}

func (g *GraphQLHandler) buildUserPreferencesType() map[string]interface{} {
	return map[string]interface{}{
		"kind":        "OBJECT",
		"name":        "UserPreferences",
		"description": "User application preferences.",
		"fields": []map[string]interface{}{
			fieldDef("theme", scalarRef("String"), "UI theme preference."),
			fieldDef("language", scalarRef("String"), "Preferred language code."),
			fieldDef("timezone", scalarRef("String"), "Preferred timezone."),
			fieldDef("notifications", scalarRef("Boolean"), "Whether notifications are enabled."),
			fieldDef("emailDigest", scalarRef("Boolean"), "Whether email digests are enabled."),
			fieldDef("itemsPerPage", scalarRef("Int"), "Default items per page."),
		},
		"interfaces":    []interface{}{},
		"enumValues":    nil,
		"inputFields":   nil,
		"possibleTypes": nil,
	}
}

func (g *GraphQLHandler) buildServerMetricsType() map[string]interface{} {
	return map[string]interface{}{
		"kind":        "OBJECT",
		"name":        "ServerMetrics",
		"description": "Current server performance metrics.",
		"fields": []map[string]interface{}{
			fieldDef("cpuUsage", scalarRef("Float"), "CPU usage percentage (0-100)."),
			fieldDef("memoryUsage", scalarRef("Float"), "Memory usage percentage (0-100)."),
			fieldDef("diskUsage", scalarRef("Float"), "Disk usage percentage (0-100)."),
			fieldDef("networkIn", scalarRef("Float"), "Network ingress in Mbps."),
			fieldDef("networkOut", scalarRef("Float"), "Network egress in Mbps."),
			fieldDef("requestsPerSecond", scalarRef("Float"), "Current requests per second."),
			fieldDef("avgResponseTime", scalarRef("Float"), "Average response time in milliseconds."),
			fieldDef("uptime", scalarRef("Int"), "Uptime in seconds."),
		},
		"interfaces":    []interface{}{},
		"enumValues":    nil,
		"inputFields":   nil,
		"possibleTypes": nil,
	}
}

func (g *GraphQLHandler) buildMediaType() map[string]interface{} {
	return map[string]interface{}{
		"kind":        "OBJECT",
		"name":        "Media",
		"description": "An uploaded media file.",
		"fields": []map[string]interface{}{
			fieldDef("id", typeRef("NON_NULL", scalarRef("ID")), "Unique identifier for the media item."),
			fieldDef("url", typeRef("NON_NULL", scalarRef("URL")), "Full URL to the media file."),
			fieldDef("thumbnailUrl", scalarRef("URL"), "Thumbnail URL."),
			fieldDef("mimeType", scalarRef("String"), "MIME type of the file."),
			fieldDef("filename", scalarRef("String"), "Original filename."),
			fieldDef("size", scalarRef("Int"), "File size in bytes."),
			fieldDef("width", scalarRef("Int"), "Image width in pixels."),
			fieldDef("height", scalarRef("Int"), "Image height in pixels."),
			fieldDef("alt", scalarRef("String"), "Alt text for accessibility."),
			fieldDef("createdAt", scalarRef("DateTime"), "When the media was uploaded."),
		},
		"interfaces":    []map[string]interface{}{{"name": "Node"}},
		"enumValues":    nil,
		"inputFields":   nil,
		"possibleTypes": nil,
	}
}

// --- Connection types (Relay-style pagination) ---

func (g *GraphQLHandler) buildUserConnectionType() map[string]interface{} {
	return map[string]interface{}{
		"kind":        "OBJECT",
		"name":        "UserConnection",
		"description": "A paginated list of users.",
		"fields": []map[string]interface{}{
			fieldDef("edges", typeRef("NON_NULL", listRef(namedRef("UserEdge"))), "The list of edges."),
			fieldDef("pageInfo", typeRef("NON_NULL", namedRef("PageInfo")), "Pagination info."),
			fieldDef("totalCount", typeRef("NON_NULL", scalarRef("Int")), "Total number of users."),
		},
		"interfaces":    []interface{}{},
		"enumValues":    nil,
		"inputFields":   nil,
		"possibleTypes": nil,
	}
}

func (g *GraphQLHandler) buildUserEdgeType() map[string]interface{} {
	return map[string]interface{}{
		"kind":        "OBJECT",
		"name":        "UserEdge",
		"description": "An edge in a UserConnection.",
		"fields": []map[string]interface{}{
			fieldDef("node", typeRef("NON_NULL", namedRef("User")), "The user at the end of the edge."),
			fieldDef("cursor", typeRef("NON_NULL", scalarRef("String")), "A cursor for pagination."),
		},
		"interfaces":    []interface{}{},
		"enumValues":    nil,
		"inputFields":   nil,
		"possibleTypes": nil,
	}
}

func (g *GraphQLHandler) buildPostConnectionType() map[string]interface{} {
	return map[string]interface{}{
		"kind":        "OBJECT",
		"name":        "PostConnection",
		"description": "A paginated list of posts.",
		"fields": []map[string]interface{}{
			fieldDef("edges", typeRef("NON_NULL", listRef(namedRef("PostEdge"))), "The list of edges."),
			fieldDef("pageInfo", typeRef("NON_NULL", namedRef("PageInfo")), "Pagination info."),
			fieldDef("totalCount", typeRef("NON_NULL", scalarRef("Int")), "Total number of posts."),
		},
		"interfaces":    []interface{}{},
		"enumValues":    nil,
		"inputFields":   nil,
		"possibleTypes": nil,
	}
}

func (g *GraphQLHandler) buildPostEdgeType() map[string]interface{} {
	return map[string]interface{}{
		"kind":        "OBJECT",
		"name":        "PostEdge",
		"description": "An edge in a PostConnection.",
		"fields": []map[string]interface{}{
			fieldDef("node", typeRef("NON_NULL", namedRef("Post")), "The post at the end of the edge."),
			fieldDef("cursor", typeRef("NON_NULL", scalarRef("String")), "A cursor for pagination."),
		},
		"interfaces":    []interface{}{},
		"enumValues":    nil,
		"inputFields":   nil,
		"possibleTypes": nil,
	}
}

// --- Input types ---

func (g *GraphQLHandler) buildCreateUserInputType() map[string]interface{} {
	return map[string]interface{}{
		"kind":        "INPUT_OBJECT",
		"name":        "CreateUserInput",
		"description": "Input for creating a new user.",
		"inputFields": []map[string]interface{}{
			inputFieldDef("username", typeRef("NON_NULL", scalarRef("String")), "The desired username."),
			inputFieldDef("email", typeRef("NON_NULL", scalarRef("String")), "The user's email address."),
			inputFieldDef("fullName", scalarRef("String"), "The user's display name."),
			inputFieldDef("role", namedRef("UserRole"), "The role to assign."),
			inputFieldDef("password", typeRef("NON_NULL", scalarRef("String")), "The account password."),
		},
		"fields":        nil,
		"interfaces":    nil,
		"enumValues":    nil,
		"possibleTypes": nil,
	}
}

func (g *GraphQLHandler) buildUpdateUserInputType() map[string]interface{} {
	return map[string]interface{}{
		"kind":        "INPUT_OBJECT",
		"name":        "UpdateUserInput",
		"description": "Input for updating an existing user.",
		"inputFields": []map[string]interface{}{
			inputFieldDef("username", scalarRef("String"), "New username."),
			inputFieldDef("email", scalarRef("String"), "New email address."),
			inputFieldDef("fullName", scalarRef("String"), "New display name."),
			inputFieldDef("role", namedRef("UserRole"), "New role."),
			inputFieldDef("status", namedRef("UserStatus"), "New account status."),
		},
		"fields":        nil,
		"interfaces":    nil,
		"enumValues":    nil,
		"possibleTypes": nil,
	}
}

func (g *GraphQLHandler) buildCreatePostInputType() map[string]interface{} {
	return map[string]interface{}{
		"kind":        "INPUT_OBJECT",
		"name":        "CreatePostInput",
		"description": "Input for creating a new blog post.",
		"inputFields": []map[string]interface{}{
			inputFieldDef("title", typeRef("NON_NULL", scalarRef("String")), "The post title."),
			inputFieldDef("body", typeRef("NON_NULL", scalarRef("String")), "The post content in HTML or markdown."),
			inputFieldDef("excerpt", scalarRef("String"), "Short summary of the post."),
			inputFieldDef("status", namedRef("PostStatus"), "Publication status."),
			inputFieldDef("tags", listRef(scalarRef("ID")), "Tag IDs to associate."),
			inputFieldDef("categoryId", scalarRef("ID"), "Primary category ID."),
			inputFieldDef("featuredImageId", scalarRef("ID"), "Media ID for the featured image."),
		},
		"fields":        nil,
		"interfaces":    nil,
		"enumValues":    nil,
		"possibleTypes": nil,
	}
}

func (g *GraphQLHandler) buildCreateOrderInputType() map[string]interface{} {
	return map[string]interface{}{
		"kind":        "INPUT_OBJECT",
		"name":        "CreateOrderInput",
		"description": "Input for creating a new order.",
		"inputFields": []map[string]interface{}{
			inputFieldDef("items", typeRef("NON_NULL", listRef(namedRef("OrderItemInput"))), "Line items for the order."),
			inputFieldDef("shippingAddressStreet", scalarRef("String"), "Shipping street address."),
			inputFieldDef("shippingAddressCity", scalarRef("String"), "Shipping city."),
			inputFieldDef("shippingAddressState", scalarRef("String"), "Shipping state."),
			inputFieldDef("shippingAddressZip", scalarRef("String"), "Shipping postal code."),
			inputFieldDef("shippingAddressCountry", scalarRef("String"), "Shipping country code."),
			inputFieldDef("notes", scalarRef("String"), "Order notes."),
		},
		"fields":        nil,
		"interfaces":    nil,
		"enumValues":    nil,
		"possibleTypes": nil,
	}
}

func (g *GraphQLHandler) buildOrderItemInputType() map[string]interface{} {
	return map[string]interface{}{
		"kind":        "INPUT_OBJECT",
		"name":        "OrderItemInput",
		"description": "Input for a single order line item.",
		"inputFields": []map[string]interface{}{
			inputFieldDef("productId", typeRef("NON_NULL", scalarRef("ID")), "Product to order."),
			inputFieldDef("quantity", typeRef("NON_NULL", scalarRef("Int")), "Quantity to order."),
		},
		"fields":        nil,
		"interfaces":    nil,
		"enumValues":    nil,
		"possibleTypes": nil,
	}
}

// --- Payload types ---

func (g *GraphQLHandler) buildCreateUserPayloadType() map[string]interface{} {
	return map[string]interface{}{
		"kind":        "OBJECT",
		"name":        "CreateUserPayload",
		"description": "Response payload for createUser mutation.",
		"fields": []map[string]interface{}{
			fieldDef("user", namedRef("User"), "The created user."),
			fieldDef("clientMutationId", scalarRef("String"), "A unique identifier for the client performing the mutation."),
		},
		"interfaces":    []interface{}{},
		"enumValues":    nil,
		"inputFields":   nil,
		"possibleTypes": nil,
	}
}

func (g *GraphQLHandler) buildUpdateUserPayloadType() map[string]interface{} {
	return map[string]interface{}{
		"kind":        "OBJECT",
		"name":        "UpdateUserPayload",
		"description": "Response payload for updateUser mutation.",
		"fields": []map[string]interface{}{
			fieldDef("user", namedRef("User"), "The updated user."),
			fieldDef("clientMutationId", scalarRef("String"), "A unique identifier for the client performing the mutation."),
		},
		"interfaces":    []interface{}{},
		"enumValues":    nil,
		"inputFields":   nil,
		"possibleTypes": nil,
	}
}

func (g *GraphQLHandler) buildDeleteUserPayloadType() map[string]interface{} {
	return map[string]interface{}{
		"kind":        "OBJECT",
		"name":        "DeleteUserPayload",
		"description": "Response payload for deleteUser mutation.",
		"fields": []map[string]interface{}{
			fieldDef("deletedId", scalarRef("ID"), "The ID of the deleted user."),
			fieldDef("success", typeRef("NON_NULL", scalarRef("Boolean")), "Whether the deletion was successful."),
			fieldDef("clientMutationId", scalarRef("String"), "A unique identifier for the client performing the mutation."),
		},
		"interfaces":    []interface{}{},
		"enumValues":    nil,
		"inputFields":   nil,
		"possibleTypes": nil,
	}
}

func (g *GraphQLHandler) buildCreatePostPayloadType() map[string]interface{} {
	return map[string]interface{}{
		"kind":        "OBJECT",
		"name":        "CreatePostPayload",
		"description": "Response payload for createPost mutation.",
		"fields": []map[string]interface{}{
			fieldDef("post", namedRef("Post"), "The created post."),
			fieldDef("clientMutationId", scalarRef("String"), "A unique identifier for the client performing the mutation."),
		},
		"interfaces":    []interface{}{},
		"enumValues":    nil,
		"inputFields":   nil,
		"possibleTypes": nil,
	}
}

func (g *GraphQLHandler) buildCreateOrderPayloadType() map[string]interface{} {
	return map[string]interface{}{
		"kind":        "OBJECT",
		"name":        "CreateOrderPayload",
		"description": "Response payload for createOrder mutation.",
		"fields": []map[string]interface{}{
			fieldDef("order", namedRef("Order"), "The created order."),
			fieldDef("clientMutationId", scalarRef("String"), "A unique identifier for the client performing the mutation."),
		},
		"interfaces":    []interface{}{},
		"enumValues":    nil,
		"inputFields":   nil,
		"possibleTypes": nil,
	}
}

// --- Enum types ---

func (g *GraphQLHandler) buildUserRoleEnum() map[string]interface{} {
	return map[string]interface{}{
		"kind":        "ENUM",
		"name":        "UserRole",
		"description": "The role assigned to a user account.",
		"enumValues": []map[string]interface{}{
			enumVal("ADMIN", "Full access to all resources and settings."),
			enumVal("EDITOR", "Can create, edit, and publish content."),
			enumVal("VIEWER", "Read-only access to content and dashboards."),
			enumVal("USER", "Standard user with basic access."),
		},
		"fields":        nil,
		"interfaces":    nil,
		"inputFields":   nil,
		"possibleTypes": nil,
	}
}

func (g *GraphQLHandler) buildUserStatusEnum() map[string]interface{} {
	return map[string]interface{}{
		"kind":        "ENUM",
		"name":        "UserStatus",
		"description": "The status of a user account.",
		"enumValues": []map[string]interface{}{
			enumVal("ACTIVE", "The account is active and in good standing."),
			enumVal("SUSPENDED", "The account has been temporarily suspended."),
			enumVal("PENDING", "The account is awaiting email verification."),
			enumVal("DEACTIVATED", "The account has been deactivated by the user."),
		},
		"fields":        nil,
		"interfaces":    nil,
		"inputFields":   nil,
		"possibleTypes": nil,
	}
}

func (g *GraphQLHandler) buildPostStatusEnum() map[string]interface{} {
	return map[string]interface{}{
		"kind":        "ENUM",
		"name":        "PostStatus",
		"description": "The publication status of a post.",
		"enumValues": []map[string]interface{}{
			enumVal("DRAFT", "Post is being worked on and is not publicly visible."),
			enumVal("PUBLISHED", "Post is live and publicly visible."),
			enumVal("ARCHIVED", "Post has been archived and is no longer visible."),
			enumVal("SCHEDULED", "Post is scheduled for future publication."),
		},
		"fields":        nil,
		"interfaces":    nil,
		"inputFields":   nil,
		"possibleTypes": nil,
	}
}

func (g *GraphQLHandler) buildOrderStatusEnum() map[string]interface{} {
	return map[string]interface{}{
		"kind":        "ENUM",
		"name":        "OrderStatus",
		"description": "The status of a customer order.",
		"enumValues": []map[string]interface{}{
			enumVal("PENDING", "Order has been placed but not yet processed."),
			enumVal("CONFIRMED", "Order has been confirmed and is being prepared."),
			enumVal("PROCESSING", "Order is being processed."),
			enumVal("SHIPPED", "Order has been shipped."),
			enumVal("DELIVERED", "Order has been delivered."),
			enumVal("CANCELLED", "Order has been cancelled."),
			enumVal("REFUNDED", "Order has been refunded."),
		},
		"fields":        nil,
		"interfaces":    nil,
		"inputFields":   nil,
		"possibleTypes": nil,
	}
}

func (g *GraphQLHandler) buildServerStatusEnum() map[string]interface{} {
	return map[string]interface{}{
		"kind":        "ENUM",
		"name":        "ServerStatus",
		"description": "The operational status of a server.",
		"enumValues": []map[string]interface{}{
			enumVal("RUNNING", "Server is running and healthy."),
			enumVal("STOPPED", "Server has been stopped."),
			enumVal("STARTING", "Server is booting up."),
			enumVal("STOPPING", "Server is shutting down."),
			enumVal("ERROR", "Server is in an error state."),
			enumVal("MAINTENANCE", "Server is undergoing maintenance."),
		},
		"fields":        nil,
		"interfaces":    nil,
		"inputFields":   nil,
		"possibleTypes": nil,
	}
}

func (g *GraphQLHandler) buildSortDirectionEnum() map[string]interface{} {
	return map[string]interface{}{
		"kind":        "ENUM",
		"name":        "SortDirection",
		"description": "Sort direction for ordered results.",
		"enumValues": []map[string]interface{}{
			enumVal("ASC", "Ascending order."),
			enumVal("DESC", "Descending order."),
		},
		"fields":        nil,
		"interfaces":    nil,
		"inputFields":   nil,
		"possibleTypes": nil,
	}
}

// --- Query execution ---

// handleQuery handles non-introspection queries.
func (g *GraphQLHandler) handleQuery(w http.ResponseWriter, query string, variables map[string]interface{}) int {
	lowerQuery := strings.ToLower(query)
	data := make(map[string]interface{})
	matched := false

	rng := pathSeed(query)

	if strings.Contains(lowerQuery, "users") {
		matched = true
		data["users"] = g.generateUserData(rng, 5)
	}
	if strings.Contains(lowerQuery, "user") && !strings.Contains(lowerQuery, "users") {
		matched = true
		data["user"] = g.generateSingleUser(rng, variables)
	}
	if strings.Contains(lowerQuery, "products") {
		matched = true
		data["products"] = g.generateProductData(rng, 5)
	}
	if strings.Contains(lowerQuery, "product") && !strings.Contains(lowerQuery, "products") {
		matched = true
		data["product"] = g.generateSingleProduct(rng, variables)
	}
	if strings.Contains(lowerQuery, "posts") {
		matched = true
		data["posts"] = g.generatePostData(rng, 5)
	}
	if strings.Contains(lowerQuery, "post") && !strings.Contains(lowerQuery, "posts") {
		matched = true
		data["post"] = g.generateSinglePost(rng, variables)
	}
	if strings.Contains(lowerQuery, "orders") {
		matched = true
		data["orders"] = g.generateOrderData(rng, 3)
	}
	if strings.Contains(lowerQuery, "order") && !strings.Contains(lowerQuery, "orders") {
		matched = true
		data["order"] = g.generateSingleOrder(rng, variables)
	}
	if strings.Contains(lowerQuery, "servers") {
		matched = true
		data["servers"] = g.generateServerData(rng, 5)
	}
	if strings.Contains(lowerQuery, "server") && !strings.Contains(lowerQuery, "servers") {
		matched = true
		data["server"] = g.generateSingleServer(rng, variables)
	}
	if strings.Contains(lowerQuery, "categories") {
		matched = true
		data["categories"] = g.generateCategoryData(rng)
	}
	if strings.Contains(lowerQuery, "tags") {
		matched = true
		data["tags"] = g.generateTagData(rng)
	}

	// Check for syntax-like errors in the query
	if !matched && !strings.Contains(lowerQuery, "{") {
		return g.writeErrors(w, http.StatusBadRequest, graphqlError{
			Message: fmt.Sprintf("Syntax Error: Expected {, found <EOF>"),
			Locations: []map[string]interface{}{
				{"line": 1, "column": len(query) + 1},
			},
		})
	}

	if !matched {
		// Return empty data for unknown queries
		data["result"] = nil
	}

	resp := map[string]interface{}{
		"data": data,
	}
	writeJSON(w, http.StatusOK, resp)
	return http.StatusOK
}

// handleMutation handles mutation queries.
func (g *GraphQLHandler) handleMutation(w http.ResponseWriter, query string, variables map[string]interface{}) int {
	lowerQuery := strings.ToLower(query)
	data := make(map[string]interface{})

	rng := pathSeed(query)

	if strings.Contains(lowerQuery, "createuser") {
		user := g.generateSingleUser(rng, variables)
		data["createUser"] = map[string]interface{}{
			"user":             user,
			"clientMutationId": deterministicUUID(rng),
		}
	} else if strings.Contains(lowerQuery, "updateuser") {
		user := g.generateSingleUser(rng, variables)
		user["updatedAt"] = deterministicTimestamp(rng)
		data["updateUser"] = map[string]interface{}{
			"user":             user,
			"clientMutationId": deterministicUUID(rng),
		}
	} else if strings.Contains(lowerQuery, "deleteuser") {
		data["deleteUser"] = map[string]interface{}{
			"deletedId":        deterministicUUID(rng),
			"success":          true,
			"clientMutationId": deterministicUUID(rng),
		}
	} else if strings.Contains(lowerQuery, "createpost") {
		post := g.generateSinglePost(rng, variables)
		data["createPost"] = map[string]interface{}{
			"post":             post,
			"clientMutationId": deterministicUUID(rng),
		}
	} else if strings.Contains(lowerQuery, "createorder") {
		order := g.generateSingleOrder(rng, variables)
		data["createOrder"] = map[string]interface{}{
			"order":            order,
			"clientMutationId": deterministicUUID(rng),
		}
	} else {
		return g.writeErrors(w, http.StatusBadRequest, graphqlError{
			Message: "Unknown mutation. Available mutations: createUser, updateUser, deleteUser, createPost, createOrder",
			Locations: []map[string]interface{}{
				{"line": 1, "column": 1},
			},
			Path: []interface{}{"mutation"},
		})
	}

	resp := map[string]interface{}{
		"data": data,
	}
	writeJSON(w, http.StatusOK, resp)
	return http.StatusOK
}

// --- Data generators ---

func (g *GraphQLHandler) generateUserData(rng *rand.Rand, count int) map[string]interface{} {
	var edges []interface{}
	for i := 0; i < count; i++ {
		uRng := pathSeed(fmt.Sprintf("gql-user-%d-%d", rng.Int63(), i))
		user := g.generateSingleUser(uRng, nil)
		edges = append(edges, map[string]interface{}{
			"node":   user,
			"cursor": fmt.Sprintf("cursor_%s", deterministicUUID(uRng)),
		})
	}
	return map[string]interface{}{
		"edges": edges,
		"pageInfo": map[string]interface{}{
			"hasNextPage":     true,
			"hasPreviousPage": false,
			"startCursor":     "cursor_start",
			"endCursor":       "cursor_end",
			"totalCount":      totalUsers,
		},
		"totalCount": totalUsers,
	}
}

func (g *GraphQLHandler) generateSingleUser(rng *rand.Rand, variables map[string]interface{}) map[string]interface{} {
	first := firstNames[rng.Intn(len(firstNames))]
	last := lastNames[rng.Intn(len(lastNames))]
	fullName := first + " " + last
	roles := []string{"ADMIN", "EDITOR", "VIEWER", "USER"}
	statuses := []string{"ACTIVE", "SUSPENDED", "PENDING"}
	themes := []string{"light", "dark", "auto"}
	languages := []string{"en", "es", "fr", "de", "ja"}
	timezones := []string{"America/New_York", "America/Los_Angeles", "Europe/London", "Asia/Tokyo"}
	cities := []string{"New York", "Los Angeles", "Chicago", "Seattle", "Austin"}
	states := []string{"NY", "CA", "IL", "WA", "TX"}
	streets := []string{"Main St", "Oak Ave", "Elm Dr", "Park Blvd", "Cedar Ln"}

	cityIdx := rng.Intn(len(cities))

	return map[string]interface{}{
		"id":       deterministicUUID(rng),
		"username": strings.ToLower(first) + "." + strings.ToLower(last),
		"email":    deterministicEmail(rng, fullName),
		"fullName": fullName,
		"role":     roles[rng.Intn(len(roles))],
		"status":   statuses[rng.Intn(len(statuses))],
		"avatarUrl": fmt.Sprintf("https://avatars.example.com/u/%s.png",
			strings.ToLower(first)),
		"phone": fmt.Sprintf("+1-%03d-%03d-%04d",
			200+rng.Intn(800), rng.Intn(1000), rng.Intn(10000)),
		"address": map[string]interface{}{
			"street":  fmt.Sprintf("%d %s", 100+rng.Intn(9900), streets[rng.Intn(len(streets))]),
			"city":    cities[cityIdx],
			"state":   states[cityIdx],
			"zip":     fmt.Sprintf("%05d", 10000+rng.Intn(90000)),
			"country": "US",
		},
		"preferences": map[string]interface{}{
			"theme":         themes[rng.Intn(len(themes))],
			"language":      languages[rng.Intn(len(languages))],
			"timezone":      timezones[rng.Intn(len(timezones))],
			"notifications": rng.Intn(2) == 1,
			"emailDigest":   rng.Intn(2) == 1,
			"itemsPerPage":  10 + rng.Intn(4)*5,
		},
		"loginCount":       rng.Intn(500) + 1,
		"twoFactorEnabled": rng.Intn(3) != 0,
		"createdAt":        deterministicTimestamp(rng),
		"updatedAt":        deterministicTimestamp(rng),
		"lastLogin":        deterministicTimestamp(rng),
	}
}

func (g *GraphQLHandler) generateProductData(rng *rand.Rand, count int) []interface{} {
	var products []interface{}
	for i := 0; i < count; i++ {
		pRng := pathSeed(fmt.Sprintf("gql-product-%d-%d", rng.Int63(), i))
		products = append(products, g.generateSingleProduct(pRng, nil))
	}
	return products
}

func (g *GraphQLHandler) generateSingleProduct(rng *rand.Rand, variables map[string]interface{}) map[string]interface{} {
	adjectives := []string{"Premium", "Classic", "Ultra", "Pro", "Essential", "Deluxe", "Advanced", "Elite"}
	nouns := []string{"Widget", "Gadget", "Device", "Module", "Component", "System", "Kit", "Tool",
		"Sensor", "Controller", "Adapter", "Hub", "Shield", "Pack", "Station"}
	categories := []string{"Electronics", "Hardware", "Software", "Accessories", "Networking", "Storage"}

	name := adjectives[rng.Intn(len(adjectives))] + " " + nouns[rng.Intn(len(nouns))]
	slug := strings.ToLower(strings.ReplaceAll(name, " ", "-"))
	price := float64(rng.Intn(50000)+500) / 100.0
	inStock := rng.Intn(5) != 0 // 80% in stock
	stockQty := 0
	if inStock {
		stockQty = rng.Intn(500) + 1
	}

	return map[string]interface{}{
		"id":             deterministicUUID(rng),
		"name":           name,
		"slug":           slug,
		"description":    fmt.Sprintf("High-quality %s for professional and personal use. Built with precision engineering and premium materials.", strings.ToLower(name)),
		"price":          price,
		"compareAtPrice": price * (1.0 + float64(rng.Intn(40)+10)/100.0),
		"sku":            fmt.Sprintf("SKU-%s-%04d", strings.ToUpper(slug[:3]), rng.Intn(10000)),
		"inStock":        inStock,
		"stockQuantity":  stockQty,
		"category": map[string]interface{}{
			"id":   deterministicUUID(rng),
			"name": categories[rng.Intn(len(categories))],
			"slug": strings.ToLower(categories[rng.Intn(len(categories))]),
		},
		"imageUrl":      fmt.Sprintf("https://images.example.com/products/%s.jpg", slug),
		"thumbnailUrl":  fmt.Sprintf("https://images.example.com/products/%s-thumb.jpg", slug),
		"weight":        float64(rng.Intn(5000)+100) / 1000.0,
		"dimensions":    fmt.Sprintf("%dx%dx%d cm", 5+rng.Intn(50), 5+rng.Intn(50), 2+rng.Intn(30)),
		"rating":        float64(rng.Intn(20)+30) / 10.0,
		"reviewCount":   rng.Intn(500),
		"createdAt":     deterministicTimestamp(rng),
		"updatedAt":     deterministicTimestamp(rng),
	}
}

func (g *GraphQLHandler) generatePostData(rng *rand.Rand, count int) map[string]interface{} {
	var edges []interface{}
	for i := 0; i < count; i++ {
		pRng := pathSeed(fmt.Sprintf("gql-post-%d-%d", rng.Int63(), i))
		post := g.generateSinglePost(pRng, nil)
		edges = append(edges, map[string]interface{}{
			"node":   post,
			"cursor": fmt.Sprintf("cursor_%s", deterministicUUID(pRng)),
		})
	}
	return map[string]interface{}{
		"edges": edges,
		"pageInfo": map[string]interface{}{
			"hasNextPage":     true,
			"hasPreviousPage": false,
			"startCursor":     "cursor_start",
			"endCursor":       "cursor_end",
			"totalCount":      187,
		},
		"totalCount": 187,
	}
}

func (g *GraphQLHandler) generateSinglePost(rng *rand.Rand, variables map[string]interface{}) map[string]interface{} {
	titles := []string{
		"Getting Started with Microservices Architecture",
		"Understanding REST API Design Patterns",
		"Best Practices for Database Indexing",
		"A Deep Dive into Container Orchestration",
		"Building Scalable Web Applications",
		"Introduction to Event-Driven Architecture",
		"How to Write Clean and Maintainable Code",
		"Monitoring and Observability in Production",
		"Security Best Practices for Modern APIs",
		"Automating Your CI/CD Pipeline",
		"The Future of Serverless Computing",
		"Data Modeling for NoSQL Databases",
		"Performance Tuning Your Applications",
		"Working with WebSockets in Practice",
		"GraphQL vs REST: A Practical Comparison",
	}
	statuses := []string{"PUBLISHED", "DRAFT", "ARCHIVED"}
	tagNames := []string{"go", "python", "javascript", "devops", "cloud", "security", "database", "api"}

	title := titles[rng.Intn(len(titles))]
	slug := strings.ToLower(strings.ReplaceAll(title, " ", "-"))
	wordCount := 500 + rng.Intn(3000)

	var tags []interface{}
	tagCount := 1 + rng.Intn(4)
	for t := 0; t < tagCount; t++ {
		tRng := pathSeed(fmt.Sprintf("gql-tag-%d-%d", rng.Int63(), t))
		tagName := tagNames[rng.Intn(len(tagNames))]
		tags = append(tags, map[string]interface{}{
			"id":   deterministicUUID(tRng),
			"name": tagName,
			"slug": tagName,
		})
	}

	authorRng := pathSeed(fmt.Sprintf("gql-post-author-%d", rng.Int63()))
	first := firstNames[authorRng.Intn(len(firstNames))]
	last := lastNames[authorRng.Intn(len(lastNames))]

	return map[string]interface{}{
		"id":       deterministicUUID(rng),
		"title":    title,
		"slug":     slug,
		"body":     fmt.Sprintf("<p>This is the full content of \"%s\". It covers important topics in software development and engineering practices.</p>", title),
		"excerpt":  fmt.Sprintf("A comprehensive guide to %s.", strings.ToLower(title)),
		"status":   statuses[rng.Intn(len(statuses))],
		"author": map[string]interface{}{
			"id":       deterministicUUID(authorRng),
			"username": strings.ToLower(first) + "." + strings.ToLower(last),
			"fullName": first + " " + last,
		},
		"tags":        tags,
		"wordCount":   wordCount,
		"readingTime": (wordCount + 249) / 250,
		"viewCount":   rng.Intn(10000),
		"likeCount":   rng.Intn(500),
		"publishedAt": deterministicTimestamp(rng),
		"createdAt":   deterministicTimestamp(rng),
		"updatedAt":   deterministicTimestamp(rng),
	}
}

func (g *GraphQLHandler) generateOrderData(rng *rand.Rand, count int) []interface{} {
	var orders []interface{}
	for i := 0; i < count; i++ {
		oRng := pathSeed(fmt.Sprintf("gql-order-%d-%d", rng.Int63(), i))
		orders = append(orders, g.generateSingleOrder(oRng, nil))
	}
	return orders
}

func (g *GraphQLHandler) generateSingleOrder(rng *rand.Rand, variables map[string]interface{}) map[string]interface{} {
	statuses := []string{"PENDING", "CONFIRMED", "PROCESSING", "SHIPPED", "DELIVERED"}
	cities := []string{"New York", "Los Angeles", "Chicago", "Houston", "Phoenix"}
	states := []string{"NY", "CA", "IL", "TX", "AZ"}

	itemCount := 1 + rng.Intn(4)
	var items []interface{}
	subtotal := 0.0
	for i := 0; i < itemCount; i++ {
		iRng := pathSeed(fmt.Sprintf("gql-order-item-%d-%d", rng.Int63(), i))
		product := g.generateSingleProduct(iRng, nil)
		qty := 1 + rng.Intn(3)
		unitPrice := product["price"].(float64)
		lineTotal := unitPrice * float64(qty)
		subtotal += lineTotal
		items = append(items, map[string]interface{}{
			"id":        deterministicUUID(iRng),
			"product":   product,
			"quantity":  qty,
			"unitPrice": unitPrice,
			"total":     lineTotal,
		})
	}

	tax := subtotal * 0.08
	shipping := 5.99 + float64(rng.Intn(1500))/100.0
	total := subtotal + tax + shipping

	cityIdx := rng.Intn(len(cities))

	return map[string]interface{}{
		"id":          deterministicUUID(rng),
		"orderNumber": fmt.Sprintf("ORD-%06d", 100000+rng.Intn(900000)),
		"status":      statuses[rng.Intn(len(statuses))],
		"customer": map[string]interface{}{
			"id":       deterministicUUID(rng),
			"username": strings.ToLower(firstNames[rng.Intn(len(firstNames))]) + "." + strings.ToLower(lastNames[rng.Intn(len(lastNames))]),
		},
		"items":        items,
		"subtotal":     float64(int(subtotal*100)) / 100,
		"tax":          float64(int(tax*100)) / 100,
		"shippingCost": shipping,
		"total":        float64(int(total*100)) / 100,
		"currency":     "USD",
		"shippingAddress": map[string]interface{}{
			"street":  fmt.Sprintf("%d %s", 100+rng.Intn(9900), "Main St"),
			"city":    cities[cityIdx],
			"state":   states[cityIdx],
			"zip":     fmt.Sprintf("%05d", 10000+rng.Intn(90000)),
			"country": "US",
		},
		"notes":     nil,
		"createdAt": deterministicTimestamp(rng),
		"updatedAt": deterministicTimestamp(rng),
		"shippedAt": nil,
	}
}

func (g *GraphQLHandler) generateServerData(rng *rand.Rand, count int) []interface{} {
	var servers []interface{}
	for i := 0; i < count; i++ {
		sRng := pathSeed(fmt.Sprintf("gql-server-%d-%d", rng.Int63(), i))
		servers = append(servers, g.generateSingleServer(sRng, nil))
	}
	return servers
}

func (g *GraphQLHandler) generateSingleServer(rng *rand.Rand, variables map[string]interface{}) map[string]interface{} {
	statuses := []string{"RUNNING", "RUNNING", "RUNNING", "STOPPED", "MAINTENANCE", "ERROR"}
	regions := []string{"us-east-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1", "ap-northeast-1"}
	providers := []string{"aws", "gcp", "azure", "digitalocean"}
	instanceTypes := []string{"t3.micro", "t3.small", "t3.medium", "t3.large", "m5.large", "m5.xlarge", "c5.large", "r5.large"}
	osList := []string{"Ubuntu 22.04 LTS", "Ubuntu 24.04 LTS", "Amazon Linux 2023", "Debian 12", "CentOS Stream 9"}
	prefixes := []string{"web", "api", "db", "cache", "worker", "proxy", "queue", "monitor"}

	prefix := prefixes[rng.Intn(len(prefixes))]
	hostname := fmt.Sprintf("%s-%03d.infra.example.com", prefix, rng.Intn(100))
	region := regions[rng.Intn(len(regions))]

	cpuCores := []int{1, 2, 4, 8, 16, 32}
	memOptions := []float64{0.5, 1, 2, 4, 8, 16, 32, 64}
	diskOptions := []float64{20, 50, 100, 200, 500, 1000}

	status := statuses[rng.Intn(len(statuses))]
	cpuUsage := 0.0
	memUsage := 0.0
	if status == "RUNNING" {
		cpuUsage = float64(rng.Intn(9000)+500) / 100.0
		memUsage = float64(rng.Intn(8000)+1000) / 100.0
	}

	return map[string]interface{}{
		"id":           deterministicUUID(rng),
		"hostname":     hostname,
		"ipAddress":    fmt.Sprintf("10.%d.%d.%d", rng.Intn(256), rng.Intn(256), 1+rng.Intn(254)),
		"status":       status,
		"region":       region,
		"provider":     providers[rng.Intn(len(providers))],
		"instanceType": instanceTypes[rng.Intn(len(instanceTypes))],
		"os":           osList[rng.Intn(len(osList))],
		"cpuCores":     cpuCores[rng.Intn(len(cpuCores))],
		"memoryGb":     memOptions[rng.Intn(len(memOptions))],
		"diskGb":       diskOptions[rng.Intn(len(diskOptions))],
		"metrics": map[string]interface{}{
			"cpuUsage":          cpuUsage,
			"memoryUsage":       memUsage,
			"diskUsage":         float64(rng.Intn(8000)+500) / 100.0,
			"networkIn":         float64(rng.Intn(10000)) / 100.0,
			"networkOut":        float64(rng.Intn(10000)) / 100.0,
			"requestsPerSecond": float64(rng.Intn(50000)) / 100.0,
			"avgResponseTime":   float64(rng.Intn(50000)+100) / 100.0,
			"uptime":            rng.Intn(8640000),
		},
		"tags":            []string{prefix, region, status},
		"createdAt":       deterministicTimestamp(rng),
		"updatedAt":       deterministicTimestamp(rng),
		"lastHealthCheck": deterministicTimestamp(rng),
	}
}

func (g *GraphQLHandler) generateCategoryData(rng *rand.Rand) []interface{} {
	categories := []struct {
		name string
		desc string
	}{
		{"Electronics", "Electronic devices and components"},
		{"Hardware", "Physical computing hardware"},
		{"Software", "Software licenses and subscriptions"},
		{"Accessories", "Peripherals and accessories"},
		{"Networking", "Network equipment and cables"},
		{"Storage", "Data storage solutions"},
		{"Audio", "Audio equipment and accessories"},
		{"Displays", "Monitors and display panels"},
	}

	var result []interface{}
	for _, cat := range categories {
		cRng := pathSeed(fmt.Sprintf("gql-category-%s", cat.name))
		result = append(result, map[string]interface{}{
			"id":           deterministicUUID(cRng),
			"name":         cat.name,
			"slug":         strings.ToLower(cat.name),
			"description":  cat.desc,
			"productCount": 10 + rng.Intn(100),
			"imageUrl":     fmt.Sprintf("https://images.example.com/categories/%s.jpg", strings.ToLower(cat.name)),
		})
	}
	return result
}

func (g *GraphQLHandler) generateTagData(rng *rand.Rand) []interface{} {
	tagNames := []string{
		"go", "python", "javascript", "typescript", "rust",
		"devops", "cloud", "security", "database", "api",
		"docker", "kubernetes", "terraform", "aws", "linux",
		"microservices", "graphql", "rest", "grpc", "testing",
	}

	var result []interface{}
	for _, name := range tagNames {
		tRng := pathSeed(fmt.Sprintf("gql-tag-%s", name))
		result = append(result, map[string]interface{}{
			"id":        deterministicUUID(tRng),
			"name":      name,
			"slug":      name,
			"postCount": rng.Intn(50) + 1,
		})
	}
	return result
}

// --- Type reference helpers ---

// scalarRef returns a type reference to a scalar or named type.
func scalarRef(name string) map[string]interface{} {
	return map[string]interface{}{
		"kind":   "SCALAR",
		"name":   name,
		"ofType": nil,
	}
}

// namedRef returns a type reference to a named object/enum/input type.
func namedRef(name string) map[string]interface{} {
	return map[string]interface{}{
		"kind":   "OBJECT",
		"name":   name,
		"ofType": nil,
	}
}

// typeRef wraps a type in a wrapper kind (NON_NULL or LIST).
func typeRef(kind string, inner map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"kind":   kind,
		"name":   nil,
		"ofType": inner,
	}
}

// listRef wraps a type in a LIST type reference.
func listRef(inner map[string]interface{}) map[string]interface{} {
	return typeRef("LIST", inner)
}

// scalarType returns a scalar type definition.
func scalarType(name, description string) map[string]interface{} {
	return map[string]interface{}{
		"kind":          "SCALAR",
		"name":          name,
		"description":   description,
		"fields":        nil,
		"interfaces":    nil,
		"enumValues":    nil,
		"inputFields":   nil,
		"possibleTypes": nil,
	}
}

// fieldDef creates a simple field definition (no args).
func fieldDef(name string, typeInfo map[string]interface{}, description string) map[string]interface{} {
	return map[string]interface{}{
		"name":              name,
		"description":       description,
		"type":              typeInfo,
		"isDeprecated":      false,
		"deprecationReason": nil,
		"args":              []map[string]interface{}{},
	}
}

// argDef creates an argument definition.
func argDef(name string, typeInfo map[string]interface{}, description string, defaultValue interface{}) map[string]interface{} {
	return map[string]interface{}{
		"name":         name,
		"description":  description,
		"type":         typeInfo,
		"defaultValue": defaultValue,
	}
}

// inputFieldDef creates an input field definition.
func inputFieldDef(name string, typeInfo map[string]interface{}, description string) map[string]interface{} {
	return map[string]interface{}{
		"name":         name,
		"description":  description,
		"type":         typeInfo,
		"defaultValue": nil,
	}
}

// enumVal creates an enum value definition.
func enumVal(name, description string) map[string]interface{} {
	return map[string]interface{}{
		"name":              name,
		"description":       description,
		"isDeprecated":      false,
		"deprecationReason": nil,
	}
}
