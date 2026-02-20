package api

import (
	"encoding/json"
	"net/http"
)

// SwaggerHandler serves the OpenAPI specification and Swagger UI.
type SwaggerHandler struct{}

// NewSwaggerHandler creates a new SwaggerHandler.
func NewSwaggerHandler() *SwaggerHandler {
	return &SwaggerHandler{}
}

// ServeSpec writes the OpenAPI 3.0.3 JSON specification.
func (s *SwaggerHandler) ServeSpec(w http.ResponseWriter, r *http.Request) int {
	spec := buildOpenAPISpec()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	addCommonHeaders(w)
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(spec)
	return http.StatusOK
}

// ServeUI writes an HTML page that renders Swagger UI.
func (s *SwaggerHandler) ServeUI(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	addCommonHeaders(w)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(swaggerUIHTML))
	return http.StatusOK
}

// swaggerUIHTML is the HTML page that loads Swagger UI from unpkg CDN.
const swaggerUIHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Glitch Platform API Documentation</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
  <style>
    html { box-sizing: border-box; overflow-y: scroll; }
    *, *:before, *:after { box-sizing: inherit; }
    body { margin: 0; background: #fafafa; }
    .topbar { display: none; }
    .swagger-ui .info .title { font-size: 2rem; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.onload = function() {
      SwaggerUIBundle({
        url: "/swagger.json",
        dom_id: "#swagger-ui",
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIBundle.SwaggerUIStandalonePreset
        ],
        layout: "BaseLayout"
      });
    };
  </script>
</body>
</html>`

// buildOpenAPISpec constructs the full OpenAPI 3.0.3 specification as a nested map.
func buildOpenAPISpec() map[string]interface{} {
	return map[string]interface{}{
		"openapi": "3.0.3",
		"info": map[string]interface{}{
			"title":       "Glitch Platform API",
			"version":     "1.0.0",
			"description": "A comprehensive REST API powering the Glitch Platform. Provides user management, e-commerce, infrastructure monitoring, and content management capabilities. Note: this server is intentionally unreliable and may return unexpected errors, malformed responses, or adaptive behavior based on client fingerprinting.",
			"contact": map[string]interface{}{
				"name": "Glitch Platform Team",
			},
			"license": map[string]interface{}{
				"name": "MIT",
			},
		},
		"servers": []map[string]interface{}{
			{
				"url":         "http://localhost:8765",
				"description": "Local development server",
			},
		},
		"tags": []map[string]interface{}{
			{"name": "Users", "description": "User management and profiles"},
			{"name": "Roles", "description": "Role-based access control"},
			{"name": "Products", "description": "Product catalog management"},
			{"name": "Orders", "description": "Order processing and tracking"},
			{"name": "Cart", "description": "Shopping cart operations"},
			{"name": "Categories", "description": "Product category hierarchy"},
			{"name": "Servers", "description": "Infrastructure server management"},
			{"name": "Deployments", "description": "Deployment pipeline management"},
			{"name": "Containers", "description": "Container orchestration"},
			{"name": "Clusters", "description": "Cluster management"},
			{"name": "Posts", "description": "Blog post management"},
			{"name": "Pages", "description": "CMS page management"},
			{"name": "Media", "description": "Media asset management"},
			{"name": "Tags", "description": "Content tagging"},
			{"name": "Auth", "description": "Authentication and registration"},
			{"name": "Search", "description": "Full-text search"},
			{"name": "Comments", "description": "User comments"},
		},
		"paths":      buildPaths(),
		"components": buildComponents(),
	}
}

func buildPaths() map[string]interface{} {
	paths := map[string]interface{}{}

	// ---- User Management ----
	paths["/api/v1/users"] = map[string]interface{}{
		"get": map[string]interface{}{
			"tags":        []string{"Users"},
			"summary":     "List all users",
			"description": "Returns a paginated list of users. Supports filtering by role, status, and search query.",
			"operationId": "listUsers",
			"parameters":  paginationParams("username", "email", "created_at"),
			"responses":   listResponse("User"),
			"security":    bearerSecurity(),
		},
		"post": map[string]interface{}{
			"tags":        []string{"Users"},
			"summary":     "Create a new user",
			"operationId": "createUser",
			"requestBody": requestBody("UserCreate", true),
			"responses":   createResponse("User"),
			"security":    bearerSecurity(),
		},
	}
	paths["/api/v1/users/{id}"] = map[string]interface{}{
		"get": map[string]interface{}{
			"tags":        []string{"Users"},
			"summary":     "Get user by ID",
			"operationId": "getUser",
			"parameters":  idParam("User"),
			"responses":   singleResponse("User"),
			"security":    bearerSecurity(),
		},
		"put": map[string]interface{}{
			"tags":        []string{"Users"},
			"summary":     "Update a user",
			"operationId": "updateUser",
			"parameters":  idParam("User"),
			"requestBody": requestBody("UserCreate", true),
			"responses":   singleResponse("User"),
			"security":    bearerSecurity(),
		},
		"delete": map[string]interface{}{
			"tags":        []string{"Users"},
			"summary":     "Delete a user",
			"operationId": "deleteUser",
			"parameters":  idParam("User"),
			"responses":   deleteResponse(),
			"security":    bearerSecurity(),
		},
	}
	paths["/api/v1/users/{id}/posts"] = map[string]interface{}{
		"get": map[string]interface{}{
			"tags":        []string{"Users"},
			"summary":     "List posts by user",
			"description": "Returns all posts authored by the specified user.",
			"operationId": "listUserPosts",
			"parameters":  idParam("User"),
			"responses":   listResponse("Post"),
			"security":    bearerSecurity(),
		},
	}
	paths["/api/v1/users/{id}/activity"] = map[string]interface{}{
		"get": map[string]interface{}{
			"tags":        []string{"Users"},
			"summary":     "Get user activity log",
			"description": "Returns a timeline of recent actions performed by the user.",
			"operationId": "getUserActivity",
			"parameters":  idParam("User"),
			"responses":   listResponse("ActivityEvent"),
			"security":    bearerSecurity(),
		},
	}
	paths["/api/v1/roles"] = map[string]interface{}{
		"get": map[string]interface{}{
			"tags":        []string{"Roles"},
			"summary":     "List available roles",
			"operationId": "listRoles",
			"responses":   listResponse("Role"),
			"security":    bearerSecurity(),
		},
	}

	// ---- E-Commerce ----
	paths["/api/v1/products"] = map[string]interface{}{
		"get": map[string]interface{}{
			"tags":        []string{"Products"},
			"summary":     "List products",
			"description": "Returns a paginated catalog of products. Supports filtering by category, price range, and availability.",
			"operationId": "listProducts",
			"parameters":  paginationParams("name", "price", "created_at"),
			"responses":   listResponse("Product"),
		},
		"post": map[string]interface{}{
			"tags":        []string{"Products"},
			"summary":     "Create a product",
			"operationId": "createProduct",
			"requestBody": requestBody("ProductCreate", true),
			"responses":   createResponse("Product"),
			"security":    bearerSecurity(),
		},
	}
	paths["/api/v1/products/{id}"] = map[string]interface{}{
		"get": map[string]interface{}{
			"tags":        []string{"Products"},
			"summary":     "Get product by ID",
			"operationId": "getProduct",
			"parameters":  idParam("Product"),
			"responses":   singleResponse("Product"),
		},
		"put": map[string]interface{}{
			"tags":        []string{"Products"},
			"summary":     "Update a product",
			"operationId": "updateProduct",
			"parameters":  idParam("Product"),
			"requestBody": requestBody("ProductCreate", true),
			"responses":   singleResponse("Product"),
			"security":    bearerSecurity(),
		},
		"delete": map[string]interface{}{
			"tags":        []string{"Products"},
			"summary":     "Delete a product",
			"operationId": "deleteProduct",
			"parameters":  idParam("Product"),
			"responses":   deleteResponse(),
			"security":    bearerSecurity(),
		},
	}
	paths["/api/v1/products/{id}/reviews"] = map[string]interface{}{
		"get": map[string]interface{}{
			"tags":        []string{"Products"},
			"summary":     "List product reviews",
			"operationId": "listProductReviews",
			"parameters":  idParam("Product"),
			"responses":   listResponse("Review"),
		},
		"post": map[string]interface{}{
			"tags":        []string{"Products"},
			"summary":     "Add a review to a product",
			"operationId": "createProductReview",
			"parameters":  idParam("Product"),
			"requestBody": requestBody("ReviewCreate", true),
			"responses":   createResponse("Review"),
			"security":    bearerSecurity(),
		},
	}
	paths["/api/v1/categories"] = map[string]interface{}{
		"get": map[string]interface{}{
			"tags":        []string{"Categories"},
			"summary":     "List product categories",
			"operationId": "listCategories",
			"responses":   listResponse("Category"),
		},
	}
	paths["/api/v1/orders"] = map[string]interface{}{
		"get": map[string]interface{}{
			"tags":        []string{"Orders"},
			"summary":     "List orders",
			"description": "Returns a paginated list of orders for the authenticated user.",
			"operationId": "listOrders",
			"parameters":  paginationParams("created_at", "total", "status"),
			"responses":   listResponse("Order"),
			"security":    bearerSecurity(),
		},
		"post": map[string]interface{}{
			"tags":        []string{"Orders"},
			"summary":     "Place a new order",
			"operationId": "createOrder",
			"requestBody": requestBody("OrderCreate", true),
			"responses":   createResponse("Order"),
			"security":    bearerSecurity(),
		},
	}
	paths["/api/v1/orders/{id}"] = map[string]interface{}{
		"get": map[string]interface{}{
			"tags":        []string{"Orders"},
			"summary":     "Get order by ID",
			"operationId": "getOrder",
			"parameters":  idParam("Order"),
			"responses":   singleResponse("Order"),
			"security":    bearerSecurity(),
		},
	}
	paths["/api/v1/cart"] = map[string]interface{}{
		"get": map[string]interface{}{
			"tags":        []string{"Cart"},
			"summary":     "Get current shopping cart",
			"operationId": "getCart",
			"responses":   singleResponse("Cart"),
			"security":    bearerSecurity(),
		},
		"delete": map[string]interface{}{
			"tags":        []string{"Cart"},
			"summary":     "Clear shopping cart",
			"operationId": "clearCart",
			"responses":   deleteResponse(),
			"security":    bearerSecurity(),
		},
	}
	paths["/api/v1/cart/items"] = map[string]interface{}{
		"post": map[string]interface{}{
			"tags":        []string{"Cart"},
			"summary":     "Add item to cart",
			"operationId": "addCartItem",
			"requestBody": requestBody("CartItemCreate", true),
			"responses":   createResponse("CartItem"),
			"security":    bearerSecurity(),
		},
	}
	paths["/api/v1/cart/items/{id}"] = map[string]interface{}{
		"put": map[string]interface{}{
			"tags":        []string{"Cart"},
			"summary":     "Update cart item quantity",
			"operationId": "updateCartItem",
			"parameters":  idParam("CartItem"),
			"requestBody": requestBody("CartItemUpdate", true),
			"responses":   singleResponse("CartItem"),
			"security":    bearerSecurity(),
		},
		"delete": map[string]interface{}{
			"tags":        []string{"Cart"},
			"summary":     "Remove item from cart",
			"operationId": "removeCartItem",
			"parameters":  idParam("CartItem"),
			"responses":   deleteResponse(),
			"security":    bearerSecurity(),
		},
	}

	// ---- Infrastructure ----
	paths["/api/v1/servers"] = map[string]interface{}{
		"get": map[string]interface{}{
			"tags":        []string{"Servers"},
			"summary":     "List servers",
			"description": "Returns all managed servers with their current status and resource utilization.",
			"operationId": "listServers",
			"parameters":  paginationParams("hostname", "status", "created_at"),
			"responses":   listResponse("Server"),
			"security":    apiKeySecurity(),
		},
		"post": map[string]interface{}{
			"tags":        []string{"Servers"},
			"summary":     "Register a new server",
			"operationId": "createServer",
			"requestBody": requestBody("ServerCreate", true),
			"responses":   createResponse("Server"),
			"security":    apiKeySecurity(),
		},
	}
	paths["/api/v1/servers/{id}"] = map[string]interface{}{
		"get": map[string]interface{}{
			"tags":        []string{"Servers"},
			"summary":     "Get server details",
			"operationId": "getServer",
			"parameters":  idParam("Server"),
			"responses":   singleResponse("Server"),
			"security":    apiKeySecurity(),
		},
		"delete": map[string]interface{}{
			"tags":        []string{"Servers"},
			"summary":     "Decommission a server",
			"operationId": "deleteServer",
			"parameters":  idParam("Server"),
			"responses":   deleteResponse(),
			"security":    apiKeySecurity(),
		},
	}
	paths["/api/v1/servers/{id}/metrics"] = map[string]interface{}{
		"get": map[string]interface{}{
			"tags":        []string{"Servers"},
			"summary":     "Get server metrics",
			"description": "Returns CPU, memory, disk, and network metrics for a server over the requested time window.",
			"operationId": "getServerMetrics",
			"parameters": append(idParam("Server"), map[string]interface{}{
				"name":        "window",
				"in":          "query",
				"description": "Time window for metrics (e.g. 1h, 24h, 7d)",
				"schema":      map[string]interface{}{"type": "string", "default": "1h"},
			}),
			"responses": singleResponse("ServerMetrics"),
			"security":  apiKeySecurity(),
		},
	}
	paths["/api/v1/deployments"] = map[string]interface{}{
		"get": map[string]interface{}{
			"tags":        []string{"Deployments"},
			"summary":     "List deployments",
			"operationId": "listDeployments",
			"parameters":  paginationParams("created_at", "status", "service"),
			"responses":   listResponse("Deployment"),
			"security":    apiKeySecurity(),
		},
		"post": map[string]interface{}{
			"tags":        []string{"Deployments"},
			"summary":     "Trigger a new deployment",
			"operationId": "createDeployment",
			"requestBody": requestBody("DeploymentCreate", true),
			"responses":   createResponse("Deployment"),
			"security":    apiKeySecurity(),
		},
	}
	paths["/api/v1/deployments/{id}"] = map[string]interface{}{
		"get": map[string]interface{}{
			"tags":        []string{"Deployments"},
			"summary":     "Get deployment details",
			"operationId": "getDeployment",
			"parameters":  idParam("Deployment"),
			"responses":   singleResponse("Deployment"),
			"security":    apiKeySecurity(),
		},
	}
	paths["/api/v1/containers"] = map[string]interface{}{
		"get": map[string]interface{}{
			"tags":        []string{"Containers"},
			"summary":     "List running containers",
			"operationId": "listContainers",
			"responses":   listResponse("Container"),
			"security":    apiKeySecurity(),
		},
	}
	paths["/api/v1/clusters"] = map[string]interface{}{
		"get": map[string]interface{}{
			"tags":        []string{"Clusters"},
			"summary":     "List clusters",
			"operationId": "listClusters",
			"responses":   listResponse("Cluster"),
			"security":    apiKeySecurity(),
		},
	}

	// ---- CMS ----
	paths["/api/v1/posts"] = map[string]interface{}{
		"get": map[string]interface{}{
			"tags":        []string{"Posts"},
			"summary":     "List blog posts",
			"description": "Returns a paginated list of published blog posts. Supports filtering by tag, author, and status.",
			"operationId": "listPosts",
			"parameters":  paginationParams("title", "published_at", "author"),
			"responses":   listResponse("Post"),
		},
		"post": map[string]interface{}{
			"tags":        []string{"Posts"},
			"summary":     "Create a blog post",
			"operationId": "createPost",
			"requestBody": requestBody("PostCreate", true),
			"responses":   createResponse("Post"),
			"security":    bearerSecurity(),
		},
	}
	paths["/api/v1/posts/{id}"] = map[string]interface{}{
		"get": map[string]interface{}{
			"tags":        []string{"Posts"},
			"summary":     "Get post by ID",
			"operationId": "getPost",
			"parameters":  idParam("Post"),
			"responses":   singleResponse("Post"),
		},
		"put": map[string]interface{}{
			"tags":        []string{"Posts"},
			"summary":     "Update a post",
			"operationId": "updatePost",
			"parameters":  idParam("Post"),
			"requestBody": requestBody("PostCreate", true),
			"responses":   singleResponse("Post"),
			"security":    bearerSecurity(),
		},
		"delete": map[string]interface{}{
			"tags":        []string{"Posts"},
			"summary":     "Delete a post",
			"operationId": "deletePost",
			"parameters":  idParam("Post"),
			"responses":   deleteResponse(),
			"security":    bearerSecurity(),
		},
	}
	paths["/api/v1/posts/{id}/comments"] = map[string]interface{}{
		"get": map[string]interface{}{
			"tags":        []string{"Posts"},
			"summary":     "List comments on a post",
			"operationId": "listPostComments",
			"parameters":  idParam("Post"),
			"responses":   listResponse("Comment"),
		},
		"post": map[string]interface{}{
			"tags":        []string{"Posts"},
			"summary":     "Add a comment to a post",
			"operationId": "createPostComment",
			"parameters":  idParam("Post"),
			"requestBody": requestBody("CommentCreate", true),
			"responses":   createResponse("Comment"),
			"security":    bearerSecurity(),
		},
	}
	paths["/api/v1/pages"] = map[string]interface{}{
		"get": map[string]interface{}{
			"tags":        []string{"Pages"},
			"summary":     "List CMS pages",
			"operationId": "listPages",
			"responses":   listResponse("Page"),
			"security":    bearerSecurity(),
		},
		"post": map[string]interface{}{
			"tags":        []string{"Pages"},
			"summary":     "Create a CMS page",
			"operationId": "createPage",
			"requestBody": requestBody("PageCreate", true),
			"responses":   createResponse("Page"),
			"security":    bearerSecurity(),
		},
	}
	paths["/api/v1/pages/{id}"] = map[string]interface{}{
		"get": map[string]interface{}{
			"tags":        []string{"Pages"},
			"summary":     "Get page by ID",
			"operationId": "getPage",
			"parameters":  idParam("Page"),
			"responses":   singleResponse("Page"),
		},
		"put": map[string]interface{}{
			"tags":        []string{"Pages"},
			"summary":     "Update a CMS page",
			"operationId": "updatePage",
			"parameters":  idParam("Page"),
			"requestBody": requestBody("PageCreate", true),
			"responses":   singleResponse("Page"),
			"security":    bearerSecurity(),
		},
	}
	paths["/api/v1/media"] = map[string]interface{}{
		"get": map[string]interface{}{
			"tags":        []string{"Media"},
			"summary":     "List media assets",
			"operationId": "listMedia",
			"responses":   listResponse("MediaAsset"),
			"security":    bearerSecurity(),
		},
		"post": map[string]interface{}{
			"tags":        []string{"Media"},
			"summary":     "Upload a media asset",
			"operationId": "uploadMedia",
			"requestBody": map[string]interface{}{
				"required": true,
				"content": map[string]interface{}{
					"multipart/form-data": map[string]interface{}{
						"schema": map[string]interface{}{
							"type": "object",
							"properties": map[string]interface{}{
								"file": map[string]interface{}{
									"type":   "string",
									"format": "binary",
								},
								"alt_text": map[string]interface{}{
									"type": "string",
								},
							},
							"required": []string{"file"},
						},
					},
				},
			},
			"responses": createResponse("MediaAsset"),
			"security":  bearerSecurity(),
		},
	}
	paths["/api/v1/media/{id}"] = map[string]interface{}{
		"get": map[string]interface{}{
			"tags":        []string{"Media"},
			"summary":     "Get media asset by ID",
			"operationId": "getMediaAsset",
			"parameters":  idParam("MediaAsset"),
			"responses":   singleResponse("MediaAsset"),
			"security":    bearerSecurity(),
		},
		"delete": map[string]interface{}{
			"tags":        []string{"Media"},
			"summary":     "Delete a media asset",
			"operationId": "deleteMediaAsset",
			"parameters":  idParam("MediaAsset"),
			"responses":   deleteResponse(),
			"security":    bearerSecurity(),
		},
	}
	paths["/api/v1/tags"] = map[string]interface{}{
		"get": map[string]interface{}{
			"tags":        []string{"Tags"},
			"summary":     "List all tags",
			"operationId": "listTags",
			"responses":   listResponse("Tag"),
		},
	}

	// ---- Auth / Forms ----
	paths["/api/auth/login"] = map[string]interface{}{
		"post": map[string]interface{}{
			"tags":        []string{"Auth"},
			"summary":     "Authenticate a user",
			"description": "Validates credentials and returns a JWT access token and refresh token.",
			"operationId": "login",
			"requestBody": requestBody("LoginRequest", true),
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "Authentication successful",
					"content": map[string]interface{}{
						"application/json": map[string]interface{}{
							"schema": ref("AuthResponse"),
						},
					},
				},
				"401": map[string]interface{}{
					"description": "Invalid credentials",
					"content": map[string]interface{}{
						"application/json": map[string]interface{}{
							"schema": ref("Error"),
						},
					},
				},
			},
		},
	}
	paths["/api/auth/register"] = map[string]interface{}{
		"post": map[string]interface{}{
			"tags":        []string{"Auth"},
			"summary":     "Register a new account",
			"operationId": "register",
			"requestBody": requestBody("RegisterRequest", true),
			"responses": map[string]interface{}{
				"201": map[string]interface{}{
					"description": "Registration successful",
					"content": map[string]interface{}{
						"application/json": map[string]interface{}{
							"schema": ref("AuthResponse"),
						},
					},
				},
				"400": map[string]interface{}{
					"description": "Validation error",
					"content": map[string]interface{}{
						"application/json": map[string]interface{}{
							"schema": ref("Error"),
						},
					},
				},
			},
		},
	}
	paths["/api/search"] = map[string]interface{}{
		"get": map[string]interface{}{
			"tags":        []string{"Search"},
			"summary":     "Search across all content",
			"description": "Full-text search across users, products, posts, and pages.",
			"operationId": "search",
			"parameters": []map[string]interface{}{
				{
					"name":        "q",
					"in":          "query",
					"required":    true,
					"description": "Search query string",
					"schema":      map[string]interface{}{"type": "string"},
				},
				{
					"name":        "type",
					"in":          "query",
					"description": "Limit search to a specific resource type",
					"schema": map[string]interface{}{
						"type": "string",
						"enum": []string{"users", "products", "posts", "pages"},
					},
				},
				{
					"name":   "page",
					"in":     "query",
					"schema": map[string]interface{}{"type": "integer", "default": 1},
				},
				{
					"name":   "per_page",
					"in":     "query",
					"schema": map[string]interface{}{"type": "integer", "default": 20},
				},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "Search results",
					"content": map[string]interface{}{
						"application/json": map[string]interface{}{
							"schema": ref("SearchResults"),
						},
					},
				},
			},
		},
	}
	paths["/api/comments"] = map[string]interface{}{
		"get": map[string]interface{}{
			"tags":        []string{"Comments"},
			"summary":     "List recent comments",
			"description": "Returns the most recent comments across all posts.",
			"operationId": "listRecentComments",
			"parameters": []map[string]interface{}{
				{
					"name":   "page",
					"in":     "query",
					"schema": map[string]interface{}{"type": "integer", "default": 1},
				},
				{
					"name":   "per_page",
					"in":     "query",
					"schema": map[string]interface{}{"type": "integer", "default": 20},
				},
			},
			"responses": listResponse("Comment"),
		},
		"post": map[string]interface{}{
			"tags":        []string{"Comments"},
			"summary":     "Post a comment",
			"operationId": "createComment",
			"requestBody": requestBody("CommentCreate", true),
			"responses":   createResponse("Comment"),
			"security":    bearerSecurity(),
		},
	}

	return paths
}

func buildComponents() map[string]interface{} {
	return map[string]interface{}{
		"schemas":         buildSchemas(),
		"securitySchemes": buildSecuritySchemes(),
	}
}

func buildSecuritySchemes() map[string]interface{} {
	return map[string]interface{}{
		"BearerAuth": map[string]interface{}{
			"type":         "http",
			"scheme":       "bearer",
			"bearerFormat": "JWT",
			"description":  "JWT access token obtained from /api/auth/login",
		},
		"ApiKeyAuth": map[string]interface{}{
			"type":        "apiKey",
			"in":          "header",
			"name":        "X-API-Key",
			"description": "API key for infrastructure and service-to-service access",
		},
	}
}

func buildSchemas() map[string]interface{} {
	return map[string]interface{}{
		// ---- User Management ----
		"User": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id":         map[string]interface{}{"type": "string", "format": "uuid"},
				"username":   map[string]interface{}{"type": "string", "example": "jdoe42"},
				"email":      map[string]interface{}{"type": "string", "format": "email"},
				"full_name":  map[string]interface{}{"type": "string", "example": "Jane Doe"},
				"role":       map[string]interface{}{"type": "string", "enum": []string{"admin", "editor", "viewer", "moderator"}},
				"avatar_url": map[string]interface{}{"type": "string", "format": "uri"},
				"status":     map[string]interface{}{"type": "string", "enum": []string{"active", "suspended", "pending"}},
				"created_at": map[string]interface{}{"type": "string", "format": "date-time"},
				"updated_at": map[string]interface{}{"type": "string", "format": "date-time"},
			},
			"required": []string{"id", "username", "email"},
		},
		"UserCreate": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"username":  map[string]interface{}{"type": "string", "minLength": 3, "maxLength": 32},
				"email":     map[string]interface{}{"type": "string", "format": "email"},
				"full_name": map[string]interface{}{"type": "string"},
				"password":  map[string]interface{}{"type": "string", "format": "password", "minLength": 8},
				"role":      map[string]interface{}{"type": "string", "enum": []string{"admin", "editor", "viewer", "moderator"}},
			},
			"required": []string{"username", "email", "password"},
		},
		"Role": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id":          map[string]interface{}{"type": "string"},
				"name":        map[string]interface{}{"type": "string", "example": "admin"},
				"description": map[string]interface{}{"type": "string"},
				"permissions": map[string]interface{}{
					"type":  "array",
					"items": map[string]interface{}{"type": "string"},
				},
			},
		},
		"ActivityEvent": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id":        map[string]interface{}{"type": "string", "format": "uuid"},
				"type":      map[string]interface{}{"type": "string", "example": "login"},
				"detail":    map[string]interface{}{"type": "string"},
				"ip":        map[string]interface{}{"type": "string", "format": "ipv4"},
				"timestamp": map[string]interface{}{"type": "string", "format": "date-time"},
			},
		},

		// ---- E-Commerce ----
		"Product": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id":          map[string]interface{}{"type": "string", "format": "uuid"},
				"name":        map[string]interface{}{"type": "string", "example": "Wireless Headphones"},
				"slug":        map[string]interface{}{"type": "string", "example": "wireless-headphones"},
				"description": map[string]interface{}{"type": "string"},
				"price":       map[string]interface{}{"type": "number", "format": "float", "example": 79.99},
				"currency":    map[string]interface{}{"type": "string", "example": "USD"},
				"category_id": map[string]interface{}{"type": "string", "format": "uuid"},
				"stock":       map[string]interface{}{"type": "integer", "example": 150},
				"status":      map[string]interface{}{"type": "string", "enum": []string{"active", "draft", "archived"}},
				"images": map[string]interface{}{
					"type":  "array",
					"items": map[string]interface{}{"type": "string", "format": "uri"},
				},
				"rating":     map[string]interface{}{"type": "number", "format": "float", "example": 4.5},
				"created_at": map[string]interface{}{"type": "string", "format": "date-time"},
				"updated_at": map[string]interface{}{"type": "string", "format": "date-time"},
			},
			"required": []string{"id", "name", "price"},
		},
		"ProductCreate": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name":        map[string]interface{}{"type": "string"},
				"description": map[string]interface{}{"type": "string"},
				"price":       map[string]interface{}{"type": "number", "format": "float"},
				"currency":    map[string]interface{}{"type": "string", "default": "USD"},
				"category_id": map[string]interface{}{"type": "string", "format": "uuid"},
				"stock":       map[string]interface{}{"type": "integer"},
			},
			"required": []string{"name", "price"},
		},
		"Review": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id":         map[string]interface{}{"type": "string", "format": "uuid"},
				"user_id":    map[string]interface{}{"type": "string", "format": "uuid"},
				"product_id": map[string]interface{}{"type": "string", "format": "uuid"},
				"rating":     map[string]interface{}{"type": "integer", "minimum": 1, "maximum": 5},
				"title":      map[string]interface{}{"type": "string"},
				"body":       map[string]interface{}{"type": "string"},
				"created_at": map[string]interface{}{"type": "string", "format": "date-time"},
			},
		},
		"ReviewCreate": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"rating": map[string]interface{}{"type": "integer", "minimum": 1, "maximum": 5},
				"title":  map[string]interface{}{"type": "string"},
				"body":   map[string]interface{}{"type": "string"},
			},
			"required": []string{"rating"},
		},
		"Category": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id":          map[string]interface{}{"type": "string", "format": "uuid"},
				"name":        map[string]interface{}{"type": "string", "example": "Electronics"},
				"slug":        map[string]interface{}{"type": "string"},
				"parent_id":   map[string]interface{}{"type": "string", "format": "uuid", "nullable": true},
				"description": map[string]interface{}{"type": "string"},
			},
		},
		"Order": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id":          map[string]interface{}{"type": "string", "format": "uuid"},
				"user_id":     map[string]interface{}{"type": "string", "format": "uuid"},
				"status":      map[string]interface{}{"type": "string", "enum": []string{"pending", "confirmed", "shipped", "delivered", "cancelled"}},
				"total":       map[string]interface{}{"type": "number", "format": "float", "example": 159.98},
				"currency":    map[string]interface{}{"type": "string", "example": "USD"},
				"items":       map[string]interface{}{"type": "array", "items": ref("OrderItem")},
				"shipping_address": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"street":  map[string]interface{}{"type": "string"},
						"city":    map[string]interface{}{"type": "string"},
						"state":   map[string]interface{}{"type": "string"},
						"zip":     map[string]interface{}{"type": "string"},
						"country": map[string]interface{}{"type": "string"},
					},
				},
				"created_at": map[string]interface{}{"type": "string", "format": "date-time"},
				"updated_at": map[string]interface{}{"type": "string", "format": "date-time"},
			},
			"required": []string{"id", "user_id", "status", "total"},
		},
		"OrderCreate": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"items": map[string]interface{}{
					"type": "array",
					"items": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"product_id": map[string]interface{}{"type": "string", "format": "uuid"},
							"quantity":   map[string]interface{}{"type": "integer", "minimum": 1},
						},
						"required": []string{"product_id", "quantity"},
					},
				},
				"shipping_address": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"street":  map[string]interface{}{"type": "string"},
						"city":    map[string]interface{}{"type": "string"},
						"state":   map[string]interface{}{"type": "string"},
						"zip":     map[string]interface{}{"type": "string"},
						"country": map[string]interface{}{"type": "string"},
					},
					"required": []string{"street", "city", "country"},
				},
			},
			"required": []string{"items", "shipping_address"},
		},
		"OrderItem": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"product_id":   map[string]interface{}{"type": "string", "format": "uuid"},
				"product_name": map[string]interface{}{"type": "string"},
				"quantity":     map[string]interface{}{"type": "integer"},
				"unit_price":   map[string]interface{}{"type": "number", "format": "float"},
				"subtotal":     map[string]interface{}{"type": "number", "format": "float"},
			},
		},
		"Cart": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id":         map[string]interface{}{"type": "string", "format": "uuid"},
				"user_id":    map[string]interface{}{"type": "string", "format": "uuid"},
				"items":      map[string]interface{}{"type": "array", "items": ref("CartItem")},
				"total":      map[string]interface{}{"type": "number", "format": "float"},
				"item_count": map[string]interface{}{"type": "integer"},
				"updated_at": map[string]interface{}{"type": "string", "format": "date-time"},
			},
		},
		"CartItem": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id":           map[string]interface{}{"type": "string", "format": "uuid"},
				"product_id":   map[string]interface{}{"type": "string", "format": "uuid"},
				"product_name": map[string]interface{}{"type": "string"},
				"quantity":     map[string]interface{}{"type": "integer"},
				"unit_price":   map[string]interface{}{"type": "number", "format": "float"},
				"subtotal":     map[string]interface{}{"type": "number", "format": "float"},
			},
		},
		"CartItemCreate": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"product_id": map[string]interface{}{"type": "string", "format": "uuid"},
				"quantity":   map[string]interface{}{"type": "integer", "minimum": 1, "default": 1},
			},
			"required": []string{"product_id"},
		},
		"CartItemUpdate": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"quantity": map[string]interface{}{"type": "integer", "minimum": 1},
			},
			"required": []string{"quantity"},
		},

		// ---- Infrastructure ----
		"Server": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id":       map[string]interface{}{"type": "string", "format": "uuid"},
				"hostname": map[string]interface{}{"type": "string", "example": "prod-web-01.us-east.glitch.io"},
				"ip":       map[string]interface{}{"type": "string", "format": "ipv4"},
				"status":   map[string]interface{}{"type": "string", "enum": []string{"running", "stopped", "maintenance", "error"}},
				"provider": map[string]interface{}{"type": "string", "enum": []string{"aws", "gcp", "azure", "bare_metal"}},
				"region":   map[string]interface{}{"type": "string", "example": "us-east-1"},
				"specs": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"cpu_cores":  map[string]interface{}{"type": "integer"},
						"memory_gb":  map[string]interface{}{"type": "integer"},
						"storage_gb": map[string]interface{}{"type": "integer"},
					},
				},
				"tags":       map[string]interface{}{"type": "object", "additionalProperties": map[string]interface{}{"type": "string"}},
				"created_at": map[string]interface{}{"type": "string", "format": "date-time"},
				"updated_at": map[string]interface{}{"type": "string", "format": "date-time"},
			},
			"required": []string{"id", "hostname", "status"},
		},
		"ServerCreate": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"hostname": map[string]interface{}{"type": "string"},
				"provider": map[string]interface{}{"type": "string", "enum": []string{"aws", "gcp", "azure", "bare_metal"}},
				"region":   map[string]interface{}{"type": "string"},
				"specs": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"cpu_cores":  map[string]interface{}{"type": "integer"},
						"memory_gb":  map[string]interface{}{"type": "integer"},
						"storage_gb": map[string]interface{}{"type": "integer"},
					},
				},
				"tags": map[string]interface{}{"type": "object", "additionalProperties": map[string]interface{}{"type": "string"}},
			},
			"required": []string{"hostname", "provider", "region"},
		},
		"ServerMetrics": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"server_id": map[string]interface{}{"type": "string", "format": "uuid"},
				"window":    map[string]interface{}{"type": "string", "example": "1h"},
				"cpu": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"avg_percent": map[string]interface{}{"type": "number", "format": "float"},
						"max_percent": map[string]interface{}{"type": "number", "format": "float"},
						"min_percent": map[string]interface{}{"type": "number", "format": "float"},
					},
				},
				"memory": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"used_gb":  map[string]interface{}{"type": "number", "format": "float"},
						"total_gb": map[string]interface{}{"type": "number", "format": "float"},
						"percent":  map[string]interface{}{"type": "number", "format": "float"},
					},
				},
				"disk": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"used_gb":  map[string]interface{}{"type": "number", "format": "float"},
						"total_gb": map[string]interface{}{"type": "number", "format": "float"},
						"percent":  map[string]interface{}{"type": "number", "format": "float"},
					},
				},
				"network": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"rx_mbps": map[string]interface{}{"type": "number", "format": "float"},
						"tx_mbps": map[string]interface{}{"type": "number", "format": "float"},
					},
				},
				"timestamp": map[string]interface{}{"type": "string", "format": "date-time"},
			},
		},
		"Deployment": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id":         map[string]interface{}{"type": "string", "format": "uuid"},
				"service":    map[string]interface{}{"type": "string", "example": "api-gateway"},
				"version":    map[string]interface{}{"type": "string", "example": "v2.3.1"},
				"status":     map[string]interface{}{"type": "string", "enum": []string{"pending", "in_progress", "completed", "failed", "rolled_back"}},
				"environment": map[string]interface{}{"type": "string", "enum": []string{"production", "staging", "development"}},
				"commit_sha": map[string]interface{}{"type": "string", "example": "a1b2c3d4"},
				"deployed_by": map[string]interface{}{"type": "string"},
				"started_at": map[string]interface{}{"type": "string", "format": "date-time"},
				"finished_at": map[string]interface{}{"type": "string", "format": "date-time", "nullable": true},
				"created_at": map[string]interface{}{"type": "string", "format": "date-time"},
			},
			"required": []string{"id", "service", "version", "status"},
		},
		"DeploymentCreate": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"service":     map[string]interface{}{"type": "string"},
				"version":     map[string]interface{}{"type": "string"},
				"environment": map[string]interface{}{"type": "string", "enum": []string{"production", "staging", "development"}},
				"commit_sha":  map[string]interface{}{"type": "string"},
			},
			"required": []string{"service", "version", "environment"},
		},
		"Container": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id":         map[string]interface{}{"type": "string"},
				"name":       map[string]interface{}{"type": "string", "example": "api-gateway-7f8d9c"},
				"image":      map[string]interface{}{"type": "string", "example": "registry.glitch.io/api-gateway:v2.3.1"},
				"status":     map[string]interface{}{"type": "string", "enum": []string{"running", "pending", "stopped", "crashed"}},
				"cpu_usage":  map[string]interface{}{"type": "number", "format": "float"},
				"memory_mb":  map[string]interface{}{"type": "integer"},
				"server_id":  map[string]interface{}{"type": "string", "format": "uuid"},
				"started_at": map[string]interface{}{"type": "string", "format": "date-time"},
			},
		},
		"Cluster": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id":          map[string]interface{}{"type": "string", "format": "uuid"},
				"name":        map[string]interface{}{"type": "string", "example": "prod-us-east"},
				"provider":    map[string]interface{}{"type": "string"},
				"region":      map[string]interface{}{"type": "string"},
				"node_count":  map[string]interface{}{"type": "integer"},
				"status":      map[string]interface{}{"type": "string", "enum": []string{"healthy", "degraded", "offline"}},
				"k8s_version": map[string]interface{}{"type": "string", "example": "1.28.3"},
				"created_at":  map[string]interface{}{"type": "string", "format": "date-time"},
			},
		},

		// ---- CMS ----
		"Post": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id":           map[string]interface{}{"type": "string", "format": "uuid"},
				"title":        map[string]interface{}{"type": "string", "example": "Getting Started with Glitch"},
				"slug":         map[string]interface{}{"type": "string", "example": "getting-started-with-glitch"},
				"body":         map[string]interface{}{"type": "string"},
				"excerpt":      map[string]interface{}{"type": "string"},
				"author_id":    map[string]interface{}{"type": "string", "format": "uuid"},
				"status":       map[string]interface{}{"type": "string", "enum": []string{"draft", "published", "archived"}},
				"tags":         map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
				"featured_image": map[string]interface{}{"type": "string", "format": "uri"},
				"published_at": map[string]interface{}{"type": "string", "format": "date-time", "nullable": true},
				"created_at":   map[string]interface{}{"type": "string", "format": "date-time"},
				"updated_at":   map[string]interface{}{"type": "string", "format": "date-time"},
			},
			"required": []string{"id", "title", "body"},
		},
		"PostCreate": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"title":   map[string]interface{}{"type": "string"},
				"body":    map[string]interface{}{"type": "string"},
				"excerpt": map[string]interface{}{"type": "string"},
				"status":  map[string]interface{}{"type": "string", "enum": []string{"draft", "published"}},
				"tags":    map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
			},
			"required": []string{"title", "body"},
		},
		"Comment": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id":         map[string]interface{}{"type": "string", "format": "uuid"},
				"post_id":    map[string]interface{}{"type": "string", "format": "uuid"},
				"author_id":  map[string]interface{}{"type": "string", "format": "uuid"},
				"author_name": map[string]interface{}{"type": "string"},
				"body":       map[string]interface{}{"type": "string"},
				"status":     map[string]interface{}{"type": "string", "enum": []string{"approved", "pending", "spam"}},
				"created_at": map[string]interface{}{"type": "string", "format": "date-time"},
			},
		},
		"CommentCreate": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"post_id": map[string]interface{}{"type": "string", "format": "uuid"},
				"body":    map[string]interface{}{"type": "string"},
			},
			"required": []string{"body"},
		},
		"Page": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id":         map[string]interface{}{"type": "string", "format": "uuid"},
				"title":      map[string]interface{}{"type": "string"},
				"slug":       map[string]interface{}{"type": "string"},
				"body":       map[string]interface{}{"type": "string"},
				"status":     map[string]interface{}{"type": "string", "enum": []string{"draft", "published"}},
				"parent_id":  map[string]interface{}{"type": "string", "format": "uuid", "nullable": true},
				"sort_order": map[string]interface{}{"type": "integer"},
				"created_at": map[string]interface{}{"type": "string", "format": "date-time"},
				"updated_at": map[string]interface{}{"type": "string", "format": "date-time"},
			},
			"required": []string{"id", "title", "body"},
		},
		"PageCreate": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"title":      map[string]interface{}{"type": "string"},
				"body":       map[string]interface{}{"type": "string"},
				"slug":       map[string]interface{}{"type": "string"},
				"status":     map[string]interface{}{"type": "string", "enum": []string{"draft", "published"}},
				"parent_id":  map[string]interface{}{"type": "string", "format": "uuid"},
				"sort_order": map[string]interface{}{"type": "integer"},
			},
			"required": []string{"title", "body"},
		},
		"MediaAsset": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id":         map[string]interface{}{"type": "string", "format": "uuid"},
				"filename":   map[string]interface{}{"type": "string", "example": "hero-banner.jpg"},
				"mime_type":  map[string]interface{}{"type": "string", "example": "image/jpeg"},
				"size_bytes": map[string]interface{}{"type": "integer", "example": 245760},
				"url":        map[string]interface{}{"type": "string", "format": "uri"},
				"alt_text":   map[string]interface{}{"type": "string"},
				"uploaded_by": map[string]interface{}{"type": "string", "format": "uuid"},
				"created_at": map[string]interface{}{"type": "string", "format": "date-time"},
			},
		},
		"Tag": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id":         map[string]interface{}{"type": "string"},
				"name":       map[string]interface{}{"type": "string", "example": "golang"},
				"slug":       map[string]interface{}{"type": "string", "example": "golang"},
				"post_count": map[string]interface{}{"type": "integer"},
			},
		},

		// ---- Auth ----
		"LoginRequest": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"email":    map[string]interface{}{"type": "string", "format": "email"},
				"password": map[string]interface{}{"type": "string", "format": "password"},
			},
			"required": []string{"email", "password"},
		},
		"RegisterRequest": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"username": map[string]interface{}{"type": "string", "minLength": 3},
				"email":    map[string]interface{}{"type": "string", "format": "email"},
				"password": map[string]interface{}{"type": "string", "format": "password", "minLength": 8},
				"full_name": map[string]interface{}{"type": "string"},
			},
			"required": []string{"username", "email", "password"},
		},
		"AuthResponse": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"access_token":  map[string]interface{}{"type": "string"},
				"refresh_token": map[string]interface{}{"type": "string"},
				"token_type":    map[string]interface{}{"type": "string", "example": "Bearer"},
				"expires_in":    map[string]interface{}{"type": "integer", "example": 3600},
				"user":          ref("User"),
			},
		},

		// ---- Search ----
		"SearchResults": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"query":       map[string]interface{}{"type": "string"},
				"total":       map[string]interface{}{"type": "integer"},
				"took_ms":     map[string]interface{}{"type": "integer"},
				"results":     map[string]interface{}{"type": "array", "items": ref("SearchHit")},
				"pagination":  ref("PaginationMeta"),
			},
		},
		"SearchHit": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"type":      map[string]interface{}{"type": "string", "enum": []string{"user", "product", "post", "page"}},
				"id":        map[string]interface{}{"type": "string"},
				"title":     map[string]interface{}{"type": "string"},
				"snippet":   map[string]interface{}{"type": "string"},
				"score":     map[string]interface{}{"type": "number", "format": "float"},
				"url":       map[string]interface{}{"type": "string"},
			},
		},
		"PaginationMeta": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"page":        map[string]interface{}{"type": "integer"},
				"per_page":    map[string]interface{}{"type": "integer"},
				"total":       map[string]interface{}{"type": "integer"},
				"total_pages": map[string]interface{}{"type": "integer"},
			},
		},

		// ---- Common ----
		"Error": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"error":   map[string]interface{}{"type": "string", "example": "validation_error"},
				"message": map[string]interface{}{"type": "string", "example": "The request body is invalid"},
				"details": map[string]interface{}{
					"type": "array",
					"items": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"field":   map[string]interface{}{"type": "string"},
							"message": map[string]interface{}{"type": "string"},
						},
					},
				},
			},
			"required": []string{"error", "message"},
		},
	}
}

// --- Helpers for building spec fragments ---

// ref returns a $ref to a component schema.
func ref(name string) map[string]interface{} {
	return map[string]interface{}{"$ref": "#/components/schemas/" + name}
}

// bearerSecurity returns the security requirement for Bearer auth.
func bearerSecurity() []map[string]interface{} {
	return []map[string]interface{}{
		{"BearerAuth": []string{}},
	}
}

// apiKeySecurity returns the security requirement for API key auth.
func apiKeySecurity() []map[string]interface{} {
	return []map[string]interface{}{
		{"ApiKeyAuth": []string{}},
	}
}

// idParam returns the standard {id} path parameter.
func idParam(resource string) []map[string]interface{} {
	return []map[string]interface{}{
		{
			"name":        "id",
			"in":          "path",
			"required":    true,
			"description": resource + " ID",
			"schema":      map[string]interface{}{"type": "string"},
		},
	}
}

// paginationParams returns standard pagination + sort query parameters.
func paginationParams(sortFields ...string) []map[string]interface{} {
	params := []map[string]interface{}{
		{
			"name":        "page",
			"in":          "query",
			"description": "Page number (1-based)",
			"schema":      map[string]interface{}{"type": "integer", "default": 1, "minimum": 1},
		},
		{
			"name":        "per_page",
			"in":          "query",
			"description": "Items per page (max 100)",
			"schema":      map[string]interface{}{"type": "integer", "default": 20, "minimum": 1, "maximum": 100},
		},
	}
	if len(sortFields) > 0 {
		params = append(params, map[string]interface{}{
			"name":        "sort",
			"in":          "query",
			"description": "Sort field",
			"schema": map[string]interface{}{
				"type": "string",
				"enum": sortFields,
			},
		})
		params = append(params, map[string]interface{}{
			"name":        "order",
			"in":          "query",
			"description": "Sort order",
			"schema": map[string]interface{}{
				"type":    "string",
				"enum":    []string{"asc", "desc"},
				"default": "desc",
			},
		})
	}
	return params
}

// requestBody returns a JSON request body referencing a schema.
func requestBody(schemaName string, required bool) map[string]interface{} {
	return map[string]interface{}{
		"required": required,
		"content": map[string]interface{}{
			"application/json": map[string]interface{}{
				"schema": ref(schemaName),
			},
		},
	}
}

// listResponse returns standard responses for a list endpoint.
func listResponse(schemaName string) map[string]interface{} {
	return map[string]interface{}{
		"200": map[string]interface{}{
			"description": "Successful response",
			"content": map[string]interface{}{
				"application/json": map[string]interface{}{
					"schema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"data": map[string]interface{}{
								"type":  "array",
								"items": ref(schemaName),
							},
							"pagination": ref("PaginationMeta"),
							"_links": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"self":  map[string]interface{}{"type": "string"},
									"first": map[string]interface{}{"type": "string"},
									"last":  map[string]interface{}{"type": "string"},
									"next":  map[string]interface{}{"type": "string"},
									"prev":  map[string]interface{}{"type": "string"},
								},
							},
						},
					},
				},
			},
		},
		"401": unauthorizedResponse(),
		"500": serverErrorResponse(),
	}
}

// singleResponse returns standard responses for a single-resource GET/PUT.
func singleResponse(schemaName string) map[string]interface{} {
	return map[string]interface{}{
		"200": map[string]interface{}{
			"description": "Successful response",
			"content": map[string]interface{}{
				"application/json": map[string]interface{}{
					"schema": ref(schemaName),
				},
			},
		},
		"401": unauthorizedResponse(),
		"404": notFoundResponse(),
		"500": serverErrorResponse(),
	}
}

// createResponse returns standard responses for a POST/create endpoint.
func createResponse(schemaName string) map[string]interface{} {
	return map[string]interface{}{
		"201": map[string]interface{}{
			"description": "Resource created",
			"content": map[string]interface{}{
				"application/json": map[string]interface{}{
					"schema": ref(schemaName),
				},
			},
		},
		"400": badRequestResponse(),
		"401": unauthorizedResponse(),
		"500": serverErrorResponse(),
	}
}

// deleteResponse returns standard responses for a DELETE endpoint.
func deleteResponse() map[string]interface{} {
	return map[string]interface{}{
		"204": map[string]interface{}{
			"description": "Resource deleted",
		},
		"401": unauthorizedResponse(),
		"403": forbiddenResponse(),
		"404": notFoundResponse(),
		"500": serverErrorResponse(),
	}
}

func unauthorizedResponse() map[string]interface{} {
	return map[string]interface{}{
		"description": "Authentication required",
		"content": map[string]interface{}{
			"application/json": map[string]interface{}{
				"schema": ref("Error"),
			},
		},
	}
}

func forbiddenResponse() map[string]interface{} {
	return map[string]interface{}{
		"description": "Insufficient permissions",
		"content": map[string]interface{}{
			"application/json": map[string]interface{}{
				"schema": ref("Error"),
			},
		},
	}
}

func notFoundResponse() map[string]interface{} {
	return map[string]interface{}{
		"description": "Resource not found",
		"content": map[string]interface{}{
			"application/json": map[string]interface{}{
				"schema": ref("Error"),
			},
		},
	}
}

func badRequestResponse() map[string]interface{} {
	return map[string]interface{}{
		"description": "Invalid request body",
		"content": map[string]interface{}{
			"application/json": map[string]interface{}{
				"schema": ref("Error"),
			},
		},
	}
}

func serverErrorResponse() map[string]interface{} {
	return map[string]interface{}{
		"description": "Internal server error",
		"content": map[string]interface{}{
			"application/json": map[string]interface{}{
				"schema": ref("Error"),
			},
		},
	}
}
