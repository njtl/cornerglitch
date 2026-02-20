package api

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// --- Data generation tables ---

var productPrefixes = []string{
	"Ultra", "Pro", "Elite", "Prime", "Quantum", "Nano", "Turbo", "Hyper",
	"Smart", "Flex", "Core", "Max", "Apex", "Zen", "Nova", "Pulse",
	"Aero", "Volt", "Ion", "Pixel", "Echo", "Nexus", "Fusion", "Helix",
	"Vertex", "Onyx", "Titan", "Vibe", "Spark", "Arc",
}

var productAdjectives = []string{
	"Wireless", "Portable", "Premium", "Compact", "Advanced", "Ergonomic",
	"Lightweight", "Rugged", "Sleek", "High-Performance", "All-in-One",
	"Waterproof", "Solar-Powered", "Foldable", "Magnetic", "Thermal",
	"Acoustic", "Modular", "Transparent", "Bamboo",
}

var productNouns = []string{
	"Speaker", "Headphones", "Keyboard", "Mouse", "Monitor", "Charger",
	"Backpack", "Lamp", "Stand", "Hub", "Cable", "Case", "Wallet",
	"Bottle", "Mat", "Dock", "Adapter", "Ring", "Watch", "Tracker",
}

var categoryList = []string{
	"Electronics", "Audio", "Computers", "Accessories", "Home & Kitchen",
	"Sports", "Outdoors", "Clothing", "Footwear", "Health", "Beauty",
	"Toys", "Books", "Automotive", "Garden",
}

var brandList = []string{
	"TechNova", "ZenWare", "PulseGear", "ArcLight", "VertexLabs",
	"OnyxCraft", "SparkLine", "FusionCore", "HelixIO", "TitanEdge",
}

var currencyList = []string{"USD", "USD", "USD", "EUR", "GBP"} // weighted toward USD

var orderStatuses = []string{"pending", "processing", "shipped", "delivered", "cancelled"}

var streetNames = []string{
	"Oak Street", "Maple Avenue", "Cedar Lane", "Pine Road", "Elm Drive",
	"Birch Boulevard", "Walnut Court", "Spruce Way", "Aspen Circle", "Willow Path",
}

var cityNames = []string{
	"Springfield", "Portland", "Burlington", "Asheville", "Madison",
	"Salem", "Dover", "Camden", "Fairview", "Bristol",
}

var stateNames = []string{
	"CA", "NY", "TX", "FL", "WA", "OR", "CO", "MA", "IL", "PA",
}

// EcommerceAPI handles all e-commerce related endpoints.
type EcommerceAPI struct{}

// NewEcommerceAPI creates a new EcommerceAPI handler.
func NewEcommerceAPI() *EcommerceAPI {
	return &EcommerceAPI{}
}

// ServeHTTP dispatches e-commerce API requests.
func (e *EcommerceAPI) ServeHTTP(w http.ResponseWriter, r *http.Request, apiPath string) int {
	if r.Method == http.MethodOptions {
		return handleOptions(w)
	}

	switch {
	case strings.HasPrefix(apiPath, "/v1/products"):
		return e.handleProducts(w, r, apiPath)
	case strings.HasPrefix(apiPath, "/v1/categories"):
		return e.handleCategories(w, r, apiPath)
	case strings.HasPrefix(apiPath, "/v1/orders"):
		return e.handleOrders(w, r, apiPath)
	case strings.HasPrefix(apiPath, "/v1/cart"):
		return e.handleCart(w, r, apiPath)
	}

	writeJSON(w, http.StatusNotFound, map[string]interface{}{
		"error":   "not_found",
		"message": "Unknown e-commerce endpoint",
	})
	return http.StatusNotFound
}

// ---- Products ----

const totalProducts = 1250

func (e *EcommerceAPI) handleProducts(w http.ResponseWriter, r *http.Request, apiPath string) int {
	id := extractID(apiPath, "/v1/products")

	// Collection endpoints
	if id == "" {
		switch r.Method {
		case http.MethodGet:
			return e.listProducts(w, r)
		case http.MethodPost:
			return e.createProduct(w, r)
		default:
			return methodNotAllowed(w, "GET, POST, OPTIONS")
		}
	}

	// Sub-resource: /v1/products/{id}/reviews
	sub := subResource(apiPath, "/v1/products")
	if sub == "reviews" {
		if r.Method != http.MethodGet {
			return methodNotAllowed(w, "GET, OPTIONS")
		}
		return e.listProductReviews(w, r, id)
	}

	// Single product
	if r.Method != http.MethodGet {
		return methodNotAllowed(w, "GET, OPTIONS")
	}
	return e.getProduct(w, r, id)
}

func (e *EcommerceAPI) listProducts(w http.ResponseWriter, r *http.Request) int {
	page, perPage := parsePagination(r)

	q := r.URL.Query()
	categoryFilter := q.Get("category")
	minPriceStr := q.Get("min_price")
	maxPriceStr := q.Get("max_price")
	sortField := q.Get("sort")

	var minPrice, maxPrice float64
	hasMinPrice := false
	hasMaxPrice := false
	if minPriceStr != "" {
		if v, err := strconv.ParseFloat(minPriceStr, 64); err == nil {
			minPrice = v
			hasMinPrice = true
		}
	}
	if maxPriceStr != "" {
		if v, err := strconv.ParseFloat(maxPriceStr, 64); err == nil {
			maxPrice = v
			hasMaxPrice = true
		}
	}

	// Generate all products that match the filter
	var filtered []map[string]interface{}
	for i := 0; i < totalProducts; i++ {
		p := generateProduct(i)
		if categoryFilter != "" && p["category"] != categoryFilter {
			continue
		}
		price := p["price"].(float64)
		if hasMinPrice && price < minPrice {
			continue
		}
		if hasMaxPrice && price > maxPrice {
			continue
		}
		filtered = append(filtered, p)
	}

	// Sorting
	if sortField != "" {
		sortProducts(filtered, sortField)
	}

	total := len(filtered)

	// Paginate
	start := (page - 1) * perPage
	if start > total {
		start = total
	}
	end := start + perPage
	if end > total {
		end = total
	}
	pageItems := filtered[start:end]
	if pageItems == nil {
		pageItems = []map[string]interface{}{}
	}

	w.Header().Set("X-Total-Count", strconv.Itoa(total))
	paginatedJSON(w, r, pageItems, total)
	return http.StatusOK
}

func sortProducts(items []map[string]interface{}, field string) {
	desc := false
	if strings.HasPrefix(field, "-") {
		desc = true
		field = field[1:]
	}

	// Simple insertion sort (adequate for deterministic, bounded data)
	for i := 1; i < len(items); i++ {
		for j := i; j > 0; j-- {
			swap := false
			switch field {
			case "price":
				a := items[j-1]["price"].(float64)
				b := items[j]["price"].(float64)
				if desc {
					swap = b > a
				} else {
					swap = a > b
				}
			case "name":
				a := items[j-1]["name"].(string)
				b := items[j]["name"].(string)
				if desc {
					swap = b > a
				} else {
					swap = a > b
				}
			case "rating":
				a := items[j-1]["rating"].(float64)
				b := items[j]["rating"].(float64)
				if desc {
					swap = b > a
				} else {
					swap = a > b
				}
			case "created_at":
				a := items[j-1]["created_at"].(string)
				b := items[j]["created_at"].(string)
				if desc {
					swap = b > a
				} else {
					swap = a > b
				}
			}
			if swap {
				items[j-1], items[j] = items[j], items[j-1]
			} else {
				break
			}
		}
	}
}

func (e *EcommerceAPI) createProduct(w http.ResponseWriter, r *http.Request) int {
	rng := pathSeed(r.URL.Path + r.RemoteAddr)
	product := map[string]interface{}{
		"id":         deterministicUUID(rng),
		"name":       "New Product",
		"slug":       "new-product",
		"status":     "draft",
		"created_at": time.Now().UTC().Format(time.RFC3339),
		"message":    "Product created successfully",
	}
	writeJSON(w, http.StatusCreated, product)
	return http.StatusCreated
}

func (e *EcommerceAPI) getProduct(w http.ResponseWriter, r *http.Request, id string) int {
	idx, err := strconv.Atoi(id)
	if err != nil || idx < 0 || idx >= totalProducts {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{
			"error":   "not_found",
			"message": fmt.Sprintf("Product %s not found", id),
		})
		return http.StatusNotFound
	}

	product := generateProduct(idx)

	// Add detailed fields for single-product view
	rng := productRng(idx)
	// Burn the same random calls that generateProduct used so we get fresh values
	// Instead, create a detail-specific rng
	detailRng := pathSeed(fmt.Sprintf("product-detail-%d", idx))

	// Specifications
	specKeys := []string{"Weight", "Dimensions", "Material", "Color", "Warranty", "Battery Life", "Connectivity", "Compatibility"}
	specVals := []string{
		fmt.Sprintf("%.1f oz", float64(detailRng.Intn(400)+10)/10.0),
		fmt.Sprintf("%dx%dx%d mm", detailRng.Intn(300)+20, detailRng.Intn(200)+20, detailRng.Intn(100)+5),
		[]string{"Aluminum", "ABS Plastic", "Stainless Steel", "Carbon Fiber", "Bamboo", "Silicone"}[detailRng.Intn(6)],
		[]string{"Black", "White", "Silver", "Space Gray", "Navy", "Forest Green", "Rose Gold"}[detailRng.Intn(7)],
		fmt.Sprintf("%d years", detailRng.Intn(5)+1),
		fmt.Sprintf("%d hours", detailRng.Intn(72)+4),
		[]string{"USB-C", "Bluetooth 5.3", "WiFi 6E", "NFC", "Lightning"}[detailRng.Intn(5)],
		[]string{"Windows/Mac/Linux", "iOS/Android", "Universal", "Mac Only", "Windows Only"}[detailRng.Intn(5)],
	}
	specs := make(map[string]string)
	numSpecs := detailRng.Intn(4) + 3
	for i := 0; i < numSpecs && i < len(specKeys); i++ {
		specs[specKeys[i]] = specVals[i]
	}
	product["specifications"] = specs

	// Variants
	variantCount := detailRng.Intn(4) + 1
	variants := make([]map[string]interface{}, variantCount)
	variantNames := []string{"Standard", "Pro", "Lite", "Max", "Mini", "XL"}
	for i := 0; i < variantCount; i++ {
		vRng := pathSeed(fmt.Sprintf("variant-%d-%d", idx, i))
		variants[i] = map[string]interface{}{
			"id":          deterministicUUID(vRng),
			"name":        variantNames[i%len(variantNames)],
			"sku":         fmt.Sprintf("SKU-%s-%d", strings.ToUpper(randHexDet(vRng, 4)), i),
			"price":       roundPrice(product["price"].(float64) + float64(detailRng.Intn(200)-50)),
			"stock_count": detailRng.Intn(500),
			"attributes": map[string]string{
				"color": []string{"Black", "White", "Silver", "Blue", "Red"}[vRng.Intn(5)],
				"size":  []string{"S", "M", "L", "XL"}[vRng.Intn(4)],
			},
		}
	}
	product["variants"] = variants

	// Related products
	relatedCount := detailRng.Intn(4) + 2
	related := make([]map[string]interface{}, relatedCount)
	for i := 0; i < relatedCount; i++ {
		relIdx := (idx + i + 1) % totalProducts
		relP := generateProduct(relIdx)
		related[i] = map[string]interface{}{
			"id":    relP["id"],
			"name":  relP["name"],
			"slug":  relP["slug"],
			"price": relP["price"],
			"image": relP["images"].([]string)[0],
		}
	}
	product["related_products"] = related

	_ = rng // silence unused
	writeJSON(w, http.StatusOK, product)
	return http.StatusOK
}

func (e *EcommerceAPI) listProductReviews(w http.ResponseWriter, r *http.Request, productID string) int {
	idx, err := strconv.Atoi(productID)
	if err != nil || idx < 0 || idx >= totalProducts {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{
			"error":   "not_found",
			"message": fmt.Sprintf("Product %s not found", productID),
		})
		return http.StatusNotFound
	}

	page, perPage := parsePagination(r)
	reviewRng := pathSeed(fmt.Sprintf("product-reviews-%d", idx))
	totalReviews := reviewRng.Intn(80) + 5

	firstNames := []string{"Alice", "Bob", "Charlie", "Diana", "Evan", "Fiona", "George", "Hannah", "Isaac", "Julia"}
	lastNames := []string{"Smith", "Johnson", "Lee", "Garcia", "Brown", "Wilson", "Taylor", "Clark", "Hall", "Young"}

	var reviews []map[string]interface{}
	for i := 0; i < totalReviews; i++ {
		rRng := pathSeed(fmt.Sprintf("review-%d-%d", idx, i))
		rating := rRng.Intn(5) + 1
		firstName := firstNames[rRng.Intn(len(firstNames))]
		lastName := lastNames[rRng.Intn(len(lastNames))]
		reviews = append(reviews, map[string]interface{}{
			"id":         deterministicUUID(rRng),
			"product_id": fmt.Sprintf("prod_%06d", idx),
			"user_name":  fmt.Sprintf("%s %s", firstName, lastName),
			"rating":     rating,
			"title":      reviewTitle(rRng, rating),
			"body":       reviewBody(rRng, rating),
			"verified":   rRng.Intn(3) != 0,
			"helpful":    rRng.Intn(50),
			"created_at": deterministicTimestamp(rRng),
		})
	}

	start := (page - 1) * perPage
	if start > len(reviews) {
		start = len(reviews)
	}
	end := start + perPage
	if end > len(reviews) {
		end = len(reviews)
	}
	pageItems := reviews[start:end]
	if pageItems == nil {
		pageItems = []map[string]interface{}{}
	}

	w.Header().Set("X-Total-Count", strconv.Itoa(totalReviews))
	paginatedJSON(w, r, pageItems, totalReviews)
	return http.StatusOK
}

// ---- Categories ----

const totalCategories = 30

var extendedCategories = []string{
	"Electronics", "Audio", "Computers", "Accessories", "Home & Kitchen",
	"Sports", "Outdoors", "Clothing", "Footwear", "Health",
	"Beauty", "Toys", "Books", "Automotive", "Garden",
	"Pet Supplies", "Office Products", "Musical Instruments", "Software", "Video Games",
	"Baby", "Grocery", "Industrial", "Handmade", "Luggage",
	"Jewelry", "Watches", "Tools", "Lighting", "Appliances",
}

func (e *EcommerceAPI) handleCategories(w http.ResponseWriter, r *http.Request, apiPath string) int {
	if r.Method != http.MethodGet {
		return methodNotAllowed(w, "GET, OPTIONS")
	}

	categories := make([]map[string]interface{}, totalCategories)
	for i := 0; i < totalCategories; i++ {
		rng := pathSeed(fmt.Sprintf("category-%d", i))
		name := extendedCategories[i]
		slug := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(name, " & ", "-"), " ", "-"))
		categories[i] = map[string]interface{}{
			"id":            fmt.Sprintf("cat_%03d", i),
			"name":          name,
			"slug":          slug,
			"product_count": rng.Intn(200) + 10,
		}
	}

	w.Header().Set("X-Total-Count", strconv.Itoa(totalCategories))
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data":  categories,
		"total": totalCategories,
	})
	return http.StatusOK
}

// ---- Orders ----

const totalOrders = 500

func (e *EcommerceAPI) handleOrders(w http.ResponseWriter, r *http.Request, apiPath string) int {
	id := extractID(apiPath, "/v1/orders")

	if id == "" {
		switch r.Method {
		case http.MethodGet:
			return e.listOrders(w, r)
		case http.MethodPost:
			return e.createOrder(w, r)
		default:
			return methodNotAllowed(w, "GET, POST, OPTIONS")
		}
	}

	if r.Method != http.MethodGet {
		return methodNotAllowed(w, "GET, OPTIONS")
	}
	return e.getOrder(w, r, id)
}

func (e *EcommerceAPI) listOrders(w http.ResponseWriter, r *http.Request) int {
	page, perPage := parsePagination(r)

	start := (page - 1) * perPage
	if start > totalOrders {
		start = totalOrders
	}
	end := start + perPage
	if end > totalOrders {
		end = totalOrders
	}

	orders := make([]map[string]interface{}, 0, end-start)
	for i := start; i < end; i++ {
		orders = append(orders, generateOrder(i, false))
	}

	w.Header().Set("X-Total-Count", strconv.Itoa(totalOrders))
	paginatedJSON(w, r, orders, totalOrders)
	return http.StatusOK
}

func (e *EcommerceAPI) getOrder(w http.ResponseWriter, r *http.Request, id string) int {
	idx, err := strconv.Atoi(id)
	if err != nil || idx < 0 || idx >= totalOrders {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{
			"error":   "not_found",
			"message": fmt.Sprintf("Order %s not found", id),
		})
		return http.StatusNotFound
	}

	order := generateOrder(idx, true)
	writeJSON(w, http.StatusOK, order)
	return http.StatusOK
}

func (e *EcommerceAPI) createOrder(w http.ResponseWriter, r *http.Request) int {
	rng := pathSeed(r.URL.Path + r.RemoteAddr)
	order := map[string]interface{}{
		"id":         deterministicUUID(rng),
		"status":     "pending",
		"total":      roundPrice(float64(rng.Intn(50000)+500) / 100.0),
		"currency":   "USD",
		"created_at": time.Now().UTC().Format(time.RFC3339),
		"message":    "Order placed successfully",
	}
	writeJSON(w, http.StatusCreated, order)
	return http.StatusCreated
}

// ---- Cart ----

func (e *EcommerceAPI) handleCart(w http.ResponseWriter, r *http.Request, apiPath string) int {
	switch {
	case apiPath == "/v1/cart":
		if r.Method != http.MethodGet {
			return methodNotAllowed(w, "GET, OPTIONS")
		}
		return e.getCart(w, r)

	case apiPath == "/v1/cart/items":
		if r.Method != http.MethodPost {
			return methodNotAllowed(w, "POST, OPTIONS")
		}
		return e.addCartItem(w, r)

	case strings.HasPrefix(apiPath, "/v1/cart/items/"):
		if r.Method != http.MethodDelete {
			return methodNotAllowed(w, "DELETE, OPTIONS")
		}
		return e.removeCartItem(w, r, apiPath)

	default:
		writeJSON(w, http.StatusNotFound, map[string]interface{}{
			"error":   "not_found",
			"message": "Unknown cart endpoint",
		})
		return http.StatusNotFound
	}
}

func (e *EcommerceAPI) getCart(w http.ResponseWriter, r *http.Request) int {
	rng := pathSeed(r.URL.Path + r.RemoteAddr)
	itemCount := rng.Intn(5) + 1

	items := make([]map[string]interface{}, itemCount)
	var subtotal float64
	for i := 0; i < itemCount; i++ {
		iRng := pathSeed(fmt.Sprintf("cart-item-%s-%d", r.RemoteAddr, i))
		prodIdx := iRng.Intn(totalProducts)
		prod := generateProduct(prodIdx)
		qty := iRng.Intn(3) + 1
		price := prod["price"].(float64)
		lineTotal := roundPrice(price * float64(qty))
		subtotal += lineTotal
		items[i] = map[string]interface{}{
			"id":          fmt.Sprintf("ci_%s", randHexDet(iRng, 6)),
			"product_id":  prod["id"],
			"product_name": prod["name"],
			"quantity":    qty,
			"unit_price":  price,
			"line_total":  lineTotal,
			"image":       prod["images"].([]string)[0],
		}
	}

	tax := roundPrice(subtotal * 0.08)
	shipping := roundPrice(float64(rng.Intn(1500)+499) / 100.0)
	total := roundPrice(subtotal + tax + shipping)

	cart := map[string]interface{}{
		"items":      items,
		"item_count": itemCount,
		"subtotal":   subtotal,
		"tax":        tax,
		"shipping":   shipping,
		"total":      total,
		"currency":   "USD",
	}

	writeJSON(w, http.StatusOK, cart)
	return http.StatusOK
}

func (e *EcommerceAPI) addCartItem(w http.ResponseWriter, r *http.Request) int {
	rng := pathSeed(r.URL.Path + r.RemoteAddr)
	item := map[string]interface{}{
		"id":         fmt.Sprintf("ci_%s", randHexDet(rng, 6)),
		"product_id": fmt.Sprintf("prod_%06d", rng.Intn(totalProducts)),
		"quantity":   1,
		"message":    "Item added to cart",
	}
	writeJSON(w, http.StatusCreated, item)
	return http.StatusCreated
}

func (e *EcommerceAPI) removeCartItem(w http.ResponseWriter, r *http.Request, apiPath string) int {
	itemID := extractID(apiPath, "/v1/cart/items")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": fmt.Sprintf("Item %s removed from cart", itemID),
		"deleted": true,
	})
	return http.StatusOK
}

// ---- Data generators ----

func productRng(idx int) *rand.Rand {
	h := sha256.Sum256([]byte(fmt.Sprintf("product-%d", idx)))
	seed := int64(binary.BigEndian.Uint64(h[:8]))
	return rand.New(rand.NewSource(seed))
}

func generateProduct(idx int) map[string]interface{} {
	rng := productRng(idx)

	prefix := productPrefixes[rng.Intn(len(productPrefixes))]
	adj := productAdjectives[rng.Intn(len(productAdjectives))]
	noun := productNouns[rng.Intn(len(productNouns))]
	name := fmt.Sprintf("%s %s %s", prefix, adj, noun)
	slug := strings.ToLower(strings.ReplaceAll(name, " ", "-"))

	category := categoryList[rng.Intn(len(categoryList))]
	brand := brandList[rng.Intn(len(brandList))]

	// Price: $4.99 to $2499.99
	price := roundPrice(float64(rng.Intn(249500)+499) / 100.0)

	sku := fmt.Sprintf("SKU-%s-%04d", strings.ToUpper(brand[:3]), idx)

	stockCount := rng.Intn(1000)
	rating := roundRating(1.0 + rng.Float64()*4.0) // 1.0 to 5.0
	reviewCount := rng.Intn(500)

	imageCount := rng.Intn(4) + 1
	images := make([]string, imageCount)
	for i := 0; i < imageCount; i++ {
		images[i] = fmt.Sprintf("/static/images/products/%06d_%d.jpg", idx, i)
	}

	currency := currencyList[rng.Intn(len(currencyList))]

	return map[string]interface{}{
		"id":           fmt.Sprintf("prod_%06d", idx),
		"name":         name,
		"slug":         slug,
		"description":  generateDescription(rng, name, category),
		"price":        price,
		"currency":     currency,
		"category":     category,
		"brand":        brand,
		"sku":          sku,
		"stock_count":  stockCount,
		"rating":       rating,
		"review_count": reviewCount,
		"images":       images,
		"created_at":   deterministicTimestamp(rng),
	}
}

func generateOrder(idx int, detailed bool) map[string]interface{} {
	rng := pathSeed(fmt.Sprintf("order-%d", idx))

	userIdx := rng.Intn(200)
	status := orderStatuses[rng.Intn(len(orderStatuses))]
	currency := "USD"

	// Order items
	itemCount := rng.Intn(5) + 1
	items := make([]map[string]interface{}, itemCount)
	var orderTotal float64
	for i := 0; i < itemCount; i++ {
		prodIdx := rng.Intn(totalProducts)
		prod := generateProduct(prodIdx)
		qty := rng.Intn(3) + 1
		price := prod["price"].(float64)
		lineTotal := roundPrice(price * float64(qty))
		orderTotal += lineTotal
		items[i] = map[string]interface{}{
			"product_id":   prod["id"],
			"product_name": prod["name"],
			"quantity":     qty,
			"unit_price":   price,
			"line_total":   lineTotal,
		}
	}

	orderTotal = roundPrice(orderTotal)
	createdAt := deterministicTimestamp(rng)
	updatedAt := deterministicTimestamp(rng)

	// Shipping address
	address := map[string]interface{}{
		"street":  fmt.Sprintf("%d %s", rng.Intn(9999)+1, streetNames[rng.Intn(len(streetNames))]),
		"city":    cityNames[rng.Intn(len(cityNames))],
		"state":   stateNames[rng.Intn(len(stateNames))],
		"zip":     fmt.Sprintf("%05d", rng.Intn(99999)+1),
		"country": "US",
	}

	order := map[string]interface{}{
		"id":               fmt.Sprintf("ord_%06d", idx),
		"user_id":          fmt.Sprintf("usr_%06d", userIdx),
		"status":           status,
		"items":            items,
		"total":            orderTotal,
		"currency":         currency,
		"shipping_address": address,
		"created_at":       createdAt,
		"updated_at":       updatedAt,
	}

	// Add tracking info for detailed view
	if detailed {
		trackingRng := pathSeed(fmt.Sprintf("tracking-%d", idx))
		tracking := map[string]interface{}{
			"carrier":         []string{"USPS", "UPS", "FedEx", "DHL"}[trackingRng.Intn(4)],
			"tracking_number": fmt.Sprintf("1Z%s", strings.ToUpper(randHexDet(trackingRng, 10))),
			"estimated_delivery": time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC).
				AddDate(0, 0, trackingRng.Intn(14)+1).Format("2006-01-02"),
		}

		if status == "shipped" || status == "delivered" {
			events := []map[string]interface{}{
				{"status": "label_created", "timestamp": createdAt, "location": "Origin Facility"},
				{"status": "picked_up", "timestamp": deterministicTimestamp(trackingRng), "location": "Distribution Center"},
				{"status": "in_transit", "timestamp": deterministicTimestamp(trackingRng), "location": cityNames[trackingRng.Intn(len(cityNames))]},
			}
			if status == "delivered" {
				events = append(events, map[string]interface{}{
					"status":    "delivered",
					"timestamp": deterministicTimestamp(trackingRng),
					"location":  fmt.Sprintf("%s, %s", cityNames[trackingRng.Intn(len(cityNames))], stateNames[trackingRng.Intn(len(stateNames))]),
				})
			}
			tracking["events"] = events
		}

		order["tracking"] = tracking

		// Also add order-level summary fields
		order["subtotal"] = orderTotal
		order["tax"] = roundPrice(orderTotal * 0.08)
		order["shipping_cost"] = roundPrice(float64(trackingRng.Intn(2000)+499) / 100.0)
		order["grand_total"] = roundPrice(orderTotal + order["tax"].(float64) + order["shipping_cost"].(float64))
	}

	return order
}

// ---- Helper functions ----

func generateDescription(rng *rand.Rand, name, category string) string {
	templates := []string{
		"The %s is a top-rated %s product designed for everyday use. Features premium build quality and exceptional performance.",
		"Introducing the %s — engineered for the modern consumer. This %s essential combines style with functionality.",
		"Discover the %s, our best-selling %s item. Built to last with industry-leading specifications.",
		"The %s delivers unmatched value in the %s category. Trusted by thousands of satisfied customers worldwide.",
		"Experience the %s — a revolutionary %s product that redefines what you expect from everyday gear.",
	}
	tmpl := templates[rng.Intn(len(templates))]
	return fmt.Sprintf(tmpl, name, category)
}

func reviewTitle(rng *rand.Rand, rating int) string {
	positive := []string{"Excellent product!", "Highly recommended", "Love it!", "Best purchase ever", "Exceeded expectations", "Great quality"}
	neutral := []string{"It's okay", "Decent for the price", "Average product", "Gets the job done"}
	negative := []string{"Disappointed", "Not worth it", "Poor quality", "Would not buy again", "Needs improvement"}
	switch {
	case rating >= 4:
		return positive[rng.Intn(len(positive))]
	case rating == 3:
		return neutral[rng.Intn(len(neutral))]
	default:
		return negative[rng.Intn(len(negative))]
	}
}

func reviewBody(rng *rand.Rand, rating int) string {
	positive := []string{
		"This product has been amazing. Build quality is superb and it works exactly as described.",
		"I've been using this for weeks now and I'm very impressed. Would definitely recommend to others.",
		"Fantastic value for money. The features are well thought out and the design is beautiful.",
	}
	neutral := []string{
		"It does what it says but nothing extraordinary. Packaging was fine, delivery was on time.",
		"Average product overall. Some features are nice but there's room for improvement.",
	}
	negative := []string{
		"Unfortunately this didn't meet my expectations. The build quality feels cheap and flimsy.",
		"I had high hopes but was let down. Returned it after a week of use.",
	}
	switch {
	case rating >= 4:
		return positive[rng.Intn(len(positive))]
	case rating == 3:
		return neutral[rng.Intn(len(neutral))]
	default:
		return negative[rng.Intn(len(negative))]
	}
}

func roundPrice(v float64) float64 {
	return float64(int(v*100+0.5)) / 100.0
}

func roundRating(v float64) float64 {
	return float64(int(v*10+0.5)) / 10.0
}

// randHexDet generates a deterministic hex string from the given rng.
func randHexDet(rng *rand.Rand, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = "0123456789abcdef"[rng.Intn(16)]
	}
	return string(b)
}
