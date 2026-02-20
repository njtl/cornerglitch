package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// --- Word banks for deterministic content generation ---

var blogTitlePrefixes = []string{
	"The Ultimate Guide to", "Understanding", "How to Master",
	"Why You Should Consider", "10 Ways to Improve",
	"A Deep Dive Into", "The Future of", "Rethinking",
	"Building Better", "The Surprising Truth About",
	"What Nobody Tells You About", "An Introduction to",
	"Lessons Learned From", "Best Practices for",
	"The Complete Handbook on", "Demystifying",
	"Exploring the World of", "Getting Started With",
	"Advanced Techniques in", "The Rise of",
}

var blogTitleSubjects = []string{
	"Modern Web Development", "Cloud Architecture", "Data Engineering",
	"Machine Learning Pipelines", "Remote Work Culture",
	"Sustainable Living", "Personal Finance", "Microservices",
	"Container Orchestration", "Digital Wellness",
	"API Design Patterns", "Open Source Communities",
	"Product Management", "Creative Writing",
	"Urban Gardening", "Fitness Routines",
	"Travel Photography", "Mediterranean Cooking",
	"Renewable Energy", "Space Exploration",
	"Artificial Intelligence", "Blockchain Technology",
	"Cybersecurity Fundamentals", "Mobile App Development",
	"Startup Culture", "Mental Health Awareness",
	"Graphic Design Trends", "Competitive Sports Analytics",
	"Podcast Production", "Home Automation",
}

var excerptSentences = []string{
	"The landscape of modern technology continues to evolve at a rapid pace, reshaping how we approach everyday challenges.",
	"Industry experts have long debated the merits of this approach, and new evidence suggests a turning point.",
	"Organizations across the globe are investing heavily in these strategies to stay competitive.",
	"Research published this quarter highlights several overlooked factors that contribute to long-term success.",
	"Early adopters have reported significant improvements in both efficiency and overall satisfaction.",
	"This trend shows no signs of slowing down, with major players announcing ambitious new initiatives.",
	"Community-driven efforts have played a pivotal role in shaping the direction of recent advancements.",
	"A careful examination of the data reveals patterns that challenge conventional assumptions.",
	"Practitioners recommend starting with small, incremental changes before committing to a full overhaul.",
	"The intersection of creativity and technology has opened doors that were unimaginable a decade ago.",
	"What began as a niche experiment has grown into a mainstream movement embraced by millions.",
	"Balancing innovation with reliability remains the central challenge for teams working in this space.",
	"Feedback from real-world deployments provides invaluable insight into what actually works in practice.",
	"Cross-functional collaboration has emerged as a key driver behind the most successful outcomes.",
	"Understanding the underlying principles is essential for anyone looking to make meaningful progress.",
	"Several case studies demonstrate that patience and consistency outperform short bursts of effort.",
	"The broader implications extend well beyond the immediate use case, affecting adjacent fields as well.",
	"Transparency and open communication are repeatedly cited as foundational elements of high-performing teams.",
	"While skeptics remain vocal, the growing body of evidence is difficult to ignore.",
	"Accessibility and inclusivity have become non-negotiable requirements in modern implementations.",
}

var bodyParagraphs = []string{
	"The rapid evolution of technology has fundamentally changed how businesses operate and compete in the global marketplace. Companies that once relied on traditional methods are now embracing digital transformation as a core part of their strategy. This shift is not merely about adopting new tools; it represents a complete rethinking of how value is created, delivered, and captured. Leaders who recognize this distinction are better positioned to guide their organizations through the inevitable challenges that accompany large-scale change.",

	"Collaboration across disciplines has become essential for tackling the complex problems that define our era. Engineers work alongside designers, data scientists partner with domain experts, and product managers serve as the connective tissue that holds it all together. When these diverse perspectives come together with a shared purpose, the results consistently exceed what any single group could achieve alone. Building a culture that supports this kind of interdisciplinary work requires intentional effort and a willingness to break down long-standing silos.",

	"Data-driven decision making has moved from a competitive advantage to a basic expectation. Organizations that fail to collect, analyze, and act on relevant data risk falling behind their peers. However, the sheer volume of information available today presents its own challenges. The ability to distinguish signal from noise, to ask the right questions before seeking answers, and to maintain healthy skepticism about seemingly compelling numbers is what separates effective data practitioners from those who are merely going through the motions.",

	"User experience remains the most reliable differentiator in crowded markets. Products and services that anticipate needs, minimize friction, and deliver moments of genuine delight earn loyalty that no amount of marketing can replicate. The best teams invest heavily in research, prototype relentlessly, and treat every interaction as an opportunity to learn. They understand that great experience is not a feature to be added; it is the result of a deep and ongoing commitment to understanding the people they serve.",

	"Sustainability is no longer an afterthought or a box to check; it is a fundamental design constraint that shapes decisions at every level. From the energy consumed by data centers to the materials used in packaging, thoughtful organizations are examining their entire value chain through an environmental lens. The most encouraging aspect of this movement is the growing recognition that sustainability and profitability are not opposing forces. When approached creatively, environmental responsibility often leads to innovations that reduce costs and open new revenue streams.",

	"Security and privacy have emerged as foundational concerns that affect every aspect of modern systems. High-profile breaches and evolving regulations have elevated these topics from technical details to board-level priorities. Building secure systems requires more than implementing the right algorithms; it demands a culture of vigilance, regular training, and the humility to acknowledge that no defense is perfect. The organizations that handle this well tend to be the ones that treat security as a continuous process rather than a one-time project.",

	"The open source movement has demonstrated that cooperation can coexist with competition in powerful ways. Thousands of projects rely on code contributed by individuals and companies who understand that a rising tide lifts all boats. The ecosystem of shared libraries, frameworks, and tools has dramatically lowered the barrier to entry for new builders while simultaneously raising the quality of what gets built. Participation in this community is both a responsibility and a remarkable opportunity for growth.",

	"Scalability challenges often reveal themselves at the most inconvenient times, making proactive planning essential. Systems that work flawlessly for a hundred users may buckle under the weight of a thousand. Architects who think carefully about growth patterns, identify potential bottlenecks early, and design with flexibility in mind save their teams enormous amounts of reactive firefighting later. The goal is not to over-engineer for scenarios that may never materialize, but to make deliberate choices that keep future options open.",

	"Continuous learning has become a survival skill in fields where the half-life of knowledge is measured in months rather than years. Professionals who carve out dedicated time for exploration, experimentation, and reflection consistently outperform those who rely solely on what they already know. The most effective learners tend to share what they discover, creating a virtuous cycle that benefits their entire community. Investing in education, whether formal or informal, remains one of the highest-return activities available.",

	"Remote and distributed work has forced a reevaluation of assumptions about productivity, communication, and culture. Teams that once relied on physical proximity to coordinate have developed new rhythms and rituals that function across time zones and continents. While challenges remain, particularly around maintaining social connection and onboarding new members, the data consistently shows that distributed teams can match and often exceed the output of their co-located counterparts when given the right tools and support.",

	"Testing and quality assurance are investments that pay dividends long after the initial effort. Teams that write comprehensive tests, automate their verification pipelines, and treat quality as a shared responsibility rather than a separate phase produce more reliable software with fewer late-stage surprises. The discipline of writing tests also improves design by forcing developers to think carefully about interfaces, edge cases, and the assumptions embedded in their code.",

	"Effective communication is the skill that amplifies all other skills. A brilliant engineer who cannot explain their ideas clearly will struggle to have the impact they deserve. A visionary leader who fails to articulate the rationale behind difficult decisions will erode trust instead of building it. The best communicators adapt their message to their audience, choose clarity over cleverness, and understand that listening is at least as important as speaking.",
}

var authorFirstNames = []string{
	"Sarah", "James", "Maria", "David", "Emma",
	"Michael", "Olivia", "Daniel", "Sophia", "William",
	"Isabella", "Alexander", "Mia", "Benjamin", "Charlotte",
	"Lucas", "Amelia", "Henry", "Harper", "Ethan",
	"Nora", "Jacob", "Lily", "Samuel", "Chloe",
}

var authorLastNames = []string{
	"Chen", "Rodriguez", "Patel", "Nakamura", "Mueller",
	"Thompson", "Garcia", "Kim", "Johnson", "Williams",
	"Brown", "Taylor", "Anderson", "Lee", "Wilson",
	"Martinez", "Clark", "Lewis", "Walker", "Hall",
	"Young", "Allen", "King", "Wright", "Scott",
}

var categories = []string{
	"technology", "lifestyle", "business", "health", "travel",
	"food", "science", "culture", "design", "sports",
}

var tagNames = []string{
	"javascript", "python", "golang", "devops", "cloud",
	"react", "kubernetes", "docker", "agile", "testing",
	"frontend", "backend", "database", "security", "performance",
	"api", "microservices", "serverless", "monitoring", "automation",
	"ux-design", "accessibility", "mobile", "machine-learning", "data-science",
	"startups", "remote-work", "productivity", "career", "leadership",
	"open-source", "linux", "networking", "architecture", "documentation",
	"ci-cd", "git", "debugging", "refactoring", "mentoring",
	"wellness", "nutrition", "fitness", "mindfulness", "travel-tips",
	"photography", "writing", "cooking", "sustainability", "finance",
	"blockchain", "web3", "rust", "typescript", "graphql",
	"rest-api", "grpc", "websockets", "caching", "streaming",
	"ai-ethics", "deep-learning", "nlp", "computer-vision", "robotics",
	"podcasting", "video-editing", "game-dev", "vr-ar", "iot",
	"algorithms", "system-design", "distributed-systems", "observability", "resilience",
	"branding", "marketing", "seo", "content-strategy", "analytics",
	"parenting", "education", "history", "philosophy", "music",
	"gardening", "diy-projects", "home-improvement", "pets", "volunteering",
	"climate-change", "renewable-energy", "urban-planning", "public-health", "social-impact",
	"book-reviews", "film-criticism", "art", "theater", "fashion",
}

var pageTemplates = []string{"home", "about", "contact", "landing", "legal"}

var pageTitles = []string{
	"Home", "About Us", "Contact", "Privacy Policy", "Terms of Service",
	"Getting Started", "Features", "Pricing", "Careers", "Press Kit",
	"Blog", "Help Center", "API Documentation", "Status Page", "Partners",
	"Community", "Events", "Case Studies", "Testimonials", "FAQ",
	"Accessibility Statement", "Cookie Policy", "Sitemap", "Brand Guidelines", "Investor Relations",
	"Security", "Compliance", "Release Notes", "Roadmap", "Our Team",
	"Mission", "Values", "History", "Locations", "Newsroom",
	"Webinars", "Whitepapers", "Ebooks", "Tutorials", "Demos",
	"Enterprise", "Integrations", "Marketplace", "Affiliate Program", "Referral Program",
}

var mimeTypes = []string{
	"image/jpeg", "image/png", "image/webp", "image/gif", "image/svg+xml",
	"application/pdf", "video/mp4", "audio/mpeg",
}

var mediaExtensions = map[string]string{
	"image/jpeg":      ".jpg",
	"image/png":       ".png",
	"image/webp":      ".webp",
	"image/gif":       ".gif",
	"image/svg+xml":   ".svg",
	"application/pdf": ".pdf",
	"video/mp4":       ".mp4",
	"audio/mpeg":      ".mp3",
}

var mediaFilenameWords = []string{
	"hero", "banner", "thumbnail", "background", "profile",
	"logo", "icon", "illustration", "screenshot", "photo",
	"diagram", "chart", "infographic", "cover", "header",
	"feature", "product", "team", "office", "event",
	"landscape", "portrait", "abstract", "pattern", "texture",
}

var commentBodies = []string{
	"This is a really insightful article. I have been thinking about this topic for a while and your perspective adds a lot of clarity.",
	"Great write-up! I would love to see a follow-up that goes deeper into the implementation details.",
	"I respectfully disagree with some of the points made here. In my experience, the opposite tends to be true in large-scale deployments.",
	"Thanks for sharing this. I sent it to my entire team because it captures exactly what we have been discussing in our retrospectives.",
	"The section about scalability really resonated with me. We hit those exact same challenges last quarter.",
	"Bookmarked for future reference. This is one of the most comprehensive treatments of this subject I have come across.",
	"I wonder how this approach would work for smaller teams with limited resources. Any thoughts on adapting it for a startup context?",
	"Solid analysis. One thing I would add is the importance of measuring outcomes rather than just outputs.",
	"This changed how I think about the problem. Sometimes you need someone to reframe the question before the answer becomes obvious.",
	"Could you elaborate on the trade-offs mentioned in the third section? I think there is more nuance there than the article suggests.",
	"Excellent post. The real-world examples make the abstract concepts much more tangible and actionable.",
	"I have been in this field for over a decade and articles like this remind me why I still love what I do.",
	"The point about collaboration is spot on. We saw a massive improvement once we broke down the walls between our engineering and design teams.",
	"I appreciate the balanced perspective here. Too many articles in this space are overly optimistic without acknowledging the real difficulties.",
	"This would make a great conference talk. Have you considered submitting it to any upcoming events?",
}

var pageContentParagraphs = []string{
	"Welcome to our platform, where innovation meets reliability. We have been helping organizations transform their operations since our founding, and our commitment to excellence continues to drive everything we do.",
	"Our team of dedicated professionals brings decades of combined experience across multiple industries. We believe that the best solutions emerge from diverse perspectives working toward a common goal.",
	"We take your privacy seriously and are committed to protecting the personal information you share with us. This policy outlines how we collect, use, and safeguard your data.",
	"By using our services, you agree to these terms and conditions. Please read them carefully before proceeding, as they constitute a legally binding agreement between you and our organization.",
	"Get in touch with our team to discuss how we can help you achieve your goals. Whether you have a specific question or just want to explore possibilities, we are here to help.",
	"Our platform offers a comprehensive suite of tools designed to streamline your workflow and boost productivity. From project management to analytics, everything you need is in one place.",
	"We are proud to serve clients ranging from early-stage startups to Fortune 500 enterprises. Our flexible solutions adapt to your needs, growing alongside your organization.",
	"Accessibility is a core principle in everything we build. We are committed to ensuring that our products and services are usable by everyone, regardless of ability or circumstance.",
}

// CmsAPI handles Content Management System endpoints.
type CmsAPI struct{}

// NewCmsAPI creates a new CMS API handler.
func NewCmsAPI() *CmsAPI {
	return &CmsAPI{}
}

// ServeHTTP dispatches CMS API requests.
func (c *CmsAPI) ServeHTTP(w http.ResponseWriter, r *http.Request, apiPath string) int {
	if r.Method == http.MethodOptions {
		return handleOptions(w)
	}

	switch {
	case strings.HasPrefix(apiPath, "/v1/posts"):
		return c.handlePosts(w, r, apiPath)
	case strings.HasPrefix(apiPath, "/v1/pages"):
		return c.handlePages(w, r, apiPath)
	case strings.HasPrefix(apiPath, "/v1/media"):
		return c.handleMedia(w, r, apiPath)
	case strings.HasPrefix(apiPath, "/v1/tags"):
		return c.handleTags(w, r, apiPath)
	}

	writeJSON(w, http.StatusNotFound, map[string]interface{}{
		"error":   "not_found",
		"message": "Unknown CMS endpoint",
	})
	return http.StatusNotFound
}

// --- Posts ---

func (c *CmsAPI) handlePosts(w http.ResponseWriter, r *http.Request, apiPath string) int {
	id := extractID(apiPath, "/v1/posts")

	// Collection endpoints
	if id == "" {
		switch r.Method {
		case http.MethodGet:
			return c.listPosts(w, r)
		case http.MethodPost:
			return c.createPost(w, r)
		default:
			return methodNotAllowed(w, "GET, POST, OPTIONS")
		}
	}

	// Sub-resource: comments
	sub := subResource(apiPath, "/v1/posts")
	if sub == "comments" {
		if r.Method == http.MethodGet {
			return c.listPostComments(w, r, id)
		}
		return methodNotAllowed(w, "GET, OPTIONS")
	}

	// Single post endpoints
	switch r.Method {
	case http.MethodGet:
		return c.getPost(w, r, id)
	case http.MethodPut:
		return c.updatePost(w, r, id)
	case http.MethodDelete:
		return c.deletePost(w, r, id)
	default:
		return methodNotAllowed(w, "GET, PUT, DELETE, OPTIONS")
	}
}

func (c *CmsAPI) listPosts(w http.ResponseWriter, r *http.Request) int {
	const totalPosts = 890

	page, perPage := parsePagination(r)

	// Build filtered set of posts
	filterCategory := r.URL.Query().Get("category")
	filterTag := r.URL.Query().Get("tag")
	filterStatus := r.URL.Query().Get("status")
	filterAuthor := r.URL.Query().Get("author")

	// Generate all posts deterministically, apply filters
	var filtered []map[string]interface{}
	for i := 1; i <= totalPosts; i++ {
		post := c.generatePostSummary(i)
		if filterCategory != "" && post["category"] != filterCategory {
			continue
		}
		if filterTag != "" {
			tags := post["tags"].([]string)
			found := false
			for _, t := range tags {
				if t == filterTag {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		if filterStatus != "" && post["status"] != filterStatus {
			continue
		}
		if filterAuthor != "" {
			author := post["author"].(map[string]interface{})
			if author["id"] != filterAuthor && author["name"] != filterAuthor {
				continue
			}
		}
		filtered = append(filtered, post)
	}

	total := len(filtered)
	w.Header().Set("X-Total-Count", strconv.Itoa(total))

	// Paginate
	start := (page - 1) * perPage
	if start > total {
		start = total
	}
	end := start + perPage
	if end > total {
		end = total
	}

	items := filtered[start:end]
	if items == nil {
		items = []map[string]interface{}{}
	}

	paginatedJSON(w, r, items, total)
	return http.StatusOK
}

func (c *CmsAPI) generatePostSummary(index int) map[string]interface{} {
	rng := pathSeed(fmt.Sprintf("cms-post-%d", index))

	id := deterministicUUID(rng)

	titlePrefix := blogTitlePrefixes[rng.Intn(len(blogTitlePrefixes))]
	titleSubject := blogTitleSubjects[rng.Intn(len(blogTitleSubjects))]
	title := titlePrefix + " " + titleSubject

	slug := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(title, " ", "-"), "'", ""))
	slug = strings.ToLower(slug)

	// Excerpt: 3-5 sentences
	numSentences := 3 + rng.Intn(3)
	var excerptParts []string
	for s := 0; s < numSentences; s++ {
		excerptParts = append(excerptParts, excerptSentences[rng.Intn(len(excerptSentences))])
	}
	excerpt := strings.Join(excerptParts, " ")

	// Author
	firstName := authorFirstNames[rng.Intn(len(authorFirstNames))]
	lastName := authorLastNames[rng.Intn(len(authorLastNames))]
	authorName := firstName + " " + lastName
	authorID := deterministicUUID(rng)

	// Category and tags
	category := categories[rng.Intn(len(categories))]
	numTags := 2 + rng.Intn(4)
	tagSet := make(map[string]bool)
	var tags []string
	for len(tags) < numTags {
		t := tagNames[rng.Intn(len(tagNames))]
		if !tagSet[t] {
			tagSet[t] = true
			tags = append(tags, t)
		}
	}

	// Status
	statusRoll := rng.Float64()
	var status string
	switch {
	case statusRoll < 0.80:
		status = "published"
	case statusRoll < 0.92:
		status = "draft"
	default:
		status = "archived"
	}

	wordCount := 800 + rng.Intn(2200)
	readTime := (wordCount + 249) / 250

	publishedAt := deterministicTimestamp(rng)
	updatedAt := deterministicTimestamp(rng)

	return map[string]interface{}{
		"id":    id,
		"title": title,
		"slug":  slug,
		"excerpt": excerpt,
		"author": map[string]interface{}{
			"id":         authorID,
			"name":       authorName,
			"avatar_url": fmt.Sprintf("https://avatars.example.com/%s.jpg", strings.ToLower(firstName+lastName)),
		},
		"category":          category,
		"tags":              tags,
		"status":            status,
		"featured_image":    fmt.Sprintf("https://images.example.com/posts/%d/featured.jpg", index),
		"word_count":        wordCount,
		"read_time_minutes": readTime,
		"published_at":      publishedAt,
		"updated_at":        updatedAt,
	}
}

func (c *CmsAPI) getPost(w http.ResponseWriter, r *http.Request, id string) int {
	// Derive a stable index from the ID
	rng := pathSeed("cms-post-detail-" + id)
	index := 1 + rng.Intn(890)

	post := c.generatePostSummary(index)
	// Override ID to match the requested one
	post["id"] = id

	// Add full body: 3-5 paragraphs
	bodyRng := pathSeed("cms-post-body-" + id)
	numParagraphs := 3 + bodyRng.Intn(3)
	var paragraphs []string
	used := make(map[int]bool)
	for len(paragraphs) < numParagraphs {
		idx := bodyRng.Intn(len(bodyParagraphs))
		if !used[idx] {
			used[idx] = true
			paragraphs = append(paragraphs, bodyParagraphs[idx])
		}
	}
	post["body"] = strings.Join(paragraphs, "\n\n")

	// Additional detail fields
	post["comments_count"] = bodyRng.Intn(150)
	post["likes_count"] = bodyRng.Intn(500)
	post["share_count"] = bodyRng.Intn(200)
	post["seo_meta"] = map[string]interface{}{
		"meta_title":       post["title"],
		"meta_description": post["excerpt"],
		"og_image":         post["featured_image"],
		"canonical_url":    fmt.Sprintf("https://blog.example.com/%s", post["slug"]),
		"robots":           "index, follow",
		"structured_data": map[string]interface{}{
			"@type":         "BlogPosting",
			"headline":      post["title"],
			"datePublished": post["published_at"],
			"dateModified":  post["updated_at"],
		},
	}

	writeJSON(w, http.StatusOK, post)
	return http.StatusOK
}

func (c *CmsAPI) createPost(w http.ResponseWriter, r *http.Request) int {
	rng := pathSeed("cms-create-post-" + r.URL.RawQuery + r.RemoteAddr)
	newID := deterministicUUID(rng)

	resp := map[string]interface{}{
		"id":         newID,
		"status":     "draft",
		"message":    "Post created successfully",
		"created_at": deterministicTimestamp(rng),
	}

	w.Header().Set("Location", fmt.Sprintf("/api/v1/posts/%s", newID))
	writeJSON(w, http.StatusCreated, resp)
	return http.StatusCreated
}

func (c *CmsAPI) updatePost(w http.ResponseWriter, r *http.Request, id string) int {
	rng := pathSeed("cms-update-post-" + id)

	resp := map[string]interface{}{
		"id":         id,
		"message":    "Post updated successfully",
		"updated_at": deterministicTimestamp(rng),
	}

	writeJSON(w, http.StatusOK, resp)
	return http.StatusOK
}

func (c *CmsAPI) deletePost(w http.ResponseWriter, r *http.Request, id string) int {
	addCommonHeaders(w)
	w.WriteHeader(http.StatusNoContent)
	return http.StatusNoContent
}

func (c *CmsAPI) listPostComments(w http.ResponseWriter, r *http.Request, postID string) int {
	const commentsPerPost = 47 // reasonable upper bound per post, varies

	rng := pathSeed("cms-comments-" + postID)
	total := 5 + rng.Intn(commentsPerPost)

	page, perPage := parsePagination(r)

	w.Header().Set("X-Total-Count", strconv.Itoa(total))

	start := (page - 1) * perPage
	if start > total {
		start = total
	}
	end := start + perPage
	if end > total {
		end = total
	}

	var comments []map[string]interface{}
	for i := start; i < end; i++ {
		cRng := pathSeed(fmt.Sprintf("cms-comment-%s-%d", postID, i))
		firstName := authorFirstNames[cRng.Intn(len(authorFirstNames))]
		lastName := authorLastNames[cRng.Intn(len(authorLastNames))]
		authorName := firstName + " " + lastName

		comments = append(comments, map[string]interface{}{
			"id":           deterministicUUID(cRng),
			"author_name":  authorName,
			"author_email": deterministicEmail(cRng, authorName),
			"body":         commentBodies[cRng.Intn(len(commentBodies))],
			"created_at":   deterministicTimestamp(cRng),
			"likes":        cRng.Intn(50),
		})
	}

	if comments == nil {
		comments = []map[string]interface{}{}
	}

	paginatedJSON(w, r, comments, total)
	return http.StatusOK
}

// --- Pages ---

func (c *CmsAPI) handlePages(w http.ResponseWriter, r *http.Request, apiPath string) int {
	id := extractID(apiPath, "/v1/pages")

	if id == "" {
		if r.Method == http.MethodGet {
			return c.listPages(w, r)
		}
		return methodNotAllowed(w, "GET, OPTIONS")
	}

	if r.Method == http.MethodGet {
		return c.getPage(w, r, id)
	}
	return methodNotAllowed(w, "GET, OPTIONS")
}

func (c *CmsAPI) listPages(w http.ResponseWriter, r *http.Request) int {
	const totalPages = 45

	page, perPage := parsePagination(r)

	w.Header().Set("X-Total-Count", strconv.Itoa(totalPages))

	start := (page - 1) * perPage
	if start > totalPages {
		start = totalPages
	}
	end := start + perPage
	if end > totalPages {
		end = totalPages
	}

	var pages []map[string]interface{}
	for i := start; i < end; i++ {
		pages = append(pages, c.generatePageSummary(i+1))
	}

	if pages == nil {
		pages = []map[string]interface{}{}
	}

	paginatedJSON(w, r, pages, totalPages)
	return http.StatusOK
}

func (c *CmsAPI) generatePageSummary(index int) map[string]interface{} {
	rng := pathSeed(fmt.Sprintf("cms-page-%d", index))

	id := deterministicUUID(rng)

	title := pageTitles[rng.Intn(len(pageTitles))]
	slug := strings.ToLower(strings.ReplaceAll(title, " ", "-"))

	template := pageTemplates[rng.Intn(len(pageTemplates))]

	statusRoll := rng.Float64()
	var status string
	if statusRoll < 0.85 {
		status = "published"
	} else {
		status = "draft"
	}

	// Some pages have parents
	var parentID interface{}
	if rng.Float64() < 0.3 && index > 3 {
		parentRng := pathSeed(fmt.Sprintf("cms-page-%d", 1+rng.Intn(index-1)))
		parentID = deterministicUUID(parentRng)
	}

	return map[string]interface{}{
		"id":         id,
		"title":      title,
		"slug":       slug,
		"template":   template,
		"status":     status,
		"parent_id":  parentID,
		"order":      rng.Intn(100),
		"created_at": deterministicTimestamp(rng),
	}
}

func (c *CmsAPI) getPage(w http.ResponseWriter, r *http.Request, id string) int {
	rng := pathSeed("cms-page-detail-" + id)
	index := 1 + rng.Intn(45)

	pg := c.generatePageSummary(index)
	pg["id"] = id

	// Add full content
	contentRng := pathSeed("cms-page-content-" + id)
	numParagraphs := 2 + contentRng.Intn(4)
	var paragraphs []string
	for p := 0; p < numParagraphs; p++ {
		paragraphs = append(paragraphs, pageContentParagraphs[contentRng.Intn(len(pageContentParagraphs))])
	}
	pg["content"] = strings.Join(paragraphs, "\n\n")
	pg["updated_at"] = deterministicTimestamp(contentRng)
	pg["meta_title"] = pg["title"]
	pg["meta_description"] = paragraphs[0][:minInt(160, len(paragraphs[0]))]

	writeJSON(w, http.StatusOK, pg)
	return http.StatusOK
}

// --- Media ---

func (c *CmsAPI) handleMedia(w http.ResponseWriter, r *http.Request, apiPath string) int {
	id := extractID(apiPath, "/v1/media")

	if id == "" {
		switch r.Method {
		case http.MethodGet:
			return c.listMedia(w, r)
		case http.MethodPost:
			return c.uploadMedia(w, r)
		default:
			return methodNotAllowed(w, "GET, POST, OPTIONS")
		}
	}

	if r.Method == http.MethodGet {
		return c.getMedia(w, r, id)
	}
	return methodNotAllowed(w, "GET, OPTIONS")
}

func (c *CmsAPI) listMedia(w http.ResponseWriter, r *http.Request) int {
	const totalMedia = 620

	page, perPage := parsePagination(r)

	w.Header().Set("X-Total-Count", strconv.Itoa(totalMedia))

	start := (page - 1) * perPage
	if start > totalMedia {
		start = totalMedia
	}
	end := start + perPage
	if end > totalMedia {
		end = totalMedia
	}

	var items []map[string]interface{}
	for i := start; i < end; i++ {
		items = append(items, c.generateMediaSummary(i+1))
	}

	if items == nil {
		items = []map[string]interface{}{}
	}

	paginatedJSON(w, r, items, totalMedia)
	return http.StatusOK
}

func (c *CmsAPI) generateMediaSummary(index int) map[string]interface{} {
	rng := pathSeed(fmt.Sprintf("cms-media-%d", index))

	id := deterministicUUID(rng)
	mimeType := mimeTypes[rng.Intn(len(mimeTypes))]
	ext := mediaExtensions[mimeType]

	word1 := mediaFilenameWords[rng.Intn(len(mediaFilenameWords))]
	word2 := mediaFilenameWords[rng.Intn(len(mediaFilenameWords))]
	filename := fmt.Sprintf("%s-%s-%04d%s", word1, word2, index, ext)

	var width, height int
	if strings.HasPrefix(mimeType, "image/") {
		widths := []int{640, 800, 1024, 1280, 1920, 2560}
		heights := []int{480, 600, 768, 720, 1080, 1440}
		dimIdx := rng.Intn(len(widths))
		width = widths[dimIdx]
		height = heights[dimIdx]
	}

	uploaderFirst := authorFirstNames[rng.Intn(len(authorFirstNames))]
	uploaderLast := authorLastNames[rng.Intn(len(authorLastNames))]

	altWords := []string{
		"A detailed view of", "Close-up photograph showing", "Illustration depicting",
		"Screenshot of", "Diagram explaining", "Photo of",
		"Banner image for", "Artistic rendering of", "High-resolution capture of",
	}
	altSubjects := []string{
		"the project dashboard", "a mountain landscape at sunset",
		"team collaboration in progress", "modern architecture details",
		"fresh ingredients on a cutting board", "a code editor with syntax highlighting",
		"an analytics chart with growth trends", "a peaceful garden scene",
		"abstract geometric patterns", "a bustling city street at night",
	}
	altText := altWords[rng.Intn(len(altWords))] + " " + altSubjects[rng.Intn(len(altSubjects))]

	media := map[string]interface{}{
		"id":          id,
		"filename":    filename,
		"url":         fmt.Sprintf("https://cdn.example.com/media/%s", filename),
		"mime_type":   mimeType,
		"size_bytes":  50000 + rng.Intn(9950000), // 50KB to ~10MB
		"alt_text":    altText,
		"uploaded_by": uploaderFirst + " " + uploaderLast,
		"uploaded_at": deterministicTimestamp(rng),
	}

	if width > 0 {
		media["width"] = width
		media["height"] = height
	}

	return media
}

func (c *CmsAPI) getMedia(w http.ResponseWriter, r *http.Request, id string) int {
	rng := pathSeed("cms-media-detail-" + id)
	index := 1 + rng.Intn(620)

	media := c.generateMediaSummary(index)
	media["id"] = id

	// Add variants if it is an image
	mimeType := media["mime_type"].(string)
	if strings.HasPrefix(mimeType, "image/") {
		filename := media["filename"].(string)
		baseName := strings.TrimSuffix(filename, filepath(filename))
		ext := filepath(filename)

		media["variants"] = map[string]interface{}{
			"thumbnail": map[string]interface{}{
				"url":    fmt.Sprintf("https://cdn.example.com/media/thumb/%s_thumb%s", baseName, ext),
				"width":  150,
				"height": 150,
			},
			"medium": map[string]interface{}{
				"url":    fmt.Sprintf("https://cdn.example.com/media/medium/%s_medium%s", baseName, ext),
				"width":  800,
				"height": 600,
			},
			"large": map[string]interface{}{
				"url":    fmt.Sprintf("https://cdn.example.com/media/large/%s_large%s", baseName, ext),
				"width":  1920,
				"height": 1080,
			},
		}
	} else {
		media["variants"] = nil
	}

	// Additional metadata
	detailRng := pathSeed("cms-media-meta-" + id)
	media["downloads"] = detailRng.Intn(5000)
	media["used_in_posts"] = detailRng.Intn(15)
	media["created_at"] = media["uploaded_at"]

	writeJSON(w, http.StatusOK, media)
	return http.StatusOK
}

// filepath returns the extension of a filename, including the dot.
func filepath(name string) string {
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '.' {
			return name[i:]
		}
	}
	return ""
}

func (c *CmsAPI) uploadMedia(w http.ResponseWriter, r *http.Request) int {
	rng := pathSeed("cms-upload-media-" + r.URL.RawQuery + r.RemoteAddr)
	newID := deterministicUUID(rng)

	resp := map[string]interface{}{
		"id":          newID,
		"message":     "Media uploaded successfully",
		"url":         fmt.Sprintf("https://cdn.example.com/media/upload-%s.jpg", newID[:8]),
		"uploaded_at": deterministicTimestamp(rng),
	}

	w.Header().Set("Location", fmt.Sprintf("/api/v1/media/%s", newID))
	writeJSON(w, http.StatusCreated, resp)
	return http.StatusCreated
}

// --- Tags ---

func (c *CmsAPI) handleTags(w http.ResponseWriter, r *http.Request, apiPath string) int {
	if r.Method != http.MethodGet {
		return methodNotAllowed(w, "GET, OPTIONS")
	}

	return c.listTags(w, r)
}

func (c *CmsAPI) listTags(w http.ResponseWriter, r *http.Request) int {
	const totalTags = 100

	page, perPage := parsePagination(r)

	w.Header().Set("X-Total-Count", strconv.Itoa(totalTags))

	start := (page - 1) * perPage
	if start > totalTags {
		start = totalTags
	}
	end := start + perPage
	if end > totalTags {
		end = totalTags
	}

	var tags []map[string]interface{}
	for i := start; i < end; i++ {
		rng := pathSeed(fmt.Sprintf("cms-tag-%d", i))
		name := tagNames[i%len(tagNames)]
		tags = append(tags, map[string]interface{}{
			"id":         deterministicUUID(rng),
			"name":       name,
			"slug":       name,
			"post_count": 5 + rng.Intn(85),
		})
	}

	if tags == nil {
		tags = []map[string]interface{}{}
	}

	paginatedJSON(w, r, tags, totalTags)
	return http.StatusOK
}

// --- Helpers ---

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
