package content

import (
	"math/rand"
	"strings"
)

// TopicVocab holds vocabulary for a specific topic or as a generic fallback.
type TopicVocab struct {
	Titles     []string
	Adjectives []string
	Nouns      []string
	Verbs      []string
	Templates  []string
}

// NameBank holds first and last name pools for generating realistic person names.
type NameBank struct {
	First []string
	Last  []string
}

// WordBank provides rich vocabularies for generating realistic-looking web pages.
// Each topic maps to a URL path segment and carries its own set of titles,
// adjectives, nouns, verbs, and sentence templates.
type WordBank struct {
	topics           map[string]*TopicVocab
	generic          *TopicVocab
	names            *NameBank
	companies        []string
	jobTitles        []string
	cities           []string
	sections         []string
	ctas             []string
	navLabels        []string
	testimonials     []string
	footerTexts      []string
	metaDescriptions []string

	// Exported convenience fields used by elements.go for direct slice access.
	FirstNames []string
	LastNames  []string
	Companies  []string
	JobTitles  []string
	Adjectives []string
	Nouns      []string
	Verbs      []string
	Topics     []string
	Buzzwords  []string
	LoremWords []string
}

// genericSegments are path segments that should be skipped when resolving topic.
var genericSegments = map[string]bool{
	"page": true, "site": true, "web": true, "app": true,
	"view": true, "content": true, "section": true, "category": true,
	"index": true, "home": true, "main": true, "default": true,
}

// NewWordBank initializes and returns a fully populated WordBank.
func NewWordBank() *WordBank {
	wb := &WordBank{
		topics: make(map[string]*TopicVocab),
	}

	wb.initMarketing()
	wb.initTechnology()
	wb.initHealth()
	wb.initFinance()
	wb.initEducation()
	wb.initTravel()
	wb.initFood()
	wb.initSports()
	wb.initFashion()
	wb.initRealEstate()
	wb.initAutomotive()
	wb.initEntertainment()
	wb.initGeneric()
	wb.initNames()
	wb.initCompanies()
	wb.initJobTitles()
	wb.initCities()
	wb.initSections()
	wb.initCTAs()
	wb.initNavLabels()
	wb.initTestimonials()
	wb.initFooterTexts()
	wb.initMetaDescriptions()
	wb.initExportedFields()

	return wb
}

// TopicFor extracts the first meaningful segment from a URL path and returns
// the matching topic vocabulary. If the first segment is generic (like "page"
// or "site"), the second segment is tried. Falls back to generic vocab.
func (wb *WordBank) TopicFor(path string) *TopicVocab {
	path = strings.TrimPrefix(path, "/")
	segments := strings.Split(path, "/")

	for _, seg := range segments {
		seg = strings.ToLower(strings.TrimSpace(seg))
		if seg == "" {
			continue
		}
		if genericSegments[seg] {
			continue
		}
		if vocab, ok := wb.topics[seg]; ok {
			return vocab
		}
		// Only try the first two meaningful segments.
		break
	}

	return wb.generic
}

// RandName returns a random "First Last" name.
func (wb *WordBank) RandName(rng *rand.Rand) string {
	first := wb.names.First[rng.Intn(len(wb.names.First))]
	last := wb.names.Last[rng.Intn(len(wb.names.Last))]
	return first + " " + last
}

// RandCompany returns a random company name.
func (wb *WordBank) RandCompany(rng *rand.Rand) string {
	return wb.companies[rng.Intn(len(wb.companies))]
}

// RandJobTitle returns a random job title.
func (wb *WordBank) RandJobTitle(rng *rand.Rand) string {
	return wb.jobTitles[rng.Intn(len(wb.jobTitles))]
}

// RandCity returns a random city name.
func (wb *WordBank) RandCity(rng *rand.Rand) string {
	return wb.cities[rng.Intn(len(wb.cities))]
}

// RandSection returns a random page section title.
func (wb *WordBank) RandSection(rng *rand.Rand) string {
	return wb.sections[rng.Intn(len(wb.sections))]
}

// RandCTA returns a random call-to-action text.
func (wb *WordBank) RandCTA(rng *rand.Rand) string {
	return wb.ctas[rng.Intn(len(wb.ctas))]
}

// RandNavLabels returns n unique navigation labels in random order.
// If n exceeds the available labels, all labels are returned shuffled.
func (wb *WordBank) RandNavLabels(rng *rand.Rand, n int) []string {
	if n >= len(wb.navLabels) {
		out := make([]string, len(wb.navLabels))
		copy(out, wb.navLabels)
		rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
		return out
	}

	// Fisher-Yates partial shuffle to pick n unique labels.
	indices := make([]int, len(wb.navLabels))
	for i := range indices {
		indices[i] = i
	}
	out := make([]string, n)
	for i := 0; i < n; i++ {
		j := i + rng.Intn(len(indices)-i)
		indices[i], indices[j] = indices[j], indices[i]
		out[i] = wb.navLabels[indices[i]]
	}
	return out
}

// RandTestimonial returns a random testimonial template.
func (wb *WordBank) RandTestimonial(rng *rand.Rand) string {
	return wb.testimonials[rng.Intn(len(wb.testimonials))]
}

// RandFooterText returns a random footer text snippet.
func (wb *WordBank) RandFooterText(rng *rand.Rand) string {
	return wb.footerTexts[rng.Intn(len(wb.footerTexts))]
}

// RandMetaDescription returns a random meta description template.
func (wb *WordBank) RandMetaDescription(rng *rand.Rand) string {
	return wb.metaDescriptions[rng.Intn(len(wb.metaDescriptions))]
}

// GenerateSentence fills a random template from the given vocabulary.
// Templates use placeholders: {adj}, {noun}, {verb}, {title}.
func (wb *WordBank) GenerateSentence(rng *rand.Rand, vocab *TopicVocab) string {
	if len(vocab.Templates) == 0 {
		return ""
	}
	tmpl := vocab.Templates[rng.Intn(len(vocab.Templates))]
	return wb.fillTemplate(rng, tmpl, vocab)
}

// GenerateParagraph generates a paragraph of the specified number of sentences.
func (wb *WordBank) GenerateParagraph(rng *rand.Rand, vocab *TopicVocab, sentences int) string {
	if sentences <= 0 {
		sentences = 3
	}
	parts := make([]string, sentences)
	for i := range parts {
		parts[i] = wb.GenerateSentence(rng, vocab)
	}
	return strings.Join(parts, " ")
}

// fillTemplate replaces placeholders in a template string with random words.
func (wb *WordBank) fillTemplate(rng *rand.Rand, tmpl string, vocab *TopicVocab) string {
	s := tmpl

	for strings.Contains(s, "{adj}") {
		adj := vocab.Adjectives[rng.Intn(len(vocab.Adjectives))]
		s = strings.Replace(s, "{adj}", adj, 1)
	}
	for strings.Contains(s, "{noun}") {
		noun := vocab.Nouns[rng.Intn(len(vocab.Nouns))]
		s = strings.Replace(s, "{noun}", noun, 1)
	}
	for strings.Contains(s, "{verb}") {
		verb := vocab.Verbs[rng.Intn(len(vocab.Verbs))]
		s = strings.Replace(s, "{verb}", verb, 1)
	}
	for strings.Contains(s, "{title}") {
		title := vocab.Titles[rng.Intn(len(vocab.Titles))]
		s = strings.Replace(s, "{title}", title, 1)
	}
	for strings.Contains(s, "{name}") {
		name := wb.RandName(rng)
		s = strings.Replace(s, "{name}", name, 1)
	}
	for strings.Contains(s, "{company}") {
		company := wb.RandCompany(rng)
		s = strings.Replace(s, "{company}", company, 1)
	}
	for strings.Contains(s, "{city}") {
		city := wb.RandCity(rng)
		s = strings.Replace(s, "{city}", city, 1)
	}

	return s
}

// Sentence generates a random sentence from the LoremWords pool.
func (wb *WordBank) Sentence(rng *rand.Rand, minWords, maxWords int) string {
	n := rng.Intn(maxWords-minWords+1) + minWords
	words := make([]string, n)
	for i := range words {
		words[i] = wb.LoremWords[rng.Intn(len(wb.LoremWords))]
	}
	words[0] = strings.ToUpper(words[0][:1]) + words[0][1:]
	return strings.Join(words, " ") + "."
}

// Paragraph generates a paragraph with the given number of sentences.
func (wb *WordBank) Paragraph(rng *rand.Rand, sentences int) string {
	parts := make([]string, sentences)
	for i := range parts {
		parts[i] = wb.Sentence(rng, 6, 14)
	}
	return strings.Join(parts, " ")
}

// initExportedFields populates the exported convenience fields from internal data.
func (wb *WordBank) initExportedFields() {
	wb.FirstNames = wb.names.First
	wb.LastNames = wb.names.Last
	wb.Companies = wb.companies
	wb.JobTitles = wb.jobTitles
	wb.Adjectives = wb.generic.Adjectives
	wb.Nouns = wb.generic.Nouns
	wb.Verbs = wb.generic.Verbs

	// Collect topic names
	wb.Topics = make([]string, 0, len(wb.topics))
	for name := range wb.topics {
		wb.Topics = append(wb.Topics, name)
	}

	wb.Buzzwords = []string{
		"AI-powered", "blockchain-enabled", "zero-trust", "serverless",
		"event-driven", "containerized", "cloud-first", "API-first",
		"mobile-first", "privacy-focused", "open-source", "low-latency",
		"fault-tolerant", "horizontally-scalable", "multi-tenant",
	}

	wb.LoremWords = []string{
		"lorem", "ipsum", "dolor", "sit", "amet", "consectetur", "adipiscing",
		"elit", "sed", "do", "eiusmod", "tempor", "incididunt", "ut", "labore",
		"et", "dolore", "magna", "aliqua", "enim", "ad", "minim", "veniam",
		"quis", "nostrud", "exercitation", "ullamco", "laboris", "nisi",
		"aliquip", "ex", "ea", "commodo", "consequat", "duis", "aute", "irure",
		"in", "reprehenderit", "voluptate", "velit", "esse", "cillum", "fugiat",
		"nulla", "pariatur", "excepteur", "sint", "occaecat", "cupidatat",
	}
}

// ---------------------------------------------------------------------------
// Topic initializers
// ---------------------------------------------------------------------------

func (wb *WordBank) initMarketing() {
	wb.topics["marketing"] = &TopicVocab{
		Titles: []string{
			"The Ultimate Guide to Digital Marketing",
			"How to Build a Brand That Lasts",
			"Content Marketing Strategies for Growth",
			"Mastering Social Media Engagement",
			"SEO Best Practices for Modern Businesses",
			"Email Marketing: From Open Rates to Conversions",
			"The Future of Influencer Marketing",
			"Data-Driven Marketing Campaigns",
			"Building Customer Loyalty Through Storytelling",
			"Growth Hacking Techniques That Actually Work",
			"Understanding Your Target Audience",
			"Marketing Automation Done Right",
			"The Power of Video Marketing",
		},
		Adjectives: []string{
			"viral", "engaging", "data-driven", "personalized", "omnichannel",
			"targeted", "scalable", "authentic", "compelling", "measurable",
			"strategic", "organic", "paid", "integrated", "dynamic",
			"customer-centric", "high-converting", "innovative", "actionable",
		},
		Nouns: []string{
			"campaign", "audience", "conversion", "funnel", "brand",
			"engagement", "analytics", "reach", "impression", "click-through",
			"lead", "retention", "segmentation", "persona", "touchpoint",
			"awareness", "ROI", "landing page", "newsletter", "influencer",
		},
		Verbs: []string{
			"optimize", "engage", "convert", "segment", "target",
			"amplify", "personalize", "automate", "measure", "scale",
			"nurture", "launch", "A/B test", "retarget",
		},
		Templates: []string{
			"Our {adj} {noun} strategy helped {company} {verb} their customer base.",
			"Learn how to {verb} your {noun} with {adj} techniques.",
			"The {adj} approach to {noun} can dramatically {verb} your results.",
			"Every successful brand needs a {adj} {noun} that can {verb} at scale.",
			"We helped over 500 businesses {verb} their {noun} using {adj} methods.",
			"Discover why {adj} {noun} is the key to sustainable growth.",
			"This {adj} framework will help you {verb} your {noun} in 30 days.",
			"Top marketers {verb} their {noun} with {adj} precision.",
			"The secret to {adj} {noun}: learn to {verb} before your competitors do.",
		},
	}
}

func (wb *WordBank) initTechnology() {
	wb.topics["technology"] = &TopicVocab{
		Titles: []string{
			"The Rise of Artificial Intelligence in Everyday Life",
			"Cloud Computing: A Complete Overview",
			"Cybersecurity Threats You Need to Know About",
			"Building Scalable Microservices",
			"The Future of Quantum Computing",
			"DevOps Best Practices for Modern Teams",
			"Blockchain Beyond Cryptocurrency",
			"Edge Computing and the IoT Revolution",
			"Machine Learning in Production Systems",
			"Zero Trust Architecture Explained",
			"Open Source Software Changing the World",
			"API Design Principles for Developers",
			"Containerization with Docker and Kubernetes",
			"Serverless Architecture Patterns",
		},
		Adjectives: []string{
			"scalable", "distributed", "cloud-native", "real-time", "resilient",
			"containerized", "serverless", "open-source", "encrypted", "autonomous",
			"high-performance", "fault-tolerant", "decentralized", "modular", "event-driven",
			"lightweight", "cross-platform", "extensible", "immutable", "reactive",
		},
		Nouns: []string{
			"infrastructure", "deployment", "pipeline", "container", "cluster",
			"endpoint", "microservice", "API", "algorithm", "protocol",
			"framework", "runtime", "repository", "middleware", "schema",
			"kernel", "binary", "daemon", "artifact", "payload",
		},
		Verbs: []string{
			"deploy", "scale", "orchestrate", "refactor", "containerize",
			"encrypt", "benchmark", "optimize", "provision", "migrate",
			"integrate", "compile", "debug", "iterate",
		},
		Templates: []string{
			"Our {adj} {noun} enables teams to {verb} with confidence.",
			"The {adj} {noun} was designed to {verb} mission-critical workloads.",
			"Engineers at {company} built a {adj} {noun} that can {verb} millions of requests.",
			"This {adj} approach lets you {verb} your {noun} without downtime.",
			"Modern teams {verb} their {noun} using {adj} tools and practices.",
			"The new {adj} {noun} will {verb} everything from edge to cloud.",
			"Why every CTO should {verb} their {noun} with {adj} design.",
			"A guide to building {adj} {noun} systems that {verb} gracefully under load.",
			"From monolith to {adj} {noun}: how we learned to {verb} at scale.",
			"The {adj} {noun} pattern helps distributed systems {verb} efficiently.",
		},
	}
}

func (wb *WordBank) initHealth() {
	wb.topics["health"] = &TopicVocab{
		Titles: []string{
			"Understanding Heart Health: A Complete Guide",
			"Mental Wellness in the Modern Workplace",
			"Nutrition Myths Debunked by Science",
			"The Benefits of Regular Exercise",
			"Sleep Science: Why Rest Matters More Than You Think",
			"Managing Stress in a Fast-Paced World",
			"Preventive Medicine: An Ounce of Prevention",
			"Holistic Approaches to Chronic Pain",
			"The Gut Microbiome and Your Health",
			"Telemedicine: Healthcare From Home",
			"Women's Health: What the Research Shows",
			"Fitness After Forty: Staying Strong",
		},
		Adjectives: []string{
			"clinical", "evidence-based", "holistic", "preventive", "therapeutic",
			"nutritional", "cardiovascular", "neurological", "rehabilitative", "diagnostic",
			"chronic", "acute", "integrative", "personalized", "regenerative",
			"anti-inflammatory", "bioavailable", "functional", "restorative",
		},
		Nouns: []string{
			"treatment", "diagnosis", "therapy", "wellness", "symptom",
			"patient", "recovery", "protocol", "outcome", "biomarker",
			"metabolism", "immunity", "inflammation", "dosage", "prognosis",
			"nutrition", "circulation", "cognition", "microbiome", "vitals",
		},
		Verbs: []string{
			"diagnose", "treat", "prevent", "rehabilitate", "monitor",
			"prescribe", "alleviate", "restore", "nourish", "strengthen",
			"screen", "manage", "supplement",
		},
		Templates: []string{
			"Research shows that {adj} {noun} can {verb} long-term health outcomes.",
			"Doctors recommend a {adj} approach to {verb} {noun} effectively.",
			"New {adj} {noun} protocols help patients {verb} faster than ever.",
			"The {adj} {noun} study found that patients who {verb} show marked improvement.",
			"A {adj} {noun} plan can {verb} common ailments before they escalate.",
			"Leading clinics now {verb} {noun} using {adj} methods.",
			"Understanding your {noun} is the first step to {adj} wellness.",
			"Studies confirm that {adj} {noun} helps {verb} recovery time by 40%.",
			"Our {adj} {noun} program was designed to {verb} the whole patient.",
		},
	}
}

func (wb *WordBank) initFinance() {
	wb.topics["finance"] = &TopicVocab{
		Titles: []string{
			"Understanding Index Funds and ETFs",
			"Building a Retirement Portfolio That Lasts",
			"Cryptocurrency: Risk, Reward, and Regulation",
			"Tax Strategies for Small Business Owners",
			"The Complete Guide to Personal Budgeting",
			"Venture Capital Trends to Watch",
			"Real Estate vs. Stock Market Investing",
			"How to Build an Emergency Fund",
			"Navigating Inflation in a Volatile Market",
			"Fintech Disrupting Traditional Banking",
			"Estate Planning Essentials",
			"Debt Management Strategies That Work",
			"Passive Income Streams for Beginners",
		},
		Adjectives: []string{
			"diversified", "tax-efficient", "high-yield", "risk-adjusted", "liquid",
			"volatile", "bullish", "bearish", "leveraged", "compounding",
			"fixed-income", "speculative", "institutional", "retail", "hedged",
			"inflation-protected", "sustainable", "fiduciary", "amortized",
		},
		Nouns: []string{
			"portfolio", "dividend", "equity", "liability", "asset",
			"bond", "index", "yield", "margin", "capital",
			"allocation", "benchmark", "derivative", "collateral", "premium",
			"valuation", "liquidity", "principal", "interest", "annuity",
		},
		Verbs: []string{
			"invest", "diversify", "hedge", "compound", "liquidate",
			"allocate", "rebalance", "underwrite", "amortize", "capitalize",
			"accrue", "depreciate", "leverage",
		},
		Templates: []string{
			"A {adj} {noun} strategy can help you {verb} your wealth over time.",
			"Financial advisors recommend you {verb} your {noun} with {adj} instruments.",
			"The {adj} {noun} market shows signs of recovery as investors {verb} cautiously.",
			"Learn how to {verb} your {noun} using {adj} techniques trusted by experts.",
			"Smart investors {verb} their {noun} to achieve {adj} returns.",
			"This {adj} approach to {noun} management helps clients {verb} risk effectively.",
			"Markets responded after {company} decided to {verb} their {adj} {noun}.",
			"The key to {adj} {noun} growth is knowing when to {verb}.",
			"Our {adj} {noun} planning service helps families {verb} for retirement.",
		},
	}
}

func (wb *WordBank) initEducation() {
	wb.topics["education"] = &TopicVocab{
		Titles: []string{
			"The Future of Online Learning",
			"Project-Based Learning in K-12 Classrooms",
			"How AI Is Transforming Education",
			"Student Engagement Strategies That Work",
			"The Case for Universal Pre-K",
			"STEM Education: Preparing the Next Generation",
			"Rethinking Homework in Modern Schools",
			"Adult Learning and Career Transitions",
			"The Rise of Micro-Credentials",
			"Inclusive Classrooms: Teaching Every Student",
			"Education Technology Trends",
			"Critical Thinking in the Digital Age",
		},
		Adjectives: []string{
			"pedagogical", "experiential", "collaborative", "inclusive", "adaptive",
			"competency-based", "interdisciplinary", "self-paced", "inquiry-based", "scaffolded",
			"formative", "summative", "differentiated", "blended", "immersive",
			"project-based", "student-centered", "asynchronous", "remedial",
		},
		Nouns: []string{
			"curriculum", "assessment", "pedagogy", "enrollment", "literacy",
			"classroom", "syllabus", "credential", "rubric", "competency",
			"lecture", "seminar", "thesis", "tuition", "scholarship",
			"accreditation", "module", "cohort", "mentor", "capstone",
		},
		Verbs: []string{
			"teach", "assess", "mentor", "enroll", "graduate",
			"instruct", "evaluate", "scaffold", "differentiate", "remediate",
			"certify", "tutor", "facilitate",
		},
		Templates: []string{
			"The {adj} {noun} model helps students {verb} at their own pace.",
			"Educators should {verb} {noun} using {adj} approaches.",
			"A {adj} {noun} framework allows teachers to {verb} diverse learners.",
			"Research on {adj} {noun} reveals that students who {verb} perform better.",
			"Schools across {city} now {verb} {noun} through {adj} programs.",
			"This {adj} {noun} initiative was designed to {verb} underserved communities.",
			"Leading universities {verb} their {noun} with {adj} innovation.",
			"The {adj} {noun} pilot produced remarkable gains when students learned to {verb}.",
			"How to {verb} any {noun} using the {adj} learning method.",
		},
	}
}

func (wb *WordBank) initTravel() {
	wb.topics["travel"] = &TopicVocab{
		Titles: []string{
			"Hidden Gems: Off-the-Beaten-Path Destinations",
			"Budget Travel Tips for Every Continent",
			"The Ultimate Packing Checklist",
			"Solo Travel: A Guide for First-Timers",
			"Sustainable Tourism and Eco-Friendly Travel",
			"Road Trips Worth Taking This Year",
			"The Best Street Food Cities in the World",
			"Luxury Resorts on a Budget",
			"How to Earn and Burn Airline Miles",
			"Backpacking Southeast Asia: A Complete Guide",
			"Cultural Etiquette Around the World",
			"Weekend Getaways You Can Plan in an Hour",
		},
		Adjectives: []string{
			"scenic", "exotic", "all-inclusive", "off-grid", "boutique",
			"budget-friendly", "luxurious", "remote", "coastal", "mountainous",
			"tropical", "historic", "culinary", "adventure-filled", "eco-friendly",
			"pet-friendly", "family-oriented", "romantic", "secluded",
		},
		Nouns: []string{
			"destination", "itinerary", "resort", "excursion", "airline",
			"passport", "visa", "luggage", "hostel", "cruise",
			"layover", "terminal", "reservation", "tour", "landmark",
			"souvenir", "departure", "accommodation", "trek", "voyage",
		},
		Verbs: []string{
			"explore", "discover", "navigate", "book", "embark",
			"wander", "trek", "cruise", "backpack", "depart",
			"photograph", "immerse", "experience",
		},
		Templates: []string{
			"Travelers seeking {adj} {noun} options should {verb} {city} this season.",
			"This {adj} {noun} guide will help you {verb} like a local.",
			"The {adj} {noun} in {city} is a must for anyone who loves to {verb}.",
			"You can {verb} the world's best {adj} {noun} without breaking the bank.",
			"We recommend you {verb} this {adj} {noun} before peak season hits.",
			"From {adj} {noun} to hidden trails, there's so much to {verb}.",
			"Frequent travelers {verb} their {noun} with {adj} planning and flexibility.",
			"The {adj} {noun} experience in {city} will change how you {verb} forever.",
			"Pack light, {verb} far, and enjoy every {adj} {noun} along the way.",
		},
	}
}

func (wb *WordBank) initFood() {
	wb.topics["food"] = &TopicVocab{
		Titles: []string{
			"Farm-to-Table: The Movement That Changed Dining",
			"Quick Weeknight Dinners Under 30 Minutes",
			"The Science of Sourdough Baking",
			"Vegan Recipes That Meat Lovers Will Enjoy",
			"Understanding Wine Pairing Basics",
			"Street Food Favorites From Around the Globe",
			"Meal Prep Tips for Busy Professionals",
			"The History of Spices and Trade",
			"Fermentation: Ancient Techniques for Modern Kitchens",
			"Comfort Food Classics Reimagined",
			"Seasonal Cooking With Local Ingredients",
			"The Art of Food Presentation",
		},
		Adjectives: []string{
			"organic", "artisan", "farm-fresh", "gluten-free", "slow-cooked",
			"plant-based", "fermented", "smoked", "seasonal", "locally-sourced",
			"savory", "decadent", "rustic", "infused", "handcrafted",
			"crispy", "creamy", "tangy", "aromatic", "caramelized",
		},
		Nouns: []string{
			"recipe", "ingredient", "flavor", "cuisine", "dish",
			"spice", "broth", "garnish", "marinade", "portion",
			"menu", "appetizer", "entree", "dessert", "pairing",
			"reduction", "emulsion", "ferment", "sourdough", "umami",
		},
		Verbs: []string{
			"saut\u00e9", "braise", "ferment", "garnish", "infuse",
			"roast", "simmer", "plate", "season", "marinate",
			"caramelize", "reduce", "whisk",
		},
		Templates: []string{
			"This {adj} {noun} recipe will help you {verb} a perfect dinner.",
			"Chefs across {city} {verb} their {noun} with {adj} techniques.",
			"The {adj} {noun} pairs beautifully when you {verb} it at low heat.",
			"Learn to {verb} {adj} {noun} like a professional chef.",
			"Our {adj} {noun} guide shows you how to {verb} seasonal produce.",
			"The secret to great {adj} {noun}: {verb} with patience and fresh ingredients.",
			"Home cooks can {verb} any {noun} using {adj} methods from around the world.",
			"From market to plate, this {adj} {noun} will {verb} your taste buds.",
			"Try to {verb} this {adj} {noun} for your next dinner party.",
		},
	}
}

func (wb *WordBank) initSports() {
	wb.topics["sports"] = &TopicVocab{
		Titles: []string{
			"Training Programs for Marathon Runners",
			"The Evolution of Analytics in Professional Sports",
			"Recovery Techniques Used by Elite Athletes",
			"Youth Sports: Building Character Through Competition",
			"The Business of Professional Sports Leagues",
			"Extreme Sports: Pushing the Limits",
			"How Technology Is Changing Referee Decisions",
			"A History of the Olympic Games",
			"Women's Sports: Breaking Barriers",
			"Fantasy Sports Strategy Guide",
			"Sports Nutrition for Peak Performance",
			"Mental Toughness in Competitive Athletics",
		},
		Adjectives: []string{
			"competitive", "elite", "professional", "amateur", "endurance-based",
			"high-intensity", "tactical", "championship-level", "recreational", "dynamic",
			"Olympic", "collegiate", "defensive", "offensive", "agile",
			"explosive", "aerobic", "anaerobic", "clutch",
		},
		Nouns: []string{
			"athlete", "tournament", "championship", "season", "roster",
			"draft", "playoff", "stadium", "league", "coach",
			"training", "stamina", "agility", "record", "trophy",
			"rivalry", "franchise", "scouting", "playbook", "overtime",
		},
		Verbs: []string{
			"compete", "train", "score", "recruit", "draft",
			"sprint", "defend", "tackle", "coach", "qualify",
			"dominate", "rally", "strategize",
		},
		Templates: []string{
			"The {adj} {noun} program helps athletes {verb} at the highest level.",
			"Fans witnessed a {adj} {noun} as both teams fought to {verb}.",
			"Our {adj} {noun} regimen will help you {verb} your personal best.",
			"The {adj} {noun} season has seen {company} rise to {verb} the league.",
			"Coaches who {verb} with {adj} {noun} tactics win more often.",
			"This {adj} {noun} breakdown shows how top athletes {verb} under pressure.",
			"From {adj} {noun} drills to game day, the goal is to {verb} consistently.",
			"The {adj} {noun} analysis reveals which teams {verb} most effectively.",
			"Every {adj} {noun} starts with the discipline to {verb} every single day.",
		},
	}
}

func (wb *WordBank) initFashion() {
	wb.topics["fashion"] = &TopicVocab{
		Titles: []string{
			"Sustainable Fashion: Style Without Waste",
			"Capsule Wardrobes for Every Season",
			"The Return of Vintage Aesthetics",
			"Streetwear Culture and High Fashion",
			"Accessorizing Like a Stylist",
			"Fashion Week Highlights and Trends",
			"The Rise of Gender-Neutral Clothing",
			"Fabric Technology in Modern Apparel",
			"How to Dress for Your Body Type",
			"Luxury Brands and the Resale Market",
			"Color Theory in Wardrobe Planning",
			"Minimalist Fashion: Less Is More",
		},
		Adjectives: []string{
			"sustainable", "bespoke", "minimalist", "vintage", "haute-couture",
			"bohemian", "tailored", "avant-garde", "timeless", "oversized",
			"monochrome", "textured", "handwoven", "limited-edition", "couture",
			"structured", "flowing", "layered", "statement", "ethically-sourced",
		},
		Nouns: []string{
			"collection", "silhouette", "fabric", "accessory", "palette",
			"trend", "runway", "garment", "wardrobe", "textile",
			"pattern", "hemline", "ensemble", "stitch", "drape",
			"boutique", "lookbook", "seam", "lining",
		},
		Verbs: []string{
			"style", "tailor", "accessorize", "curate", "drape",
			"pair", "layer", "embroider", "showcase", "design",
			"model", "stitch", "coordinate",
		},
		Templates: []string{
			"This {adj} {noun} defines the season's must-have look.",
			"Designers {verb} their {noun} with {adj} attention to detail.",
			"The {adj} {noun} trend is here to stay, and stylists {verb} accordingly.",
			"You can {verb} any {adj} {noun} to create a stunning ensemble.",
			"Fashion insiders {verb} this {adj} {noun} as the year's top pick.",
			"From the runway to the street, {adj} {noun} continues to {verb} wardrobes.",
			"Learn how to {verb} a {adj} {noun} that works for any occasion.",
			"The {adj} {noun} from {company} sets a new standard for how we {verb}.",
			"Every wardrobe needs a {adj} {noun} that you can {verb} effortlessly.",
		},
	}
}

func (wb *WordBank) initRealEstate() {
	wb.topics["real-estate"] = &TopicVocab{
		Titles: []string{
			"First-Time Home Buyer's Complete Guide",
			"Investment Properties: What to Look For",
			"Understanding Mortgage Rates in Today's Market",
			"The Pros and Cons of Renting vs. Buying",
			"Commercial Real Estate Trends",
			"Home Staging Tips That Sell",
			"Navigating the Closing Process",
			"How Location Affects Property Value",
			"Flipping Houses: Risks and Rewards",
			"The Future of Urban Development",
			"Smart Home Features That Boost Resale Value",
			"Property Management for Passive Income",
		},
		Adjectives: []string{
			"turnkey", "waterfront", "move-in-ready", "newly-renovated", "mixed-use",
			"income-producing", "pre-construction", "gated", "affordable", "luxury",
			"historic", "energy-efficient", "open-concept", "multi-family", "commercial",
			"residential", "zoned", "appraised", "listed",
		},
		Nouns: []string{
			"property", "mortgage", "listing", "appraisal", "escrow",
			"closing", "equity", "lien", "deed", "zoning",
			"tenant", "landlord", "lease", "assessment", "commission",
			"renovation", "inspection", "title", "square footage", "HOA",
		},
		Verbs: []string{
			"list", "appraise", "renovate", "inspect", "close",
			"lease", "refinance", "flip", "stage", "negotiate",
			"zone", "develop", "assess",
		},
		Templates: []string{
			"This {adj} {noun} in {city} is one of the best opportunities to {verb} this year.",
			"Buyers should {verb} every {noun} before signing on a {adj} home.",
			"The {adj} {noun} market in {city} continues to {verb} despite headwinds.",
			"Smart investors {verb} {adj} {noun} assets for long-term appreciation.",
			"Our guide helps you {verb} {adj} {noun} deals with confidence.",
			"The {adj} {noun} was recently updated and is ready to {verb} quickly.",
			"Agents recommend you {verb} a {adj} {noun} strategy before entering the market.",
			"Understanding {adj} {noun} trends will help you {verb} at the right time.",
			"From {adj} {noun} to final walkthrough, here's how to {verb} like a pro.",
		},
	}
}

func (wb *WordBank) initAutomotive() {
	wb.topics["automotive"] = &TopicVocab{
		Titles: []string{
			"Electric Vehicles: The Road Ahead",
			"How to Choose the Right Car for Your Family",
			"Self-Driving Technology: Where Are We Now?",
			"Hybrid vs. Full Electric: A Buyer's Guide",
			"The History of Muscle Cars",
			"Car Maintenance Tips Every Owner Should Know",
			"The Rise of Car Subscription Services",
			"Truck Reviews: Best Picks for Work and Play",
			"Motorsport Engineering Breakthroughs",
			"How Vehicle Safety Ratings Are Determined",
			"The Used Car Market in a Post-Pandemic World",
			"Charging Infrastructure and EV Adoption",
		},
		Adjectives: []string{
			"electric", "hybrid", "turbocharged", "all-wheel-drive", "fuel-efficient",
			"autonomous", "aerodynamic", "high-torque", "zero-emission", "luxury",
			"compact", "heavy-duty", "performance-tuned", "certified-pre-owned", "factory-direct",
			"supercharged", "mid-size", "full-size", "plug-in",
		},
		Nouns: []string{
			"vehicle", "engine", "transmission", "suspension", "chassis",
			"horsepower", "torque", "mileage", "drivetrain", "warranty",
			"sedan", "SUV", "pickup", "coupe", "hatchback",
			"battery", "range", "charge", "dealership", "recall",
		},
		Verbs: []string{
			"accelerate", "brake", "tow", "cruise", "charge",
			"test-drive", "lease", "service", "upgrade", "customize",
			"manufacture", "recall", "engineer",
		},
		Templates: []string{
			"The {adj} {noun} delivers impressive performance you can {verb} every day.",
			"Buyers looking to {verb} should consider this {adj} {noun} from {company}.",
			"This {adj} {noun} review covers everything from how it handles to how it can {verb}.",
			"Engineers at {company} designed a {adj} {noun} that can {verb} like never before.",
			"The {adj} {noun} market is set to {verb} as new models arrive.",
			"You can {verb} this {adj} {noun} for less than you might expect.",
			"From daily commutes to long hauls, this {adj} {noun} is built to {verb}.",
			"Our testers found the {adj} {noun} easy to {verb} in all conditions.",
			"The new {adj} {noun} from {company} is engineered to {verb} with precision.",
		},
	}
}

func (wb *WordBank) initEntertainment() {
	wb.topics["entertainment"] = &TopicVocab{
		Titles: []string{
			"Streaming Wars: Who's Winning the Battle for Your Screen",
			"The Golden Age of Television",
			"Indie Films That Defined a Decade",
			"How Video Games Became a Billion-Dollar Industry",
			"Live Music's Comeback After the Pandemic",
			"The Podcasting Boom: What's Next",
			"Virtual Reality and the Future of Entertainment",
			"Awards Season Preview and Predictions",
			"The Rise of User-Generated Content",
			"Binge-Worthy Shows You Missed",
			"The Evolution of Stand-Up Comedy",
			"Music Production in the Age of AI",
			"Behind the Scenes of Blockbuster Filmmaking",
		},
		Adjectives: []string{
			"binge-worthy", "critically-acclaimed", "viral", "award-winning", "blockbuster",
			"indie", "immersive", "interactive", "serialized", "cinematic",
			"chart-topping", "genre-defining", "streaming", "live-action", "animated",
			"behind-the-scenes", "sold-out", "limited-series", "cult-classic",
		},
		Nouns: []string{
			"series", "episode", "soundtrack", "premiere", "sequel",
			"franchise", "box office", "screenplay", "cast", "genre",
			"playlist", "album", "performance", "festival", "release",
			"production", "audience", "director", "studio", "trailer",
		},
		Verbs: []string{
			"stream", "premiere", "binge", "produce", "direct",
			"score", "cast", "release", "perform", "review",
			"debut", "syndicate", "adapt",
		},
		Templates: []string{
			"This {adj} {noun} has audiences everywhere rushing to {verb} it.",
			"Critics agree that the {adj} {noun} is a must-see this season.",
			"The {adj} {noun} from {company} is expected to {verb} record viewership.",
			"Fans who {verb} the latest {adj} {noun} won't be disappointed.",
			"Our review of the {adj} {noun} reveals why audiences can't stop watching.",
			"The {adj} {noun} is set to {verb} on all major platforms this week.",
			"From the {adj} {noun} to behind the scenes, there's so much to {verb}.",
			"The {adj} {noun} festival in {city} will {verb} thousands of fans.",
			"If you love {adj} {noun} content, you'll want to {verb} this immediately.",
		},
	}
}

// ---------------------------------------------------------------------------
// Generic and shared data
// ---------------------------------------------------------------------------

func (wb *WordBank) initGeneric() {
	wb.generic = &TopicVocab{
		Titles: []string{
			"Everything You Need to Know",
			"A Comprehensive Guide for Beginners",
			"What the Experts Are Saying",
			"Top Trends Shaping the Industry",
			"How to Get Started Today",
			"The Complete Overview",
			"Why This Matters More Than Ever",
			"An Insider's Perspective",
			"Lessons Learned From the Best",
			"The Definitive Resource",
			"Breaking Down the Fundamentals",
			"A Fresh Take on What Works",
		},
		Adjectives: []string{
			"innovative", "comprehensive", "essential", "advanced", "practical",
			"proven", "emerging", "reliable", "cutting-edge", "streamlined",
			"actionable", "robust", "versatile", "premium", "next-generation",
			"sustainable", "transformative", "intuitive", "cost-effective", "strategic",
		},
		Nouns: []string{
			"solution", "approach", "strategy", "platform", "framework",
			"resource", "system", "process", "service", "tool",
			"method", "insight", "opportunity", "challenge", "outcome",
			"initiative", "benchmark", "standard", "capability", "milestone",
		},
		Verbs: []string{
			"optimize", "transform", "accelerate", "streamline", "enhance",
			"implement", "deliver", "leverage", "simplify", "achieve",
			"establish", "discover", "integrate", "customize",
		},
		Templates: []string{
			"Our {adj} {noun} helps businesses {verb} their core operations.",
			"The {adj} {noun} approach allows teams to {verb} with confidence.",
			"Discover how a {adj} {noun} can help you {verb} faster.",
			"Industry leaders {verb} their {noun} using {adj} strategies.",
			"This {adj} {noun} guide will show you how to {verb} step by step.",
			"The {adj} {noun} from {company} is trusted by thousands worldwide.",
			"Learn to {verb} any {noun} with our {adj} methodology.",
			"A {adj} {noun} is the key to helping organizations {verb} at scale.",
			"From concept to execution, this {adj} {noun} helps you {verb} with ease.",
			"The right {adj} {noun} can {verb} outcomes across every department.",
		},
	}
}

func (wb *WordBank) initNames() {
	wb.names = &NameBank{
		First: []string{
			"James", "Mary", "Robert", "Patricia", "John",
			"Jennifer", "Michael", "Linda", "David", "Elizabeth",
			"William", "Barbara", "Richard", "Susan", "Joseph",
			"Jessica", "Thomas", "Sarah", "Christopher", "Karen",
			"Daniel", "Lisa", "Matthew", "Nancy", "Anthony",
			"Betty", "Mark", "Margaret", "Steven", "Sandra",
			"Andrew", "Ashley", "Emily", "Joshua", "Samantha",
		},
		Last: []string{
			"Smith", "Johnson", "Williams", "Brown", "Jones",
			"Garcia", "Miller", "Davis", "Rodriguez", "Martinez",
			"Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson",
			"Thomas", "Taylor", "Moore", "Jackson", "Martin",
			"Lee", "Perez", "Thompson", "White", "Harris",
			"Sanchez", "Clark", "Ramirez", "Lewis", "Robinson",
			"Walker", "Young", "Allen", "King", "Wright",
		},
	}
}

func (wb *WordBank) initCompanies() {
	wb.companies = []string{
		"Apex Solutions", "BrightPath Systems", "ClearView Analytics",
		"DataStream Corp", "Elevate Technologies", "FusionWorks",
		"GreenLeaf Industries", "Horizon Digital", "InnoVate Labs",
		"JetStream Networks", "Keystone Partners", "Luminary Group",
		"Meridian Software", "NexGen Platforms", "Onyx Consulting",
		"Pinnacle Ventures", "Quantum Edge", "Redwood Services",
		"Silverline Media", "TerraVox", "Uplift Dynamics",
		"Vertex Global", "Wavelength Inc", "Xenith Systems",
		"Yellowstone Capital", "Zenith Enterprises", "BlueArc Technologies",
		"CrownPoint Financial", "DawnBreaker AI", "EchoBase Solutions",
		"ForgePoint Labs", "GridIron Analytics",
	}
}

func (wb *WordBank) initJobTitles() {
	wb.jobTitles = []string{
		"Software Engineer", "Product Manager", "Data Scientist",
		"Marketing Director", "Chief Executive Officer", "Chief Technology Officer",
		"UX Designer", "DevOps Engineer", "Sales Representative",
		"Human Resources Manager", "Financial Analyst", "Operations Manager",
		"Content Strategist", "Business Development Lead", "Customer Success Manager",
		"Machine Learning Engineer", "Frontend Developer", "Backend Developer",
		"Quality Assurance Engineer", "Project Manager", "Technical Writer",
		"Systems Architect", "Security Analyst", "Database Administrator",
		"VP of Engineering",
	}
}

func (wb *WordBank) initCities() {
	wb.cities = []string{
		"New York", "London", "Tokyo", "Paris", "Sydney",
		"Berlin", "Toronto", "Singapore", "Dubai", "San Francisco",
		"Los Angeles", "Chicago", "Mumbai", "Shanghai", "Seoul",
		"Amsterdam", "Barcelona", "Stockholm", "Austin", "Denver",
		"Seattle", "Melbourne", "Cape Town", "Buenos Aires", "Bangkok",
		"Istanbul", "Dublin", "Lisbon", "Prague", "Vienna",
		"Helsinki", "Zurich", "Taipei", "Nairobi",
	}
}

func (wb *WordBank) initSections() {
	wb.sections = []string{
		"Our Services", "Meet the Team", "Featured Products",
		"How It Works", "What Our Clients Say", "Latest News",
		"About Us", "Our Mission", "Core Values",
		"Case Studies", "By the Numbers", "Frequently Asked Questions",
		"Get In Touch", "Our Partners", "Upcoming Events",
		"Industry Insights", "Company Timeline", "Awards & Recognition",
		"Why Choose Us", "Featured In", "Our Process",
		"Success Stories", "Resources & Guides", "Join Our Team",
	}
}

func (wb *WordBank) initCTAs() {
	wb.ctas = []string{
		"Get Started", "Learn More", "Sign Up Free",
		"Request a Demo", "Start Your Trial", "Download Now",
		"Contact Us", "Schedule a Call", "See Pricing",
		"Join Today", "Try It Free", "Book a Consultation",
		"Subscribe Now", "Explore Features", "Get a Quote",
		"Watch the Video", "Read the Case Study", "Claim Your Offer",
		"Start Building", "Talk to Sales",
	}
}

func (wb *WordBank) initNavLabels() {
	wb.navLabels = []string{
		"Home", "About", "Services", "Products", "Blog",
		"Contact", "Pricing", "Features", "Resources", "Documentation",
		"Support", "Careers", "News", "Partners", "FAQ",
		"Team", "Portfolio", "Testimonials", "Events", "Login",
	}
}

func (wb *WordBank) initTestimonials() {
	wb.testimonials = []string{
		"Working with {company} completely transformed our workflow. Highly recommended!",
		"I've been using this product for six months and the results speak for themselves.",
		"The team at {company} went above and beyond to deliver on every promise.",
		"This is hands down the best solution we've found after evaluating dozens of options.",
		"From onboarding to daily use, everything has been seamless and intuitive.",
		"Our productivity increased by 40% within the first quarter of adoption.",
		"If you're on the fence, just try it. You won't regret it.",
		"The customer support alone makes {company} worth every penny.",
		"We switched from a competitor and haven't looked back since.",
		"I recommend {company} to everyone in the industry. It just works.",
		"The {adj} approach they took to solving our problems was genuinely impressive.",
		"After implementing their {noun}, our team was able to {verb} in half the time.",
		"Five stars. Seriously. The {adj} {noun} exceeded all our expectations.",
		"Our CEO loves the dashboard. Our engineers love the API. Everyone wins.",
		"We evaluated three vendors and {company} was the clear winner on every metric.",
	}
}

func (wb *WordBank) initFooterTexts() {
	wb.footerTexts = []string{
		"\u00a9 2024 {company}. All rights reserved.",
		"\u00a9 2025 {company}. All rights reserved.",
		"Privacy Policy | Terms of Service | Cookie Preferences",
		"Made with care in {city}.",
		"\u00a9 {company}. Unauthorized reproduction is prohibited.",
		"By using this site, you agree to our Terms of Service and Privacy Policy.",
		"Questions? Contact us at support@example.com",
		"{company} is a registered trademark. All rights reserved worldwide.",
		"This site uses cookies to improve your experience. Learn more.",
		"Follow us on Twitter | LinkedIn | GitHub",
		"\u00a9 2024-2025 {company}, Inc. All trademarks are property of their respective owners.",
		"Site design and content \u00a9 {company}. Built with love and caffeine.",
	}
}

func (wb *WordBank) initMetaDescriptions() {
	wb.metaDescriptions = []string{
		"Discover {adj} {noun} solutions from {company}. Get started today.",
		"Learn how to {verb} your {noun} with our {adj} platform.",
		"Join thousands of professionals who trust {company} for {adj} {noun}.",
		"The leading provider of {adj} {noun} services. Free trial available.",
		"Transform your business with {adj} {noun} tools. See why teams love us.",
		"{company} offers {adj} {noun} for businesses of all sizes. Learn more.",
		"Looking for a {adj} way to {verb} your {noun}? We can help.",
		"Get {adj} results with our proven {noun} methodology. Start free.",
		"From startups to enterprises, {company} helps you {verb} what matters.",
		"The {adj} {noun} platform trusted by teams in over 50 countries.",
		"Explore our {adj} {noun} features and see the difference for yourself.",
		"Ready to {verb} your {noun}? {company} makes it simple.",
	}
}
